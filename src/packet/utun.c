#include "packet/utun.h"
#include "core/logging.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if_utun.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>

struct utun_handle {
    int fd;
    char name[16];
    uint16_t mtu;
    bool read_loop_running;
    pthread_t read_thread;
    packet_received_callback_t callback;
    void *user_data;
};

static void *read_loop_thread(void *arg) {
    utun_handle_t *handle = (utun_handle_t *)arg;
    uint8_t buffer[MAX_PACKET_SIZE + 4];
    
    LOG_INFO("Starting utun read loop for %s", handle->name);
    
    while (handle->read_loop_running) {
        ssize_t bytes_read = read(handle->fd, buffer, sizeof(buffer));
        
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (handle->read_loop_running) {
                LOG_ERROR("Read error on %s: %s", handle->name, strerror(errno));
            }
            break;
        }
        
        if (bytes_read < 4) {
            LOG_WARN("Received short packet (%zd bytes) on %s", bytes_read, handle->name);
            continue;
        }
        
        // SECURITY FIX: Strict bounds validation to prevent buffer overflow
        if (bytes_read > sizeof(buffer)) {
            LOG_ERROR("Packet size %zd exceeds buffer size %zu on %s", 
                     bytes_read, sizeof(buffer), handle->name);
            continue;
        }
        
        uint32_t protocol_family = ntohl(*(uint32_t *)buffer);
        uint8_t *packet_data = buffer + 4;
        size_t packet_size = bytes_read - 4;
        
        if (handle->callback && packet_size > 0) {
            packet_info_t packet = {0};
            packet.data = packet_data;
            packet.length = packet_size;
            packet.timestamp_ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
            
            uint8_t ip_version = (packet_data[0] >> 4) & 0x0F;
            packet.flow.ip_version = ip_version;
            
            if (ip_version == 4 && packet_size >= sizeof(struct ip)) {
                struct ip *ip_hdr = (struct ip *)packet_data;
                packet.flow.src_ip.v4.addr = ip_hdr->ip_src.s_addr;
                packet.flow.dst_ip.v4.addr = ip_hdr->ip_dst.s_addr;
                packet.flow.protocol = ip_hdr->ip_p;
            } else if (ip_version == 6 && packet_size >= sizeof(struct ip6_hdr)) {
                struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)packet_data;
                memcpy(packet.flow.src_ip.v6.addr, &ip6_hdr->ip6_src, 16);
                memcpy(packet.flow.dst_ip.v6.addr, &ip6_hdr->ip6_dst, 16);
                packet.flow.protocol = ip6_hdr->ip6_nxt;
            }
            
            handle->callback(&packet, handle->user_data);
        }
    }
    
    LOG_INFO("Stopped utun read loop for %s", handle->name);
    return NULL;
}

utun_handle_t *utun_create(const char *interface_name, uint16_t mtu) {
    LOG_INFO("Creating utun interface: %s (MTU: %d)", interface_name ? interface_name : "auto", mtu);
    
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        LOG_ERROR("Failed to create control socket: %s", strerror(errno));
        return NULL;
    }
    
    struct ctl_info info = {0};
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        LOG_ERROR("Failed to get utun control info: %s", strerror(errno));
        close(fd);
        return NULL;
    }
    
    struct sockaddr_ctl addr = {0};
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;
    
    if (interface_name && strncmp(interface_name, "utun", 4) == 0) {
        int unit = atoi(interface_name + 4);
        if (unit > 0) {
            addr.sc_unit = unit + 1;
        }
    }
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to connect to utun control: %s", strerror(errno));
        close(fd);
        return NULL;
    }
    
    char name[16];
    socklen_t name_len = sizeof(name);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &name_len) < 0) {
        LOG_ERROR("Failed to get interface name: %s", strerror(errno));
        close(fd);
        return NULL;
    }
    
    utun_handle_t *handle = calloc(1, sizeof(utun_handle_t));
    if (!handle) {
        LOG_ERROR("Failed to allocate utun handle");
        close(fd);
        return NULL;
    }
    
    handle->fd = fd;
    strncpy(handle->name, name, sizeof(handle->name) - 1);
    handle->mtu = mtu > 0 ? mtu : MAX_MTU;
    handle->read_loop_running = false;
    
    if (!utun_set_mtu(handle, handle->mtu)) {
        LOG_WARN("Failed to set MTU to %d for %s", handle->mtu, handle->name);
    }
    
    LOG_INFO("Created utun interface: %s (fd: %d, MTU: %d)", handle->name, handle->fd, handle->mtu);
    return handle;
}

void utun_destroy(utun_handle_t *handle) {
    if (!handle) return;
    
    LOG_INFO("Destroying utun interface: %s", handle->name);
    
    if (handle->read_loop_running) {
        utun_stop_read_loop(handle);
    }
    
    if (handle->fd >= 0) {
        close(handle->fd);
    }
    
    free(handle);
}

int utun_get_fd(utun_handle_t *handle) {
    return handle ? handle->fd : -1;
}

const char *utun_get_name(utun_handle_t *handle) {
    return handle ? handle->name : NULL;
}

uint16_t utun_get_mtu(utun_handle_t *handle) {
    return handle ? handle->mtu : 0;
}

bool utun_set_mtu(utun_handle_t *handle, uint16_t mtu) {
    if (!handle || mtu < MIN_MTU || mtu > MAX_MTU) {
        return false;
    }
    
    handle->mtu = mtu;
    return true;
}

ssize_t utun_read(utun_handle_t *handle, uint8_t *buffer, size_t buffer_size) {
    if (!handle || !buffer || buffer_size < 4) {
        return -1;
    }
    
    ssize_t bytes_read = read(handle->fd, buffer, buffer_size);
    if (bytes_read < 4) {
        return -1;
    }
    
    return bytes_read - 4;
}

ssize_t utun_write(utun_handle_t *handle, const uint8_t *packet, size_t packet_size) {
    if (!handle || !packet || packet_size == 0 || packet_size > MAX_PACKET_SIZE) {
        return -1;
    }
    
    uint8_t buffer[MAX_PACKET_SIZE + 4];
    uint32_t protocol_family = AF_INET;
    
    if (packet_size > 0) {
        uint8_t ip_version = (packet[0] >> 4) & 0x0F;
        if (ip_version == 6) {
            protocol_family = AF_INET6;
        }
    }
    
    *(uint32_t *)buffer = htonl(protocol_family);
    memcpy(buffer + 4, packet, packet_size);
    
    ssize_t bytes_written = write(handle->fd, buffer, packet_size + 4);
    if (bytes_written < 4) {
        return -1;
    }
    
    return bytes_written - 4;
}

bool utun_start_read_loop(utun_handle_t *handle, packet_received_callback_t callback, void *user_data) {
    if (!handle || !callback || handle->read_loop_running) {
        return false;
    }
    
    handle->callback = callback;
    handle->user_data = user_data;
    handle->read_loop_running = true;
    
    if (pthread_create(&handle->read_thread, NULL, read_loop_thread, handle) != 0) {
        LOG_ERROR("Failed to create read thread for %s", handle->name);
        handle->read_loop_running = false;
        return false;
    }
    
    return true;
}

void utun_stop_read_loop(utun_handle_t *handle) {
    if (!handle || !handle->read_loop_running) {
        return;
    }
    
    handle->read_loop_running = false;
    
    if (pthread_join(handle->read_thread, NULL) != 0) {
        LOG_WARN("Failed to join read thread for %s", handle->name);
    }
}