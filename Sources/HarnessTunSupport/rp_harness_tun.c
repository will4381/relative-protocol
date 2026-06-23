// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

#include "rp_harness_tun.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static void rp_set_errno(int *out_errno)
{
    if (out_errno != NULL) {
        *out_errno = errno;
    }
}

int rp_harness_open_tun(const char *requested_name,
                        int include_packet_info,
                        char *actual_name,
                        size_t actual_name_len,
                        int *out_errno)
{
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        rp_set_errno(out_errno);
        return -1;
    }

    struct ifreq request;
    memset(&request, 0, sizeof(request));
    request.ifr_flags = IFF_TUN;
    if (!include_packet_info) {
        request.ifr_flags |= IFF_NO_PI;
    }

    if (requested_name != NULL && requested_name[0] != '\0') {
        size_t name_len = strnlen(requested_name, IFNAMSIZ - 1);
        memcpy(request.ifr_name, requested_name, name_len);
        request.ifr_name[name_len] = '\0';
    }

    if (ioctl(fd, TUNSETIFF, (void *)&request) < 0) {
        rp_set_errno(out_errno);
        close(fd);
        return -1;
    }

    if (actual_name != NULL && actual_name_len > 0) {
        size_t copy_len = strnlen(request.ifr_name, IFNAMSIZ);
        if (copy_len >= actual_name_len) {
            copy_len = actual_name_len - 1;
        }
        memcpy(actual_name, request.ifr_name, copy_len);
        actual_name[copy_len] = '\0';
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        rp_set_errno(out_errno);
        close(fd);
        return -1;
    }

    if (out_errno != NULL) {
        *out_errno = 0;
    }
    return fd;
}

#else

int rp_harness_open_tun(const char *requested_name,
                        int include_packet_info,
                        char *actual_name,
                        size_t actual_name_len,
                        int *out_errno)
{
    (void)requested_name;
    (void)include_packet_info;
    if (actual_name != NULL && actual_name_len > 0) {
        actual_name[0] = '\0';
    }
    if (out_errno != NULL) {
        *out_errno = ENOTSUP;
    }
    return -1;
}

#endif

ssize_t rp_harness_read_fd(int fd, void *buffer, size_t buffer_len, int *out_errno)
{
    ssize_t result = read(fd, buffer, buffer_len);
    if (out_errno != NULL) {
        *out_errno = result < 0 ? errno : 0;
    }
    return result;
}

ssize_t rp_harness_write_fd(int fd, const void *buffer, size_t buffer_len, int *out_errno)
{
    ssize_t result = write(fd, buffer, buffer_len);
    if (out_errno != NULL) {
        *out_errno = result < 0 ? errno : 0;
    }
    return result;
}

int rp_harness_close_fd(int fd)
{
    return close(fd);
}
