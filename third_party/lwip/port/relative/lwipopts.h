#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS                 1
#define LWIP_NETCONN           0
#define LWIP_SOCKET            0

#define LWIP_IPV4              1
#define LWIP_IPV6              1
#define LWIP_TCP               1
#define LWIP_UDP               1
#define LWIP_ICMP              1
#define LWIP_ICMP6             1

// Prefer MSS clamp over fragmentation/reassembly to reduce memory pressure
#define IP_REASSEMBLY          0
#define IP_FRAG                0

#define TCP_SND_QUEUELEN       128
#define TCP_SND_BUF            (64 * 1024)
#define TCP_WND                (64 * 1024)
#define LWIP_WND_SCALE         1
#define TCP_RCV_SCALE          2
#define TCP_QUEUE_OOSEQ        1
#define LWIP_TCP_SACK_OUT      1
#define TCP_MSS                1460

#define CHECKSUM_GEN_IP        1
#define CHECKSUM_GEN_UDP       1
#define CHECKSUM_GEN_TCP       1
#define CHECKSUM_CHECK_IP      1
#define CHECKSUM_CHECK_UDP     1
#define CHECKSUM_CHECK_TCP     1

#define MEM_SIZE               (2 * 1024 * 1024)
// Tune pools for consumer extension limits; keep counts conservative but sufficient
#define MEMP_NUM_TCP_PCB       256
#define MEMP_NUM_UDP_PCB       256
#define MEMP_NUM_TCP_SEG       4096
#define PBUF_POOL_SIZE         4096
#define PBUF_POOL_BUFSIZE      1600

#endif


