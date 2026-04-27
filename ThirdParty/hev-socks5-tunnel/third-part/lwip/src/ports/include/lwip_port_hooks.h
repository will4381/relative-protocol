#ifndef VPNBRIDGE_LWIP_PORT_HOOKS_H
#define VPNBRIDGE_LWIP_PORT_HOOKS_H

#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

u32_t lwip_port_tcp_isn(const ip_addr_t *local_ip,
                        u16_t local_port,
                        const ip_addr_t *remote_ip,
                        u16_t remote_port);

#ifdef __cplusplus
}
#endif

#define LWIP_HOOK_TCP_ISN(local_ip, local_port, remote_ip, remote_port) \
    lwip_port_tcp_isn((local_ip), (local_port), (remote_ip), (remote_port))

#endif
