#include <stdlib.h>
#include <string.h>

#include "lwip/opt.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"

// Swift-side trampoline provided by glue to handle Internet egress
extern void rlwip_proxynetif_trampoline_output(const uint8_t *data, size_t len);

// Serialize pbuf chain into contiguous buffer and emit via proxy callback
static err_t proxynetif_emit(struct netif *netif, struct pbuf *p) {
	LWIP_UNUSED_ARG(netif);
	if (!p) return ERR_IF;

    size_t total = p->tot_len;
    LWIP_ASSERT("pbuf too large", total <= 0xFFFF);
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return ERR_MEM;
    u16_t copied = pbuf_copy_partial(p, buf, (u16_t)total, 0);
    if (copied != (u16_t)total) {
        free(buf);
        return ERR_IF;
    }
    rlwip_proxynetif_trampoline_output(buf, total);
    free(buf);
	return ERR_OK;
}

static err_t proxynetif_output_ip4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
	LWIP_UNUSED_ARG(ipaddr);
	return proxynetif_emit(netif, p);
}

#if LWIP_IPV6
static err_t proxynetif_output_ip6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
	LWIP_UNUSED_ARG(ipaddr);
	return proxynetif_emit(netif, p);
}
#endif

err_t proxynetif_init(struct netif *netif) {
	netif->name[0] = 'p';
	netif->name[1] = 'x';
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_LINK_UP | NETIF_FLAG_UP | NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
	netif->output = proxynetif_output_ip4;
#if LWIP_IPV6
	netif->output_ip6 = proxynetif_output_ip6;
#endif
	netif->linkoutput = NULL;
	return ERR_OK;
}


