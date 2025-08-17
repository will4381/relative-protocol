#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <TargetConditionals.h>

#if TARGET_OS_IPHONE

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/ip.h"
#include "lwip/timeouts.h"
#include "lwip/ip4_addr.h"

static void (*g_output_cb)(const uint8_t *data, size_t len) = 0;
static void (*g_proxy_output_cb)(const uint8_t *data, size_t len) = 0;
static int g_running = 0;
static struct netif g_tunif;
static struct netif g_proxynetif;

void rlwip_set_output(void (*cb)(const uint8_t *data, size_t len)) {
    g_output_cb = cb;
}

void rlwip_set_proxy_output(void (*cb)(const uint8_t *data, size_t len)) {
    g_proxy_output_cb = cb;
}

// Called by our netif port to emit outbound IP packets towards Swift
void rlwip_trampoline_output(const uint8_t *data, size_t len) {
    if (g_output_cb && data && len) {
        g_output_cb(data, len);
    }
}

// From port file
extern err_t tunif_init(struct netif *netif);
extern err_t proxynetif_init(struct netif *netif);

int rlwip_start(void) {
    if (g_running) return 1;
    lwip_init();
    memset(&g_tunif, 0, sizeof(g_tunif));
    memset(&g_proxynetif, 0, sizeof(g_proxynetif));
    if (!netif_add(&g_proxynetif, NULL, NULL, NULL, NULL, proxynetif_init, ip_input)) {
        return 0;
    }
    if (!netif_add(&g_tunif, NULL, NULL, NULL, NULL, tunif_init, ip_input)) {
        return 0;
    }
    // Assign IPv4 addresses so routing/forwarding works (avoid ANY addresses)
    ip4_addr_t px_addr, px_mask, px_gw;
    IP4_ADDR(&px_addr, 100, 64, 0, 1);
    IP4_ADDR(&px_mask, 255, 255, 255, 0);
    IP4_ADDR(&px_gw, 0, 0, 0, 0);
    netif_set_addr(&g_proxynetif, &px_addr, &px_mask, &px_gw);

    // CRITICAL FIX: Configure tunif with non-loopback address to avoid kernel 127/8 handling
    ip4_addr_t tn_addr, tn_mask, tn_gw;
    IP4_ADDR(&tn_addr, 100, 64, 0, 2);     // Use non-loopback tunnel interface IP 100.64.0.2
    IP4_ADDR(&tn_mask, 255, 255, 255, 0);  // /24 netmask for tunnel network  
    IP4_ADDR(&tn_gw, 0, 0, 0, 0);
    netif_set_addr(&g_tunif, &tn_addr, &tn_mask, &tn_gw);
    // Use proxynetif as default egress (terminating proxy), tunif handles OS-side ingress/egress
    netif_set_default(&g_proxynetif);
    netif_set_up(&g_proxynetif);
    netif_set_up(&g_tunif);
    g_running = 1;
    return 1;
}

void rlwip_stop(void) {
    if (!g_running) return;
    netif_set_down(&g_tunif);
    netif_set_down(&g_proxynetif);
    g_running = 0;
}

int rlwip_feed_packet(const uint8_t *data, size_t len) {
    if (!g_running || !data || !len) return 0;
    if (len > 0xFFFF) {
        // Defensive: lwIP pbuf lengths are u16_t; reject oversized buffers
        return 0;
    }
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) return 0;
    pbuf_take(p, data, (u16_t)len);
    err_t err = g_tunif.input(p, &g_tunif);
    if (err != ERR_OK) {
        pbuf_free(p);
        return 0;
    }
    return 1;
}

// Proxynetif trampoline: called by netif_proxynetif to hand outbound payloads to Swift socket bridge
void rlwip_proxynetif_trampoline_output(const uint8_t *data, size_t len) {
    if (g_proxy_output_cb && data && len) {
        g_proxy_output_cb(data, len);
    }
}

// Injection API for Internet-side data headed back into lwIP through proxynetif
int rlwip_inject_proxynetif(const uint8_t *data, size_t len) {
    if (!g_running || !data || !len) return 0;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) return 0;
    pbuf_take(p, data, (u16_t)len);
    // Deliver as if received on proxynetif
    err_t err = g_proxynetif.input(p, &g_proxynetif);
    if (err != ERR_OK) {
        pbuf_free(p);
        return 0;
    }
    return 1;
}

// Drive lwIP software timers (NO_SYS=1) periodically from Swift
void rlwip_drive_timeouts(void) {
    sys_check_timeouts();
}

// iOS end
#else

// Non-iOS host builds (e.g., macOS unit tests): provide no-op stubs so we don't
// require linking the full lwIP core. These stubs allow building and running
// tests that exercise pure-Swift helpers without driving the C stack.
static void (*g_output_cb)(const uint8_t *data, size_t len) = 0;
static void (*g_proxy_output_cb)(const uint8_t *data, size_t len) = 0;
int rlwip_start(void) { return 1; }
void rlwip_stop(void) {}
void rlwip_set_output(void (*cb)(const uint8_t *data, size_t len)) { g_output_cb = cb; }
void rlwip_set_proxy_output(void (*cb)(const uint8_t *data, size_t len)) { g_proxy_output_cb = cb; }
void rlwip_trampoline_output(const uint8_t *data, size_t len) { if (g_output_cb && data && len) { g_output_cb(data, len); } }
void rlwip_proxynetif_trampoline_output(const uint8_t *data, size_t len) { if (g_proxy_output_cb && data && len) { g_proxy_output_cb(data, len); } }
int rlwip_feed_packet(const uint8_t *data, size_t len) { (void)data; (void)len; return 1; }
int rlwip_inject_proxynetif(const uint8_t *data, size_t len) { (void)data; (void)len; return 1; }
void rlwip_drive_timeouts(void) {}

#endif
