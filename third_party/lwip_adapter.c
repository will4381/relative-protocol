#include <stdint.h>
#include <stdbool.h>

/* Minimal lwIP adapter for RelativeVPN */

void lwip_vpn_init(void) {
    /* Initialize lwIP stack */
}

void lwip_vpn_input(const uint8_t *packet, size_t length) {
    /* Process incoming packet */
}

bool lwip_vpn_output(uint8_t *packet, size_t *length) {
    /* Generate outgoing packet */
    return false;
}

void lwip_vpn_cleanup(void) {
    /* Cleanup lwIP resources */
}
