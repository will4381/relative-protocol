/*
 * Minimal unix lwIP portability shim for the vendored hev-socks5-tunnel build.
 *
 * This package only builds lwIP in NO_SYS mode on Apple platforms, so we keep
 * the unix port surface intentionally small instead of carrying the full
 * upstream unix port subtree.
 */

#ifndef LWIP_PORT_UNIX_CC_H
#define LWIP_PORT_UNIX_CC_H

#include <sys/types.h>
#include <sys/time.h>

#if defined(__APPLE__)
#include <machine/endian.h>
#endif

/* Use the platform timeval rather than a private lwIP definition. */
#define LWIP_TIMEVAL_PRIVATE 0

#endif /* LWIP_PORT_UNIX_CC_H */
