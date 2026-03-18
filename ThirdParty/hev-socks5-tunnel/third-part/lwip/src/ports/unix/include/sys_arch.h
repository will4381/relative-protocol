/*
 * Minimal unix lwIP sys_arch shim for the vendored hev-socks5-tunnel build.
 *
 * The tunnel uses lwIP with NO_SYS=1 and SYS_LIGHTWEIGHT_PROT=0, so the full
 * unix sys_arch implementation is not required here.
 */

#ifndef LWIP_PORT_UNIX_SYS_ARCH_H
#define LWIP_PORT_UNIX_SYS_ARCH_H

typedef unsigned long sys_prot_t;

#endif /* LWIP_PORT_UNIX_SYS_ARCH_H */
