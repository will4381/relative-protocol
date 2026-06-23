// Created by Will Kusch, Relative Companies, Inc.
// Copyright (c) 2026 Relative Companies, Inc.
// Licensed for personal, non-commercial use only. See LICENSE for terms.

#ifndef RP_HARNESS_TUN_H
#define RP_HARNESS_TUN_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int rp_harness_open_tun(const char *requested_name,
                        int include_packet_info,
                        char *actual_name,
                        size_t actual_name_len,
                        int *out_errno);

ssize_t rp_harness_read_fd(int fd, void *buffer, size_t buffer_len, int *out_errno);
ssize_t rp_harness_write_fd(int fd, const void *buffer, size_t buffer_len, int *out_errno);
int rp_harness_close_fd(int fd);

#ifdef __cplusplus
}
#endif

#endif
