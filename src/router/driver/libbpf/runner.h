// +build linux

#ifndef __GLASNOSTIC_LIBBPF_H__
#define __GLASNOSTIC_LIBBPF_H__

#include <stdint.h> // for uintptr_t
#include <stdlib.h> // for size_t

#include "xdp.h"    // for self-defined data structure

// init_afxdp_with_libbpf
int init_afxdp_with_libbpf(char *ifname, int queue);
// exit_afxdp_with_libbpf
int exit_afxdp_with_libbpf();
// poll_packets_with_libbpf
int poll_packets_with_libbpf(size_t request_frames);
// int reserve_packets_from_fq(size_t rx_buf_number);

int poll_libbpf();

// read_packet_from_fq_torx_with_libbpf
int read_packet_from_fq_torx_with_libbpf(uintptr_t bptr);
// new_packet_wit_libbpf
int new_packet_wit_libbpf(unsigned char * buf, size_t len);

int pass_rx_packet_to_tx(uint32_t len);

void drop_rx_packet_to_fq();

int flush_tx(int num_frames);
void flush_fq(int num_frames);
void flush_cq(int num_frames);
void flush_rx(int num_frames);
void rx_fwd();

#endif /* __GLASNOSTIC_LIBBPF_H__ */
