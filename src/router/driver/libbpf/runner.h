// +build linux

#ifndef __GLASNOSTIC_LIBBPF_H__
#define __GLASNOSTIC_LIBBPF_H__

#include <stdint.h> // for uintptr_t
#include <stdlib.h> // for size_t

#include "xdp.h"    // for self-defined data structure

#define NUM_FRAMES			(1U << 12)
#define BURST_SIZE			(NUM_FRAMES >> 2)
#define FRAME_BATCH_SIZE		(BURST_SIZE >> 2)
#define SINGLE_FRAME			1

static inline size_t max_fetch(size_t request)
{
	return (FRAME_BATCH_SIZE > request) ? request : FRAME_BATCH_SIZE;
}

// libbpf_xsk__init
struct libbpf *libbpf_xsk__init(char *ifname, int queue_id);
// libbpf_xsk__exit
int libbpf_xsk__exit(struct libbpf *ptr);

// libbpf_xsk__poll
int libbpf_xsk__poll(struct libbpf *ptr, size_t nb_pkts);
// libbpf_xsk__pull_cq
int libbpf_xsk__pull_cq(struct libbpf *ptr);

// libbpf_xsk__pkt_read;
int libbpf_xsk__pkt_read(const struct libbpf *ptr, uintptr_t bptr);
// libbpf_xsk__pkt_write;
int libbpf_xsk__pkt_write(struct libbpf *ptr, const unsigned char *buf, const size_t len);
// libbpf_xsk__pkt_pass
int libbpf_xsk__pkt_pass(struct libbpf *ptr, const unsigned char *buf, const size_t len);
// libbpf_xsk__pkt_drop;
int libbpf_xsk__pkt_drop(struct libbpf *ptr);


#endif /* __GLASNOSTIC_LIBBPF_H__ */
