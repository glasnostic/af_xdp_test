// +build linux

#ifndef __GLASNOSTIC_LIBBPF_H__
#define __GLASNOSTIC_LIBBPF_H__

#include <stdint.h> // for uintptr_t
#include <stdlib.h> // for size_t

#include "xdp.h"    // for self-defined data structure

#define LIBBPF_XSK_MEMPOOL_NUM_FRAMES	(1U << 13) /* 4096 packets */
#define LIBBPF_XSK_RING_PROD_NUM_DESCS	(1U << 12) /* 2048 packets */
#define LIBBPF_XSK_RING_CONS_NUM_DESCS	(1U << 12) /* 2048 packets */
#define LIBBPF_XSK_RING_FRAME_SIZE	(1U << 12) /* 2048 bytes */
#define LIBBPF_XSK_RING_BATCH_SIZE	(LIBBPF_XSK_MEMPOOL_NUM_FRAMES >> 6)
#define LIBBPF_XSK_RING_FRAME_HEADROOM	0

static inline size_t max_fetch(size_t request)
{
	return (LIBBPF_XSK_RING_BATCH_SIZE > request) ? request : LIBBPF_XSK_RING_BATCH_SIZE;
}

// libbpf_xsk__init
struct libbpf *libbpf_xsk__init(char *ifname, int queue_id);
// libbpf_xsk__exit
int libbpf_xsk__exit(struct libbpf *ptr);

// libbpf_xsk__pull_rx
int libbpf_xsk__pull_rx(struct libbpf *ptr, size_t nb_pkts);
// libbpf_xsk__pull_cq
int libbpf_xsk__pull_cq(struct libbpf *ptr);
// libbpf_xsk__kick_tx
int libbpf_xsk__kick_tx(struct libbpf *ptr, uint16_t pkts);

// libbpf_xsk__pkt_read;
uint32_t libbpf_xsk__pkt_read(const struct libbpf *ptr, uintptr_t bptr);
// libbpf_xsk__pkt_write;
int libbpf_xsk__pkt_write(struct libbpf *ptr, const unsigned char *buf, const size_t len);
// libbpf_xsk__pkt_pass
int libbpf_xsk__pkt_pass(struct libbpf *ptr, const unsigned char *buf, const size_t len);
// libbpf_xsk__pkt_drop;
int libbpf_xsk__pkt_drop(struct libbpf *ptr);

void report_ring(struct libbpf *ptr);


#endif /* __GLASNOSTIC_LIBBPF_H__ */
