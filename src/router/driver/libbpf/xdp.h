// +build linux

#ifndef __GLASNOSTIC_LIBBPF_XDP_H__
#define __GLASNOSTIC_LIBBPF_XDP_H__

#include "xsk.h"

struct xsk_umem_ptr {
	struct xsk_ring_prod fq; // fill queue
	struct xsk_ring_cons cq; // completion queue
	struct xsk_umem *umem;   // umem
	void * buf;              // raw buffer
};

struct xsk_sock_ptr {
	struct xsk_ring_cons rx; // RX ring
	struct xsk_ring_prod tx; // TX ring
	struct xsk_umem_ptr *umem;
	struct xsk_socket *xsk;
	int nicindex;
	__u32 prog_id;
};

struct libbpf_pointer {
	// struct pollfd pollfds;
	struct xsk_sock_ptr* xsk;
	__u32 rx_idx;
	__u32 tx_idx;
	__u32 fq_idx;
	__u32 cq_idx;
	int err;
};

#endif /* __GLASNOSTIC_LIBBPF_XDP_H__ */
