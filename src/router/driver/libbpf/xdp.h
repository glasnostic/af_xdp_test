// +build linux

#ifndef __GLASNOSTIC_LIBBPF_XDP_H__
#define __GLASNOSTIC_LIBBPF_XDP_H__

#include <poll.h>         // for pollfds

#include "xsk.h"
#include "mempool.h"

struct membuf {
	uint64_t addr;
	uint32_t len;
};

struct xsk_umem_ptr {
	struct xsk_ring_prod fq; // fill queue
	struct xsk_ring_cons cq; // completion queue
	struct xsk_umem *umem;   // umem
	void *buf;               // should be the same as umem->umem_area
};

struct xsk_sock_ptr {
	struct xsk_ring_cons rx; // RX ring
	struct xsk_ring_prod tx; // TX ring
	struct xsk_umem_ptr *umem;
	struct xsk_socket *xsk;
	int nicindex;
	__u32 prog_id;
};

struct libbpf {
	struct xsk_sock_ptr *xsk; //
	struct mempool *pool;     // memory pool of availables
	struct membuf *inqueue;   // membuf for reading packets
	struct membuf *outqueue;  // membuf for sending packets
	struct pollfd fds;        //
	uint64_t *bufs;           //
	int current;              // current idx of inqueue
	int current_cached;       // current cached size of inqueue
	int err;                  // error code
};

#endif /* __GLASNOSTIC_LIBBPF_XDP_H__ */
