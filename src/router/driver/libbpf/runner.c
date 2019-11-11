// +build linux

#include <errno.h>        // for errno reporting
#include <stdint.h>       // for uintptr_t
#include <stdlib.h>       // for calloc
#include <net/if.h>       // for if_nametoindex
#include <unistd.h>       // for getpagesize
#include <string.h>       // for memcpy, strerror
#include <poll.h>         // for pollfds
#include <sys/types.h>    // for sendto
#include <sys/socket.h>   // for sendto
#include <sys/mman.h>     // for mmap
#include <linux/if_xdp.h> // for xdp_desc
#include <uapi/linux/if_link.h> // for XDP_FLAGS, XDP_FLAGS_SKB_MODE

#include "runner.h"       // for exported CGO function declaration
#include "xdp.h"          // for data structure declaration
#include "errors.h"       // for error-number declaration
#include "mempool.h"      // for memory pool implementation

#include "libbpf.h"       // must from libbpf/libbpf.h
#include "xsk.h"          // must from libbpf/xsk.h

static uint32_t idx_fq = 0;
static uint32_t idx_rx = 0;

static inline void ring_cons_msg(const char *msg, struct xsk_ring_cons *cons)
{
	fprintf(stderr, "%s: cached_prod %03d, producer %03d, cached_cons %03d, size %03d\n",
			msg, cons->cached_prod, *cons->producer, cons->cached_cons, cons->size);
}

static inline void ring_prod_msg(const char *msg, struct xsk_ring_prod *prod)
{
	fprintf(stderr, "%s: cached_prod %03d, cached_cons %03d, consumer %03d, size %03d\n",
			msg, prod->cached_prod, prod->cached_cons, *prod->consumer, prod->size);
}

// configure_xsk_umem should allocate memory with given size
static struct xsk_umem_ptr *configure_xsk_umem(char *ifname, struct xsk_umem_config *umem_config, __u64 size)
{
	struct xsk_umem_ptr *umem_ptr = calloc(1, sizeof(*umem_ptr));
	if (!umem_ptr) {
		fprintf(stderr, "ERROR: allocate xsk_umem_ptr failed\n");
		return NULL;
	}
	void *buffer_addr = NULL;
	buffer_addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	/* FIXME: still no idea why the memory allocated from aligned_alloc or
	 * mmap can't be free here. If I try to free it in following checks,
	 * the free call would cause a SIGSEGV signal and crash our process.
	 * For the time being, let the system recycle those memory for us.
	 */
	if (!buffer_addr) {
		fprintf(stderr, "ERROR: allocate aligned memory failed\n");
		return NULL;
	}

	int ret = xsk_umem__create(&umem_ptr->umem, buffer_addr, size,
				   &umem_ptr->fq, &umem_ptr->cq, umem_config);
	if (ret != 0) {
		fprintf(stderr, "ERROR: create xsk_umem__create failed\n");
		fprintf(stderr, "       error code %d:\"%s\" \n",
			ret, strerror(errno));
		return NULL;
	}
	umem_ptr->buf = buffer_addr;
	return umem_ptr;
}

// libbpf_xsk__init
struct libbpf *libbpf_xsk__init(char *ifname, int queue_id)
{
	__u32 opt_xdp_flags = XDP_FLAGS_SKB_MODE;
	__u32 opt_xdp_bind_flags = 0;

	// create libbpf pointer object
	struct libbpf *ptr = calloc(1, sizeof(*ptr));
	if (!ptr) {
		goto init_out;
	}

	// create xsk_sock_ptr object
	struct xsk_sock_ptr *xsk = calloc(1, sizeof(*xsk));
	if (!xsk) {
		// failed to allocate memory for socket ptr
		ptr->err = E_ALLOC_XSK_PTR;
		goto init_out;
	}

	// allocate and register umem to xsk_sock_ptr object
	// also create umem mempool
	struct xsk_umem_config umem_config = {
		.fill_size = LIBBPF_XSK_RING_PROD_NUM_DESCS,
		.comp_size = LIBBPF_XSK_RING_CONS_NUM_DESCS,
		.frame_size = LIBBPF_XSK_RING_FRAME_SIZE,
		.frame_headroom = LIBBPF_XSK_RING_FRAME_HEADROOM,
	};

	xsk->umem = configure_xsk_umem(ifname, &umem_config, LIBBPF_XSK_MEMPOOL_NUM_FRAMES * LIBBPF_XSK_RING_FRAME_SIZE);
	if (!xsk->umem) {
		// allocate memory for umem ptr failed
		ptr->err = E_ALLOC_UMEM_PTR;
		goto init_out;
	}

	// create mempool object
	ptr->pool = mempool_create((uint64_t)xsk->umem->buf, LIBBPF_XSK_MEMPOOL_NUM_FRAMES, LIBBPF_XSK_RING_FRAME_SIZE);
	if (!ptr->pool) {
		ptr->err = E_ALLOC_MEMPOOL;
		goto init_out;
	}

	// create inqueue object
	ptr->inqueue = calloc(LIBBPF_XSK_RING_BATCH_SIZE, sizeof(struct membuf));
	if (!ptr->inqueue) {
		ptr->err = E_ALLOC_INQUEUE;
		goto init_out;
	}
	// create bufs cache
	ptr->bufs = calloc(LIBBPF_XSK_RING_BATCH_SIZE, sizeof(uint64_t));
	if (!ptr->bufs) {
		ptr->err = E_ALLOC_MEM_BUFS;
		goto init_out;
	}

	// setup cfg content
	struct xsk_socket_config cfg = {
		.rx_size = LIBBPF_XSK_RING_CONS_NUM_DESCS,
		.tx_size = LIBBPF_XSK_RING_PROD_NUM_DESCS,
		.libbpf_flags = 0,
		.xdp_flags = opt_xdp_flags,
		.bind_flags = opt_xdp_bind_flags,
	};

	// create AF_XDP socket
	if (xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem->umem, &xsk->rx, &xsk->tx, &cfg) != 0) {
		// failed to create AF_XDP socket
		fprintf(stderr, "ERROR: xsk_socket__create failed\n");
		ptr->err = E_CREATE_XSK;
		goto init_out;
	}

	// get nic index by its name
	xsk->nicindex = if_nametoindex(ifname);
	if (!xsk->nicindex) {
		// failed to get nic index
		fprintf(stderr, "ERROR: if_nametoindex failed\n");
		ptr->err = E_GET_NIC_IDX;
		goto init_out;
	}

	// link bpf for AF_XDP
	if (bpf_get_link_xdp_id(xsk->nicindex, &(xsk->prog_id), opt_xdp_flags) != 0) {
		// failed to link bpf for AF_XDP
		fprintf(stderr, "ERROR: bpf_get_link_xdp_id failed\n");
		ptr->err = E_LINK_BPF_TO_XSK;
		goto init_out;
	}

	// reserve producer buffer for FQ
	if (xsk_ring_prod__reserve(&xsk->umem->fq, LIBBPF_XSK_RING_PROD_NUM_DESCS, &idx_fq) != LIBBPF_XSK_RING_PROD_NUM_DESCS) {
		// failed to reserve producer buffer
		ptr->err = E_RESERVE_FQ_BUF;
		goto init_out;
	}

	// init fq ring addresses
	for (int i = 0; i < LIBBPF_XSK_RING_PROD_NUM_DESCS; i++) {
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = pop(ptr->pool);
	}

	// move FQ producer ptr forward, to let kernel know there's more free
	// spaces can pass packets in
	xsk_ring_prod__submit(&xsk->umem->fq, LIBBPF_XSK_RING_PROD_NUM_DESCS);
	
	ptr->xsk = xsk;
	ptr->fds.fd = xsk_socket__fd(xsk->xsk);
	ptr->fds.events = POLLIN;

init_out:
	return ptr;
}

// libbpf_xsk__exit
int libbpf_xsk__exit(struct libbpf *ptr)
{
	if (NULL == ptr || NULL == ptr->xsk) {
		return -1; // FIXME: return error number
	}
	xsk_socket__delete(ptr->xsk->xsk);
	xsk_umem__delete(ptr->xsk->umem->umem);
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(ptr->xsk->nicindex, &curr_prog_id, XDP_FLAGS_UPDATE_IF_NOEXIST)){
		// can't get curr_prog_id of nic or not existed
		return -1; // should return different error code
	}

	if (ptr->xsk->prog_id == curr_prog_id) {
		bpf_set_link_xdp_fd(ptr->xsk->nicindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
	}

	return 0;
}

// libbpf_xsk__kick_tx
int libbpf_xsk__kick_tx(struct libbpf *ptr, uint16_t pkts)
{
	xsk_ring_prod__submit(&ptr->xsk->tx, pkts);
	int res = sendto(xsk_socket__fd(ptr->xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (res < 0 && !ignored(errno)) {
		libbpf_xsk__pull_cq(ptr);
		fprintf(stderr, "send packet to xsk_socket failed with \"%s\"\n", strerror(errno));
		res = -errno;
	}
	return res;
}

// libbpf_xsk__pull_rx check how many pakcets in RX and move them into inqueue
int libbpf_xsk__pull_rx(struct libbpf *ptr, size_t nb_pkts)
{
	struct xsk_ring_cons *rx = &ptr->xsk->rx;
	struct xsk_ring_prod *fq = &ptr->xsk->umem->fq;
	size_t received = 0;
	// xsk_ring_cons__peek will return how many packets landing in RX
	received = xsk_ring_cons__peek(rx, max_fetch(nb_pkts), &idx_rx);
	fprintf(stderr, "Try to peek %d but got %d packets\n", max_fetch(nb_pkts), received);
	// fprintf(stderr, "RX: %d, FQ: %d\n", idx_rx, idx_fq);
	ring_prod_msg("FQ", fq);
	ring_cons_msg("RX", rx);

	if (!received) {
		poll(&ptr->fds, 1, 100);
		goto pull_rx_empty;
	}

	// ===== try to fill up FQ as much as possible =====
	// 1. prepare membuf from mempool
	// 2. reserve xsk desc from FQ, if failed release membuf from (1) back
	//    to mempool
	// 3. fill FQ with membuf addresses

	// 1. prepare membuf from mempool
	if (!allocate(ptr->pool, ptr->bufs, nb_pkts)) {
		goto pull_rx_out;
	}

	// xsk_ring_prod__reserver will return 0 (if buffer not enough) or just
	// the number we asked.
	// reserve nb_pkts xsk desc from FQ
	// if failed, release those membuf and skipping fill FQ
	if (!xsk_ring_prod__reserve(fq, nb_pkts, &idx_fq)) {
		release(ptr->pool, ptr->bufs, nb_pkts);
		goto pull_rx_out;
	}

	// fill FQ with nb_pkts buffers
	for (int i = 0; i < nb_pkts; i++) {
		*xsk_ring_prod__fill_addr(&ptr->xsk->umem->fq, idx_fq++) = (uint64_t)ptr->bufs[i];
	}

	xsk_ring_prod__submit(&ptr->xsk->umem->fq, nb_pkts);

pull_rx_out:

	ptr->current_cached = received;
	ptr->current = 0;
	// read packets from RX to inqueue
	for (int i = 0; i < received; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, idx_rx++);
		ptr->inqueue[i].addr = desc->addr;
		ptr->inqueue[i].len = desc->len;
	}
	xsk_ring_cons__release(&ptr->xsk->rx, received);

pull_rx_empty:
	return received;
}

// libbpf_xsk__pull_cq check CQ sent packet, and push them back to mempool
int libbpf_xsk__pull_cq(struct libbpf *ptr)
{
	struct xsk_ring_cons *cq = &ptr->xsk->umem->cq;
	uint32_t idx_cq = 0;

	size_t n = xsk_ring_cons__peek(cq, LIBBPF_XSK_RING_BATCH_SIZE, &idx_cq);

	for (int i = 0; i < n; i++) {
		uint64_t addr = *xsk_ring_cons__comp_addr(cq, idx_cq++);
		push(ptr->pool, addr);
	}

	xsk_ring_cons__release(cq, n);
	return n;
}

// libbpf_xsk__pkt_read read current mbuf from the inqueue
uint32_t libbpf_xsk__pkt_read(const struct libbpf *ptr, uintptr_t bptr)
{
	// unlikely
	if (ptr->current >= ptr->current_cached) {
		return 0;
	}

	unsigned char ** bufptr = (unsigned char **)bptr;
	const struct membuf *buf = &ptr->inqueue[ptr->current];
	uint64_t addr = buf->addr;
	uint32_t len = buf->len;

	*bufptr = xsk_umem__get_data(ptr->xsk->umem->buf, addr);

	return len;
}

// libbpf_xsk__pkt_write allocate a new membuf, write data into it
// move new membuf to tx, trigger libbpf_xsk__kick_tx
int libbpf_xsk__pkt_write(struct libbpf *ptr, const unsigned char *buf, const size_t len)
{
	// If buf addr is the same as "current", we just pass this pkt buffer
	// to tx. If buf addr is not the same as "current", we copy the content
	// from it and move the pkt buffer to tx.
	//
	// 1. Copy content from buf to current if it's not the same addr
	// 2. move pkt buffer to tx
	// 3. trigger libbpf_xsk__kick_tx
	//
	int current = ptr->current;
	void * addr = xsk_umem__get_data(ptr->xsk->umem->buf, ptr->inqueue[current].addr);
	if ((uint64_t)addr != (uint64_t)buf) {
		memcpy(addr, buf, len);
	}
	ptr->inqueue[current].len = len;

	return libbpf_xsk__pkt_pass(ptr, buf, len);
}

// libbpf_xsk__pkt_pass move current membuf from rx to tx and trigger libbpf_xsk__kick_tx
int libbpf_xsk__pkt_pass(struct libbpf *ptr, const unsigned char *buf, const size_t len)
{
	// move current inqueue memory to TX
	int current = ptr->current++;
	int idx_tx = 0;
	if (!xsk_ring_prod__reserve(&ptr->xsk->tx, 1, &idx_tx)) {
		return -1;
	}
	struct xdp_desc *desc = xsk_ring_prod__tx_desc(&ptr->xsk->tx, idx_tx);
	desc->len = len;
	desc->addr = (uint64_t)ptr->inqueue[current].addr;
	return libbpf_xsk__kick_tx(ptr, 1);
}

// libbpf_xsk__pkt_drop release current membuf from rx back to mempool
int libbpf_xsk__pkt_drop(struct libbpf *ptr)
{
	// release current inqueue memory back to mempool
	return push(ptr->pool, ptr->inqueue[ptr->current++].addr);
}

void report_ring(struct libbpf *ptr)
{
	ring_prod_msg("FQ", &ptr->xsk->umem->fq);
	ring_cons_msg("RX", &ptr->xsk->rx);
	ring_prod_msg("TX", &ptr->xsk->tx);
	ring_cons_msg("CQ", &ptr->xsk->umem->cq);
}
