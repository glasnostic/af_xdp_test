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

// configure_xsk_umem should allocate memory with given size
static struct xsk_umem_ptr *configure_xsk_umem(char *ifname, __u64 size)
{
	void *buffer_addr = NULL;
	struct xsk_umem_ptr *umem = calloc(1, sizeof(*umem));
	if (!umem) {
		fprintf(stderr, "ERROR: allocate xsk_umem_ptr failed\n");
		return NULL;
	}
	buffer_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	/* FIXME: still no idea why the memory allocated from aligned_alloc or 
	 * mmap can't be free here. If I try to free it in following checks,
	 * the free call would cause a SIGSEGV signal and crash our process.
	 * For the time being, let the system recycle those memory for us.
	 */
	if (!buffer_addr) {
		fprintf(stderr, "ERROR: allocate aligned memory failed\n");
		return NULL;
	}
	struct xsk_umem_config *user_config = NULL; // just make the parameter meaningful
	int ret = xsk_umem__create(&umem->umem, buffer_addr, size, &umem->fq, &umem->cq, user_config);
	if (ret != 0) {
		fprintf(stderr, "ERROR: create xsk_umem__create failed\n");
		fprintf(stderr, "       error code %d:\"%s\" \n", ret, strerror(errno));
		return NULL;
	}
	umem->buf = buffer_addr;
	return umem;
}

// libbpf_xsk__init
struct libbpf *libbpf_xsk__init(char *ifname, int queue_id)
{
	__u32 opt_xdp_flags = XDP_FLAGS_SKB_MODE;
	__u32 opt_xdp_bind_flags = 0;

	// create libbpf pointer object
	struct libbpf *ptr = calloc(1, sizeof(*ptr));
	if (!ptr) {
		goto out;
	}

	// create xsk_sock_ptr object
	struct xsk_sock_ptr *xsk = calloc(1, sizeof(*xsk));
	if (!xsk) {
		// failed to allocate memory for socket ptr
		ptr->err = E_ALLOC_XSK_PTR;
		goto out;
	}

	// allocate and register umem to xsk_sock_ptr object
	// also create umem mempool
	xsk->umem = configure_xsk_umem(ifname, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (!xsk->umem) {
		// allocate memory for umem ptr failed
		ptr->err = E_ALLOC_UMEM_PTR;
		goto out;
	}

	// create mempool object
	ptr->pool = mempool_create(xsk->umem->buf, NUM_FRAMES, XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (!ptr->pool) {
		ptr->err = E_ALLOC_MEMPOOL;
		goto out;
	}

	// create inqueue object
	ptr->inqueue = calloc(FRAME_BATCH_SIZE, sizeof(struct membuf));
	if (!ptr->inqueue) {
		ptr->err = E_ALLOC_INQUEUE;
		goto out;
	}
	// create bufs cache
	ptr->bufs = calloc(FRAME_BATCH_SIZE, sizeof(void *));
	if (!ptr->bufs) {
		ptr->err = E_ALLOC_MEM_BUFS;
		goto out;
	}

	// setup cfg content
	struct xsk_socket_config cfg;
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;

	// create AF_XDP socket
	if (xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem->umem, &xsk->rx, &xsk->tx, &cfg) != 0) {
		// failed to create AF_XDP socket
		fprintf(stderr, "ERROR: xsk_socket__create failed\n");
		ptr->err = E_CREATE_XSK;
		goto out;
	}

	// get nic index by its name
	xsk->nicindex = if_nametoindex(ifname);
	if (!xsk->nicindex) {
		// failed to get nic index
		fprintf(stderr, "ERROR: if_nametoindex failed\n");
		ptr->err = E_GET_NIC_IDX;
		goto out;
	}

	// link bpf for AF_XDP
	if (bpf_get_link_xdp_id(xsk->nicindex, &(xsk->prog_id), opt_xdp_flags) != 0) {
		// failed to link bpf for AF_XDP
		fprintf(stderr, "ERROR: bpf_get_link_xdp_id failed\n");
		ptr->err = E_LINK_BPF_TO_XSK;
		goto out;
	}

	// reserve producer buffer for FQ
	int idx_fq = 0;
	if (xsk_ring_prod__reserve(&xsk->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx_fq) != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		// failed to reserve producer buffer
		ptr->err = E_RESERVE_FQ_BUF;
		goto out;
	}

	// init fq ring addresses
	for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) = (uint64_t)pop(ptr->pool);
	}

	// move FQ producer ptr forward, to let kernel know there's more free
	// spaces can pass packets in
	xsk_ring_prod__submit(&xsk->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	
	ptr->xsk = xsk;
	ptr->fds.fd = xsk_socket__fd(ptr->xsk->xsk);
	ptr->fds.events = POLLIN;

out:
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

// kick_tx
int kick_tx(struct libbpf *ptr, uint16_t pkts)
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

// libbpf_xsk__poll check how many pakcets in RX and move them into inqueue
int libbpf_xsk__poll(struct libbpf *ptr, size_t nb_pkts)
{
	struct xsk_ring_cons *rx = &ptr->xsk->rx;
	size_t received = 0;
	uint32_t idx_rx = 0;
	uint32_t idx_fq = 0;
	// xsk_ring_cons__peek will return how many packets landing in RX
	received = xsk_ring_cons__peek(&ptr->xsk->rx, nb_pkts, &idx_rx);
	if (!received) {
		poll(&ptr->fds, 1, 1000);
		goto poll_empty;
	}

	// ===== try to fill up FQ as much as possible =====
	// 1. prepare membuf from mempool
	// 2. reserve xsk desc from FQ, if failed release membuf from (1) back
	//    to mempool
	// 3. fill FQ with membuf addresses

	// 1. prepare membuf from mempool
	if (!allocate(ptr->pool, ptr->bufs, nb_pkts)) {
		goto poll_out;
	}

	// xsk_ring_prod__reserver will return 0 (if buffer not enough) or just
	// the number we asked.
	// reserve nb_pkts xsk desc from FQ
	// if failed, release those membuf and skipping fill FQ
	if (!xsk_ring_prod__reserve(&ptr->xsk->umem->fq, nb_pkts, &idx_fq)) {
		release(ptr->pool, ptr->bufs, nb_pkts);
		goto poll_out;
	}

	// fill FQ with nb_pkts buffers
	for (int i = 0; i < nb_pkts; i++) {
		__u64 *fq_addr;
		uint64_t addr;

		fq_addr = xsk_ring_prod__fill_addr(&ptr->xsk->umem->fq, idx_fq++);
		addr = (uint64_t)ptr->bufs[i];
		*fq_addr = addr;
	}

	xsk_ring_prod__submit(&ptr->xsk->umem->fq, nb_pkts);

poll_out:

	// read packets from RX to inqueue
	for (int i = 0; i < received; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, idx_rx++);
		ptr->inqueue[i].addr = (void *)desc->addr;
		ptr->inqueue[i].len = desc->len;
	}
	xsk_ring_cons__release(&ptr->xsk->rx, received);

poll_empty:
	return received;
}

// libbpf_xsk__pull_cq check CQ sent packet, and push them back to mempool
int libbpf_xsk__pull_cq(struct libbpf *ptr)
{
	struct xsk_ring_cons *cq = &ptr->xsk->umem->cq;
	uint32_t idx_cq = 0;

	size_t n = xsk_ring_cons__peek(cq, FRAME_BATCH_SIZE, &idx_cq);

	for (int i = 0; i < n; i++) {
		void *addr = (void *)xsk_ring_cons__comp_addr(cq, idx_cq++);
		push(ptr->pool, addr);
	}

	xsk_ring_cons__release(cq, n);
	ptr->current = 0;
	return n;
}

// libbpf_xsk__pkt_read read current mbuf from the inqueue
int libbpf_xsk__pkt_read(const struct libbpf *ptr, uintptr_t bptr)
{
	if (ptr->current >= FRAME_BATCH_SIZE) {
		return 0;
	}

	unsigned char ** bufptr = (unsigned char **)bptr;
	const struct membuf *buf = &ptr->inqueue[ptr->current];
	uint64_t addr = (uint64_t)buf->addr;
	uint32_t len = buf->len;

	*bufptr = xsk_umem__get_data(ptr->xsk->umem->buf, addr);

	return len;
}

// libbpf_xsk__pkt_write allocate a new membuf, write data into it
// move new membuf to tx, trigger kick_tx
int libbpf_xsk__pkt_write(struct libbpf *ptr, const unsigned char *buf, const size_t len)
{
	// If buf addr is the same as "current", we just pass this pkt buffer
	// to tx. If buf addr is not the same as "current", we copy the content
	// from it and move the pkt buffer to tx.
	// 
	// 1. Copy content from buf to current if it's not the same addr
	// 2. move pkt buffer to tx
	// 3. trigger kick_tx
	//
	int current = ptr->current;
	if ((uint64_t)ptr->inqueue[current].addr != (uint64_t)buf) {
		memcpy((void *)ptr->inqueue[current].addr, buf, len);
	}
	ptr->inqueue[current].len = len;

	return libbpf_xsk__pkt_pass(ptr, buf, len);
}

// libbpf_xsk__pkt_pass move current membuf from rx to tx and trigger kick_tx
// WIP:
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
	return kick_tx(ptr, 1);
}

// libbpf_xsk__pkt_drop release current membuf from rx back to mempool
int libbpf_xsk__pkt_drop(struct libbpf *ptr)
{
	// release current inqueue memory back to mempool
	return push(ptr->pool, ptr->inqueue[ptr->current++].addr);
}
