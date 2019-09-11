// +build linux

#include <errno.h>        // for errno reporting
#include <stdint.h>       // for uintptr_t
#include <stdlib.h>       // for calloc
#include <net/if.h>       // for if_nametoindex
#include <unistd.h>       // for getpagesize
#include <string.h>       // for memcpy, strerror
#include <sys/types.h>    // for sendto
#include <sys/socket.h>   // for sendto
#include <sys/mman.h>     // for mmap
#include <linux/if_xdp.h> // for xdp_desc
#include <poll.h>         // for pollfds
#include <uapi/linux/if_link.h> // for XDP_FLAGS, XDP_FLAGS_SKB_MODE

#include "runner.h"       // for self-defined function declaration
#include "xdp.h"          // for self-defined data structure declaration
#include "errors.h"       // for self-defined error-number declaration

#include "libbpf.h"       // must from libbpf/libbpf.h
#include "xsk.h"          // must from libbpf/xsk.h

#define NUM_FRAMES			(1U << 12)
#define BURST_SIZE			(NUM_FRAMES >> 2)
#define FRAME_BATCH_SIZE		(BURST_SIZE >> 2)
#define SINGLE_FRAME			1

static struct xsk_sock_ptr* xsk_ptr = NULL;
static struct pollfd fds;
__u32 rx_idx = 0;
__u32 fq_idx = 0;
__u32 cq_idx = 0;

static inline size_t max_fetch(size_t request_frames)
{
	return (FRAME_BATCH_SIZE > request_frames) ? request_frames : FRAME_BATCH_SIZE;
}

static inline bool ignored(int n)
{
	return n == ENOBUFS || n == EAGAIN || n == EBUSY;
}

// configure_xsk_umem should allocate memory with given size
static struct xsk_umem_ptr *configure_xsk_umem(char *ifname, __u64 size)
{
	void *buffer_addr = NULL;
	struct xsk_umem_ptr *umem = calloc(1, sizeof(*umem));
	if (!umem) {
		fprintf(stderr, "ERROR: allocate xsk_umem_ptr failed\n");
		return NULL;
	}
	// buffer_addr = aligned_alloc(getpagesize(), size);
	buffer_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	/* FIXME: still no idea why the memory allocated from aligned_alloc
	 * can't be free. If I try to free it in following checks, the free
	 * calls would cause a SIGSEGV signal and crash our process. For the
	 * time being, let the system recycle those memory for us.
	 */
	if (!buffer_addr) {
		fprintf(stderr, "ERROR: allocate aligned memory failed\n");
		return NULL;
	}
	int ret = xsk_umem__create(&umem->umem, buffer_addr, size, &umem->fq, &umem->cq, NULL);
	if (ret != 0) {
		fprintf(stderr, "ERROR: create xsk_umem__create failed\n");
		fprintf(stderr, "       error code %d:\"%s\" \n", ret, strerror(errno));
		return NULL;
	}
	umem->buf = buffer_addr;
	return umem;
}

// init_afxdp_with_libbpf
int init_afxdp_with_libbpf(char *ifname, int queue_id)
{
	struct xsk_socket_config cfg;
	__u32 opt_xdp_flags = XDP_FLAGS_SKB_MODE;
	__u32 opt_xdp_bind_flags = 0;

	// create xsk_sock_ptr object
	struct xsk_sock_ptr *xsk = NULL;
	if (xsk_ptr != NULL) {
		return E_ALREADY_INITED;
	}
	xsk = calloc(1, sizeof(*xsk));
	if (!xsk) {
		// failed to allocate memory for socket ptr
		return E_ALLOC_XSK_PTR;
	}

	// allocate and register umem to xsk_sock_ptr object
	xsk->umem = configure_xsk_umem(ifname, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
	if (!xsk->umem) {
		// allocate memory for umem ptr failed
		return E_ALLOC_UMEM_PTR;
	}

	// setup cfg content
	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	cfg.libbpf_flags = 0;
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;

	// create AF_XDP socket
	if (xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem->umem, &xsk->rx, &xsk->tx, &cfg) != 0) {
		// failed to create AF_XDP socket
		fprintf(stderr, "ERROR: xsk_socket__create failed\n");
		return E_CREATE_XSK;
	}

	// get nic index by its name
	xsk->nicindex = if_nametoindex(ifname);
	if (!xsk->nicindex) {
		// failed to get nic index
		fprintf(stderr, "ERROR: if_nametoindex failed\n");
		return E_GET_NIC_IDX;
	}

	// link bpf for AF_XDP
	if (bpf_get_link_xdp_id(xsk->nicindex, &(xsk->prog_id), opt_xdp_flags) != 0) {
		// failed to link bpf for AF_XDP
		fprintf(stderr, "ERROR: bpf_get_link_xdp_id failed\n");
		return E_LINK_BPF_TO_XSK;
	}

	// reserve producer buffer for FQ
	if (xsk_ring_prod__reserve(&xsk->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &fq_idx) != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		// failed to reserve producer buffer
		return E_RESERVE_FQ_BUF;
	}

	// init fq ring addresses
	for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * XSK_UMEM__DEFAULT_FRAME_SIZE; i += XSK_UMEM__DEFAULT_FRAME_SIZE) {
		*xsk_ring_prod__fill_addr(&xsk->umem->fq, fq_idx++) = i;
	}

	// move FQ producer ptr forward, to let kernel know there's more free
	// spaces can pass packets in
	xsk_ring_prod__submit(&xsk->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	
	// store xsk_ptr
	xsk_ptr = xsk;

	// setup pollfds
	fds.fd = xsk_socket__fd(xsk_ptr->xsk);
	fds.events = POLLIN;

	return 0;
}

// exit_afxdp_with_libbpf
int exit_afxdp_with_libbpf()
{
	if (NULL == xsk_ptr) {
		// xsk_ptr not existed, can't clean up
		return -1; // FIXME: return error number
	}
	xsk_socket__delete(xsk_ptr->xsk);
	xsk_umem__delete(xsk_ptr->umem->umem);
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(xsk_ptr->nicindex, &curr_prog_id, XDP_FLAGS_UPDATE_IF_NOEXIST)){
		// can't get curr_prog_id of nic or not existed
		return -1; // should return different error code
	}

	if (xsk_ptr->prog_id == curr_prog_id) {
		bpf_set_link_xdp_fd(xsk_ptr->nicindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
		xsk_ptr = NULL;
	}

	return 0;
}

int poll_libbpf()
{
	return poll(&fds, 1, 100);
}

int poll_packets_with_libbpf(size_t request_frames)
{
	int ret = 0;
	uint16_t rx_pkts_number = xsk_ring_cons__peek(&xsk_ptr->rx, max_fetch(request_frames), &rx_idx);
	if (rx_pkts_number == 0) {
		return 0;
	}

	do {
		ret = xsk_ring_prod__reserve(&xsk_ptr->umem->fq, rx_pkts_number, &fq_idx);
	} while(ret != rx_pkts_number);

	return rx_pkts_number;
}

int read_packet_from_fq_torx_with_libbpf(uintptr_t bptr)
{
	unsigned char ** bufptr = (unsigned char **)bptr;
	const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&xsk_ptr->rx, rx_idx);
	uint64_t addr = rx_desc->addr;
	uint32_t len = rx_desc->len;
	*bufptr = xsk_umem__get_data(xsk_ptr->umem->buf, addr);
	return len;
}

void drop_rx_packet_to_fq()
{
	const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&xsk_ptr->rx, rx_idx);
	uint64_t addr = rx_desc->addr;
	*xsk_ring_prod__fill_addr(&xsk_ptr->umem->fq, fq_idx++) = addr;
}

int pass_rx_packet_to_tx(uint32_t len)
{
	__u32 tx_idx = 0;
	struct xdp_desc *tx_desc;

	int ret = xsk_ring_prod__reserve(&xsk_ptr->tx, SINGLE_FRAME, &tx_idx);
	if (ret != SINGLE_FRAME) {
		return 0;
	}
	tx_desc = xsk_ring_prod__tx_desc(&xsk_ptr->tx, tx_idx);
	const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&xsk_ptr->rx, rx_idx);
	uint64_t addr = rx_desc->addr;
	tx_desc->addr = addr;
	tx_desc->len = len;
	return ret;
}

int new_packet_wit_libbpf(unsigned char * buf, size_t len)
{
	const struct xdp_desc *rx_desc = xsk_ring_cons__rx_desc(&xsk_ptr->rx, rx_idx);
	void *pkt = xsk_umem__get_data(xsk_ptr->umem->buf, rx_desc->addr);
	memcpy(pkt, buf, len);
	return pass_rx_packet_to_tx(len);
}

void rx_fwd()
{
	rx_idx++;
}

int flush_tx(int num_frames)
{
	xsk_ring_prod__submit(&xsk_ptr->tx, num_frames);
	int res = sendto(xsk_socket__fd(xsk_ptr->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (res < 0 && !ignored(errno)) {
		fprintf(stderr, "send packet to xsk_socket failed with \"%s\"\n", strerror(errno));
		res = -errno;
	}
	return res;
}

void flush_fq(int num_frames)
{
	xsk_ring_prod__submit(&xsk_ptr->umem->fq, num_frames);
}

void flush_rx(int num_frames)
{
	xsk_ring_cons__release(&xsk_ptr->rx, num_frames);
}

void flush_cq(int num_frames)
{
	int txed_packets = xsk_ring_cons__peek(&xsk_ptr->umem->cq, num_frames, &cq_idx);
	if (txed_packets > 0) {
		xsk_ring_cons__release(&xsk_ptr->umem->cq, txed_packets);
	}
}
