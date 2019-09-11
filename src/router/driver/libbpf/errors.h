// +build linux

#ifndef __GLASNOSTIC_LIBBPF_ERRORS_H__
#define __GLASNOSTIC_LIBBPF_ERRORS_H__

enum init_error {
	E_ALREADY_INITED  = -1,
	E_ALLOC_XSK_PTR   = -2,
	E_ALLOC_UMEM_CFG  = -3,
	E_ALLOC_UMEM_PTR  = -4,
	E_CREATE_XSK      = -5,
	E_GET_NIC_IDX     = -6,
	E_LINK_BPF_TO_XSK = -7,
	E_RESERVE_FQ_BUF  = -8
};


// report_errno return last set errno
char * report_errno();

#endif // __GLASNOSTIC_LIBBPF_ERRORS_H__
