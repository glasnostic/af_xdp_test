package libbpf

/*
#include "errors.h"
*/
import "C"

import (
	"errors"
)

var (
	ErrInvalidLibbpf = errors.New("invalid libbpf init")
	ErrAlreadyInited = errors.New("already been inited")
	ErrAllocXskPtr   = errors.New("allocate xsk pointer")
	ErrAllocUmemCfg  = errors.New("allocate umem config")
	ErrAllocUmemPtr  = errors.New("allocate ueme pointer")
	ErrCreateXsk     = errors.New("create XSK")
	ErrGetNicIdx     = errors.New("get nic index")
	ErrLinkBpfToXsk  = errors.New("link bpf to xsk")
	ErrReserveFQBuf  = errors.New("reserve FQ buffer")
	ErrAllocMempool  = errors.New("allocate mempool failed")
	ErrAllocInqueue  = errors.New("allocate in-queue failed")
	ErrAllocMemBufs  = errors.New("allocate mem-bufs failed")
)

var afxdpErrors map[int]error

func init() {
	afxdpErrors = map[int]error{
		int(C.E_ALREADY_INITED):  ErrAlreadyInited,
		int(C.E_ALLOC_XSK_PTR):   ErrAllocXskPtr,
		int(C.E_ALLOC_UMEM_CFG):  ErrAllocUmemCfg,
		int(C.E_ALLOC_UMEM_PTR):  ErrAllocUmemPtr,
		int(C.E_CREATE_XSK):      ErrCreateXsk,
		int(C.E_GET_NIC_IDX):     ErrGetNicIdx,
		int(C.E_LINK_BPF_TO_XSK): ErrLinkBpfToXsk,
		int(C.E_RESERVE_FQ_BUF):  ErrReserveFQBuf,
		int(C.E_ALLOC_MEMPOOL):   ErrAllocMempool,
		int(C.E_ALLOC_INQUEUE):   ErrAllocInqueue,
		int(C.E_ALLOC_MEM_BUFS):  ErrAllocMemBufs,
	}
}
