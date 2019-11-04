package libbpf

// FIXME: get libbpf path from env
//go:generate cp /tmp/libbpf/src/libbpf.h /go/router/driver/libbpf/
//go:generate cp /tmp/libbpf/src/libbpf_util.h /go/router/driver/libbpf
//go:generate cp /tmp/libbpf/src/xsk.h /go/router/driver/libbpf

/*
#cgo CFLAGS: -O3 -I/usr/include/uapi/
#cgo LDFLAGS: -lelf /tmp/libbpf/src/xsk.o /tmp/libbpf/src/libbpf.o /tmp/libbpf/src/libbpf.a

#include <stdlib.h> // for C.free

#include "runner.h" //
#include "xdp.h"    //
#include "errors.h" //
*/
import "C"

import (
	"log"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	DefaultCombinedQueueID = 0
	BatchFrames            = 1 << 4 // the maximum number of frame we tell AF_XDP we want fetch per poll
)

const (
	stop uint64 = iota
	process
)

var (
	CombinedQueueID int
)

func init() {
	CombinedQueueID = DefaultCombinedQueueID
	if s := os.Getenv("QUEUE_ID"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			CombinedQueueID = int(v)
		}
	}
}

type libbpfRunnerLinux struct {
	libbpf    *C.struct_libbpf
	flag      uint64
	incomming chan Packet // channel for incomming packets
	next      chan bool   // single signal control of incomming packets

	*sync.WaitGroup
}

func newRunner(ifName string) (*libbpfRunnerLinux, error) {
	res := &libbpfRunnerLinux{
		incomming: make(chan Packet),
		next:      make(chan bool),
		WaitGroup: &sync.WaitGroup{},
	}
	if err := res.init(ifName); err != nil {
		log.Println(C.GoString(C.report_errno()))
		return nil, err
	}
	return res, nil
}

func (l *libbpfRunnerLinux) Read() <-chan Packet {
	return l.incomming
}

func (l *libbpfRunnerLinux) Pass(pkt Packet) {
	// write the packet
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&pkt))
	C.libbpf_xsk__pkt_pass(l.libbpf, (*C.uchar)(unsafe.Pointer(slice.Data)), C.size_t(len(pkt)))
	l.complete()
}

func (l *libbpfRunnerLinux) New(pkt Packet) {
	// write new data to current buffer
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&pkt))
	C.libbpf_xsk__pkt_write(l.libbpf, (*C.uchar)(unsafe.Pointer(slice.Data)), C.size_t(len(pkt)))
	l.complete()
}

func (l *libbpfRunnerLinux) Drop() {
	// we have to record the current packet been dropped correctly
	C.libbpf_xsk__pkt_drop(l.libbpf)
	l.complete()
}

func (l *libbpfRunnerLinux) Close() {
	close(l.next)
	atomic.StoreUint64(&l.flag, stop)
	l.Wait()
	C.libbpf_xsk__exit(l.libbpf)
}

func (l *libbpfRunnerLinux) init(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))

	l.libbpf = C.libbpf_xsk__init(cIfName, C.int(CombinedQueueID))
	if l.libbpf == nil {
		return ErrInvalidLibbpf
	}
	if l.libbpf.err != 0 {
		return afxdpErrors[int(l.libbpf.err)]
	}
	l.flag = process
	// worker keep fetching packet from XSK
	l.Add(1)
	go l.worker()

	return nil
}

func (l *libbpfRunnerLinux) worker() {
	// mark this worker should take one OS thread for reducing
	// 1. don't migrate to other OS thread
	// 2. take one OS thread resource
	runtime.LockOSThread()

	defer l.Done()
	log.Println("Libbpf runner worker starting")
	defer log.Println("Libbpf runner worker returned")
	for atomic.LoadUint64(&l.flag) == process {
		total := int(C.libbpf_xsk__poll(l.libbpf, C.size_t(BatchFrames)))
		// most likely BatchFrames(C.FRAME_BATCH_SIZE) packets in FQ waiting for proceed
		log.Printf("libbpf fetch %d packets\n", total)
		for i := 0; i < total; i++ {
			l.fetchOnePacketFromXSK()
			if _, ok := <-l.next; !ok {
				// next channel has been closed by Close, stop fetching packets from AF_XDP
				return
			}
		}
	}
}

func (l *libbpfRunnerLinux) fetchOnePacketFromXSK() {
	var bufptr *C.u_char
	bptr := C.uintptr_t(uintptr(unsafe.Pointer(&bufptr)))
	pktLen := int(C.libbpf_xsk__pkt_read(l.libbpf, bptr))
	var data []byte

	// If we got invalid-length packet, we just pass a nil slice out
	// packet handler should recognize this packet as invaid packet
	// and drop it.
	if pktLen > 0 {
		slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
		slice.Data = uintptr(unsafe.Pointer(bufptr))
		slice.Len = pktLen
		slice.Cap = pktLen
	}

	l.incomming <- data
}

func (l *libbpfRunnerLinux) complete() {
	l.next <- true
}
