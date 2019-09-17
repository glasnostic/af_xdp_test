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
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"
)

const (
	DefaultCombinedQueueID = 0
	BatchFrames            = 1 << 4 // the maximum number of frame we tell AF_XDP we want fetch per poll
	// BatchFrames            = 1 << 10 // the maximum number of frame we tell AF_XDP we want fetch per poll
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
	flag      uint64
	incomming chan Packet // channel for incomming packets
	next      chan bool   // single signal control of incomming packets

	*sync.WaitGroup

	dropped  int
	passed   int
	injected int
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
	res := int(C.pass_rx_packet_to_tx(C.uint(len(pkt))))
	l.passed += res
	l.complete()
}

func (l *libbpfRunnerLinux) New(pkt Packet) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&pkt))
	C.new_packet_with_libbpf((*C.uchar)(unsafe.Pointer(slice.Data)), C.size_t(len(pkt)))
	l.injected++
	l.complete()
}

func (l *libbpfRunnerLinux) Drop() {
	C.drop_rx_packet_to_fq()
	l.dropped++
	l.complete()
}

func (l *libbpfRunnerLinux) Close() {
	close(l.next)
	atomic.StoreUint64(&l.flag, stop)
	l.Wait()
	C.exit_afxdp_with_libbpf()
}

func (l *libbpfRunnerLinux) init(ifName string) error {
	cIfName := C.CString(ifName)
	defer C.free(unsafe.Pointer(cIfName))

	if ret := int(C.init_afxdp_with_libbpf(cIfName, C.int(CombinedQueueID))); ret != 0 {
		return initErrors[ret]
	}
	l.flag = process
	// worker keep fetching packet from XSK
	l.Add(1)
	go l.worker()

	return nil
}

func (l *libbpfRunnerLinux) worker() {
	defer l.Done()
	log.Println("Libbpf runner worker starting")
	defer log.Println("Libbpf runner worker returned")
	for atomic.LoadUint64(&l.flag) == process {
		if int(C.poll_libbpf()) <= 0 {
			continue
		}
		total := int(C.poll_packets_with_libbpf(C.size_t(BatchFrames)))
		log.Printf("[guesslin] libbpf fetch %d packets\n", total)
		if total > 0 {
			// most likely BatchFrames(16) packets in FQ waiting for proceed
			for i := 0; i < total; i++ {
				l.fetchOnePacketFromXSK()
				if _, ok := <-l.next; !ok {
					// next channel has been closed by Close, stop fetching packets from AF_XDP
					return
				}
				C.rx_fwd()
			}
			l.flush(total)
		}
	}
}

func (l *libbpfRunnerLinux) fetchOnePacketFromXSK() {
	var bufptr *C.u_char
	bptr := C.uintptr_t(uintptr(unsafe.Pointer(&bufptr)))
	pktLen := int(C.read_packet_from_fq_torx_with_libbpf(bptr))

	// Since we can't make sure there's no race condition between worker goroutine
	// and a simple `go l.Drop()`, so we don't check the packet length here, and
	// let packet-handler to drop this invalid packets. This way we can make sure
	// the dropped packet is in the same lifecycle and race condition protection.

	var data []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = uintptr(unsafe.Pointer(bufptr))
	slice.Len = pktLen
	slice.Cap = pktLen
	l.incomming <- data
}

//
func (l *libbpfRunnerLinux) flush(total int) {
	handled := l.passed + l.injected + l.dropped
	if total != handled {
	}

	C.flush_tx(C.int(l.passed + l.injected)) // flush_tx will trigger sendto to send packets in tx
	C.flush_cq(C.int(l.passed + l.injected))

	C.flush_rx(C.int(total)) // release buffers in rx
	C.flush_fq(C.int(total)) // recycle buffers in fq

	l.resetCounters()
}

func (l *libbpfRunnerLinux) complete() {
	l.next <- true
}

func (l *libbpfRunnerLinux) resetCounters() {
	l.passed = 0
	l.injected = 0
	l.dropped = 0
}
