package libbpf

import (
	"log"
	"sync"

	"github.com/glasnostic/example/router/packet"
)

type libbpf struct {
	runner libbpfAfxdpRunner

	stop chan struct{}

	*sync.WaitGroup
}

func New(nicName string) (*libbpf, error) {
	runner, err := newRunner(nicName)
	if err != nil {
		return nil, err
	}
	res := &libbpf{
		runner:    runner,
		stop:      make(chan struct{}),
		WaitGroup: &sync.WaitGroup{},
	}

	return res, nil
}

func (l *libbpf) Run(packetHandler packet.Handler) {
	log.Println("Libbpf Run called")
	l.Add(1)
	defer l.Done()

	var pktMeta packet.Metadata

	for {
		select {
		case <-l.stop:
			return
		case pkt := <-l.runner.Read():
			pktMeta.Reset()
			pktMeta.Packet = pkt
			action, err := packetHandler.Handle(&pktMeta)
			if err != nil {
				log.Println("Libbpf based AF_XDP drops packet due to error:", err)
				l.runner.Drop()
				continue
			}
			l.handle(action, pktMeta.Packet)
		}
	}
}

func (l *libbpf) Suspend() {
	l.stop <- struct{}{} // send close signal
	l.Wait()             // wait current Run finished
}

func (l *libbpf) Close() {
	log.Println("Stopping libbpf based AF_XDP NetworkDriver")
	defer log.Println("Stopped libbpf based AF_XDP NetworkDriver")

	close(l.stop)    // close stop channel
	l.runner.Close() // close runner
	l.Wait()         // wait current Run finished
}

func (l *libbpf) handle(action packet.Action, pkt Packet) {
	switch action {
	case packet.Drop:
		// drop this packet
		l.runner.Drop()
	case packet.Pass, packet.Rewrite:
		// pass this packet to TX
		l.runner.Pass(pkt)
	case packet.New:
		// send this new created packet to TX
		l.runner.New(pkt)
	default:
		// drop this packet
		log.Println("Libbpf based AF_XDP drops packet due to un-expected action returned!")
		l.runner.Drop()
	}
}
