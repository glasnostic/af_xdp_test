package libbpf

type Packet []byte

type libbpfAfxdpRunner interface {
	Read() <-chan Packet

	Pass(data Packet)
	New(data Packet)
	Drop()

	Close()
}
