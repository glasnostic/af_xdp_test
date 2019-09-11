package packet

type Metadata struct {
	Packet []byte
}

func (m *Metadata) Reset() {
	m.Packet = nil
}
