package handler

import (
	"encoding/binary"

	"github.com/glasnostic/example/router/packet"

	"github.com/google/gopacket/layers"
)

func FastInternetChecksumUint16(data []byte, len int) uint16 {
	nleft := len

	// byte => uint8
	sum := uint32(0) // 4 * uint8

	idx := 0 // idx

	for ; nleft > 3; nleft -= 4 {
		sum += uint32(data[idx]) << 8
		sum += uint32(data[idx+1])
		sum += uint32(data[idx+2]) << 8
		sum += uint32(data[idx+3])
		idx += 4
	}

	switch nleft {
	case 3:
		sum += uint32(data[idx]) << 8
		sum += uint32(data[idx+1])
		sum += uint32(data[idx+2]) << 8
	case 2:
		sum += uint32(data[idx]) << 8
		sum += uint32(data[idx+1])
	case 1:
		sum += uint32(data[idx]) << 8
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff) /* add hi 16 to low 16 */
	}

	return uint16(^sum)
}

func GetTransportPacketIPv4(ipPacket []byte) []byte {
	headerLength := (uint8(ipPacket[0]) & 0x0F) * 4
	totalLength := binary.BigEndian.Uint16(ipPacket[2:4])
	transportPacket := ipPacket[headerLength:totalLength]
	return transportPacket
}

func GetTransportPacketIPv6(ipPacket []byte) []byte {
	payloadLength := binary.BigEndian.Uint16(ipPacket[4:6])
	transportPacket := ipPacket[40 : 40+payloadLength]
	return transportPacket
}

func CalculateTransportChecksum(ipPacket []byte, ipVersion layers.EthernetType, protocol layers.IPProtocol) {
	var pseudoHeader []byte
	var headerAndPayload []byte
	var start, end int

	switch ipVersion {
	case layers.EthernetTypeIPv4:
		pseudoHeader = make([]byte, 12)
		copy(pseudoHeader[0:8], ipPacket[12:20]) // IP src/dst
		pseudoHeader[8] = 0                      // zero
		pseudoHeader[9] = ipPacket[9]            // PTCL
		headerAndPayload = GetTransportPacketIPv4(ipPacket)
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(headerAndPayload)))

	case layers.EthernetTypeIPv6:
		pseudoHeader = make([]byte, 40)
		copy(pseudoHeader[0:32], ipPacket[8:40]) // IP src/dst
		headerAndPayload = GetTransportPacketIPv6(ipPacket)
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(headerAndPayload)))
		pseudoHeader[39] = ipPacket[6] // PTCL
	}

	switch protocol {
	case layers.IPProtocolTCP:
		start, end = 16, 18
	case layers.IPProtocolUDP:
		start, end = 6, 8
	}

	binary.BigEndian.PutUint16(headerAndPayload[start:end], 0) // reset to zero
	data := append(append([]byte{}, pseudoHeader...), headerAndPayload...)
	csum := FastInternetChecksumUint16(data, len(data))
	binary.BigEndian.PutUint16(headerAndPayload[start:end], csum) // update checksum
}

func CleanIPChecksum(ipPacket []byte) {
	ipPacket[10] = uint8(0)
	ipPacket[11] = uint8(0)
}

// resets IPv4 Header checksum field to zeros and re-calculate checksum
func CalculateIPChecksum(ipPacket []byte) {
	CleanIPChecksum(ipPacket)
	iphl := int(ipPacket[0]&0x0f) << 2
	checksum := FastInternetChecksumUint16(ipPacket[0:iphl], iphl)
	binary.BigEndian.PutUint16(ipPacket[10:12], checksum)
}

func checksum(meta *packet.Metadata) (packet.Action, error) {
	ipPacket := meta.Packet[14:]
	switch ipProtocol := layers.IPProtocol(binary.BigEndian.Uint16(ipPacket[10:12])); ipProtocol {
	case layers.IPProtocolTCP, layers.IPProtocolUDP:
		// only calculate the transport checksum for IPv4/{TCP,UDP} packets
		CalculateTransportChecksum(ipPacket, layers.EthernetTypeIPv4, ipProtocol)
	}
	CalculateIPChecksum(ipPacket)
	return packet.Rewrite, nil
}
