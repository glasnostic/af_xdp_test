package handler

import (
	"encoding/binary"
	"net"

	"github.com/glasnostic/example/router/packet"
	"github.com/google/gopacket/layers"
)

func IPv6ToIPv4Len(ip net.IP) []byte {
	if len(ip) == net.IPv6len {
		return ip[net.IPv6len-net.IPv4len:]
	}
	return ip
}

func typeOfPacket(meta *packet.Metadata) layers.EthernetType {
	return layers.EthernetType(binary.BigEndian.Uint16(meta.Packet[12:14]))
}

func isARPRequest(meta *packet.Metadata) bool {
	arpPacket := meta.Packet[14 : 14+28]
	op := binary.BigEndian.Uint16(arpPacket[6:8]) // Request is 1, Reply is 2
	return op == uint16(1)
}

func getSrcDstIPFromARPPacket(meta *packet.Metadata) (uint32, uint32) {
	arpPacket := meta.Packet[14 : 14+28]
	srcIP := binary.BigEndian.Uint32(arpPacket[14:18])
	dstIP := binary.BigEndian.Uint32(arpPacket[24:28])
	return srcIP, dstIP
}

func getSrcIPFromIPPacket(meta *packet.Metadata) uint32 {
	ipPacket := meta.Packet[14:]
	srcIP := binary.BigEndian.Uint32(ipPacket[12:16])
	return srcIP
}

func setDst(meta *packet.Metadata, ip uint32, mac net.HardwareAddr) {
	etherHeader := meta.Packet[:14]
	copy(etherHeader[0:6], mac)
	ipPacket := meta.Packet[14:]
	copy(ipPacket[16:20], IPv6ToIPv4Len(Uint32ToIP(ip)))
}

func setSrc(meta *packet.Metadata, ip uint32, mac net.HardwareAddr) {
	etherHeader := meta.Packet[:14]
	copy(etherHeader[6:12], mac)
	ipPacket := meta.Packet[14:]
	copy(ipPacket[12:16], IPv6ToIPv4Len(Uint32ToIP(ip)))
}
