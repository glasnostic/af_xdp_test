package handler

import (
	"encoding/binary"
	"net"

	"github.com/glasnostic/example/router/packet"
)

var (
	BroadcastHardwareAddr = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func (r *rewriter) handleARP(meta *packet.Metadata) (packet.Action, error) {
	if len(meta.Packet) < 14+28 {
		return packet.Drop, ErrNotValidPacket
	}
	if isARPRequest(meta) {
		return r.handleARPRequest(meta)
	}
	return r.handleARPReply(meta)
}

func (r *rewriter) handleARPReply(meta *packet.Metadata) (packet.Action, error) {
	// store srcIP:srcMac into local store
	r.saveIP4Mac(meta)
	return packet.Drop, nil
}

func (r *rewriter) handleARPRequest(meta *packet.Metadata) (packet.Action, error) {
	// store srcIP:srcMac into local store
	r.saveIP4Mac(meta)
	// get source/destination IP
	srcIP, dstIP := getSrcDstIPFromARPPacket(meta)
	// if destination IP equal to localIP
	if r.local.value == dstIP {
		return r.sendARPReply(meta, srcIP)
	}
	// send arp reply
	return packet.Drop, nil
}

func (r *rewriter) saveIP4Mac(meta *packet.Metadata) {
	arpPacket := meta.Packet[14:]
	ip := IPToUint32(arpPacket[14:18])
	mac := make(net.HardwareAddr, 6)
	copy(mac, arpPacket[8:14])
	r.table[ip] = mac
}

func (r *rewriter) sendARPRequest(meta *packet.Metadata, ip uint32) (packet.Action, error) {
	var arpRequest uint16 = 1
	meta.Packet = r.buildARP(ip, arpRequest, BroadcastHardwareAddr)
	return packet.New, nil
}

func (r *rewriter) sendARPReply(meta *packet.Metadata, dstIP uint32) (packet.Action, error) {
	var arpReply uint16 = 2
	meta.Packet = r.buildARP(dstIP, arpReply, r.table[dstIP])
	return packet.New, nil
}

func (r *rewriter) buildARP(dstIP uint32, arpType uint16, remoteMAC net.HardwareAddr) []byte {
	var arpFrame [14 + 28]byte
	// Ethernet header
	copy(arpFrame[0:6], remoteMAC)                      // Destination
	copy(arpFrame[6:12], r.local.mac)                   // Source
	binary.BigEndian.PutUint16(arpFrame[12:14], 0x0806) // Type: ARP

	// ARP packet Payload
	arpPacket := arpFrame[14:]                               // ARP Request
	binary.BigEndian.PutUint16(arpPacket[0:2], 1)            // Hardware type: Ethernet is 1
	binary.BigEndian.PutUint16(arpPacket[2:4], 0x800)        // Protocol type: IPv4 is 0x800
	arpPacket[4] = uint8(6)                                  // HWAddr length: Ethernet addresses size is 6
	arpPacket[5] = uint8(4)                                  // IPAddr length: IPv4 addresses size is 4
	binary.BigEndian.PutUint16(arpPacket[6:8], arpType)      // Request is 1, Reply is 2
	copy(arpPacket[8:14], r.local.mac)                       // sender mac address
	copy(arpPacket[14:18], IPv6ToIPv4Len(r.local.ip))        // sender ip address
	copy(arpPacket[18:24], remoteMAC)                        // target mac address
	copy(arpPacket[24:28], IPv6ToIPv4Len(Uint32ToIP(dstIP))) // target ip address

	return arpFrame[:]
}
