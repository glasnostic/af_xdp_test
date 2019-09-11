package handler

import (
	"log"
	"net"

	"github.com/glasnostic/example/router/packet"

	"github.com/google/gopacket/layers"
)

// rewriter
type rewriter struct {
	mac net.HardwareAddr

	local  *pod
	client *pod
	server *pod

	table map[uint32]net.HardwareAddr
}

// NewRewriter create New Rewriter Handler
func NewRewriter(localMac net.HardwareAddr, localIP net.IP, client, server net.IP) packet.Handler {
	return &rewriter{
		mac:    localMac,
		local:  newPod(localIP),
		client: newPod(client),
		server: newPod(server),
		table:  make(map[uint32]net.HardwareAddr),
	}
}

func (r *rewriter) Handle(meta *packet.Metadata) (packet.Action, error) {
	switch typ := typeOfPacket(meta); typ {
	case layers.EthernetTypeARP:
		return r.handleARP(meta)
	case layers.EthernetTypeIPv4:
		return r.handleIP(meta)
	case layers.EthernetTypeIPv6:
		return r.handleIPv6(meta)
	default:
		log.Printf("unknown type %s\n", typ)
	}
	return packet.Drop, ErrNotAcceptableType
}

func (r *rewriter) handleIPv6(meta *packet.Metadata) (packet.Action, error) {
	return packet.Drop, ErrV6NotSupport
}

func (r *rewriter) handleIP(meta *packet.Metadata) (packet.Action, error) {
	realSrc := getSrcIPFromIPPacket(meta)
	// 1. change destination IP (local -> picked)
	realDst := r.selectTarget(realSrc)
	// 2. check we have the MAC address of destination IP
	dstMAC, ok := r.table[realDst]
	if !ok {
		// 2-1. if no, send ARP request
		return r.sendARPRequest(meta, realDst)
	}
	// 2-2. if yes, set realDst with dstMAC to packet
	setDst(meta, realDst, dstMAC)
	// 3. change source IP to local (real -> local)
	setSrc(meta, r.local.value, r.mac)
	// 4. calculate the checksum
	return checksum(meta)
}

// For simplifying setup, just pick destination from the source
func (r *rewriter) selectTarget(ip uint32) uint32 {
	switch ip {
	case r.client.value:
		return r.server.value
	default:
		return r.client.value
	}
}
