package handler

import "net"

type pod struct {
	ip    net.IP
	value uint32
}

func newPod(ip net.IP) *pod {
	return &pod{
		ip:    ip,
		value: IPToUint32(ip),
	}
}
