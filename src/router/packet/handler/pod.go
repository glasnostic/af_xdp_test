package handler

import "net"

type pod struct {
	ip    net.IP
	mac   net.HardwareAddr
	value uint32
}

func newPod(ip net.IP, mac net.HardwareAddr) *pod {
	return &pod{
		ip:    ip,
		mac:   mac,
		value: IPToUint32(ip),
	}
}
