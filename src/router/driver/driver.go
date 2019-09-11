package driver

import (
	"github.com/glasnostic/example/router/driver/libbpf"
	"github.com/glasnostic/example/router/packet"
)

type Runner interface {
	Run(packetHandler packet.Handler)
}

func New(driverName, nicName string) (Runner, error) {
	switch driverName {
	default:
		return libbpf.New(nicName)
	}
}
