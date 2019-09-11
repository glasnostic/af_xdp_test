// +build !linux

package libbpf

import "errors"

var (
	ErrNetworkDriverNotAvailable = errors.New("Not available")
)

func newRunner(ifName string) (libbpfAfxdpRunner, error) {
	return nil, ErrNetworkDriverNotAvailable
}
