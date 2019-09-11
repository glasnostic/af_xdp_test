package handler

import "errors"

var (
	ErrMaskOverflow      = errors.New("mask overflow")
	ErrNotValidIP        = errors.New("not valid IP")
	ErrNotValidIPv4      = errors.New("not valid IPv4")
	ErrNotAcceptableType = errors.New("not acceptable packet type")
	ErrNotValidPacket    = errors.New("not a valid packet")
	ErrV6NotSupport      = errors.New("ipv6 not support")
)
