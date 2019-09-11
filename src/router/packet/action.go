package packet

type Action uint8

const (
	Drop = iota
	Pass
	Rewrite
	New
)
