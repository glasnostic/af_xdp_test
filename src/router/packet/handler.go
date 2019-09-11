package packet

type Handler interface {
	Handle(*Metadata) (Action, error)
}
