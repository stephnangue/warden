package listener

import "context"

type Listener interface {
	Addr() string
	Start(ctx context.Context) error
	Stop() error
	Type() string
}
