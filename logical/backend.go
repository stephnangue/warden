package logical

import "net/http"

type Backend interface {
	HandleRequest(w http.ResponseWriter, r *http.Request) error
	GetType() string
	GetClass() string
	GetDescription() string
	GetAccessor() string
	Cleanup()
	Setup(conf map[string]any) error
	Config() map[string]any
}

type ContextKey string

const (
	OriginalPath ContextKey = "originalPath"
)
