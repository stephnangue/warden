package logical

import "net/http"

type Backend interface {
	HandleRequest(w http.ResponseWriter, r *http.Request) error
	GetType() string
	GetClass() string
	GetDescription() string
	GetAccessor() string
	Cleanup()
}


type ContextKey string

const (
    OriginalPath ContextKey = "originalPath"
)
