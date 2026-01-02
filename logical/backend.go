package logical

import (
	"context"
	"net/http"
)

type Backend interface {
	HandleRequest(w http.ResponseWriter, r *http.Request) error
	GetType() string
	GetClass() string
	GetDescription() string
	GetAccessor() string
	Cleanup(context.Context)
	Setup(context.Context, map[string]any) error
	Initialize(context.Context) error
	Config() map[string]any
}

type ContextKey string

const (
	OriginalPath ContextKey = "originalPath"
)
