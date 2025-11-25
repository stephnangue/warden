package core

import (
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// SystemBackend implements logical.Backend and is used to interact with
// the core of the system. This backend is hardcoded to exist at the "sys"
// prefix. Conceptually it is similar to procfs on Linux.
type SystemBackend struct {
	Core   *Core
	logger logger.Logger
	logical.Backend
}