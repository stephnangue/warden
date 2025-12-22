package physical

import (
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/stephnangue/warden/logger"
)

// Factory is the factory function to create a storage.
type Factory func(config map[string]string, log *logger.GatedLogger) (physical.Backend, error)