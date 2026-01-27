package physical

import (
	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/physical"
)

// Factory is the factory function to create a storage.
type Factory func(config map[string]string, logger log.Logger) (physical.Backend, error)
