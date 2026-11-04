package server

import (
	"context"
	"io"
	"testing"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logger"
	wardenlogical "github.com/stephnangue/warden/logical"
)

// streamSamples are concrete paths for each streaming-path shape a provider
// declares. "role/*" is the router's prefix for role/<name>/gateway[/...]: the
// backend matches the full pattern itself.
var streamSamples = map[string][]string{
	"gateway":   {"gateway"},
	"gateway/*": {"gateway/x", "gateway/x/y"},
	"role/*":    {"role/r/gateway", "role/r/gateway/x"},
}

// Every registered provider names its own data plane: it is a
// TransparentModeProvider, so core can ask IsTransparentPath, and every
// streaming path it declares is one IsTransparentPath reports. Core's
// request.data_plane, and the refusal of built-in operator roles there, rest
// on this; a provider that broke it would leave a gateway open to them.
func TestProviders_DeclareTheirDataPlane(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{
		Underlying:   io.Discard,
		InitialState: logger.GateOpen,
	})

	for typ, factory := range providers {
		t.Run(typ, func(t *testing.T) {
			b, err := factory(context.Background(), &wardenlogical.BackendConfig{
				StorageView: &sdklogical.InmemStorage{},
				Logger:      log,
			})
			require.NoError(t, err)
			tmp, ok := b.(wardenlogical.TransparentModeProvider)
			require.True(t, ok, "%s is not a TransparentModeProvider: core cannot tell its data plane", typ)

			paths := b.SpecialPaths()
			if paths == nil {
				return // streams nothing: an access backend's data plane is IsTransparentPath alone
			}
			for _, p := range paths.Stream {
				samples, known := streamSamples[p]
				require.True(t, known, "%s streams %q, a shape this test has no sample for: add one", typ, p)
				for _, sample := range samples {
					assert.True(t, tmp.IsTransparentPath(sample), "%s streams %q but %q is off its declared data plane", typ, p, sample)
				}
			}
		})
	}
}
