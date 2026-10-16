package configutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/config"
)

func TestConfigureWrapper_PKCS11Unsupported(t *testing.T) {
	wrapper, err := ConfigureWrapper(&config.KMS{Type: "pkcs11"}, nil, nil, nil)
	require.Error(t, err)
	assert.Nil(t, wrapper)
	assert.Contains(t, err.Error(), `seal type "pkcs11" is not supported`)
	assert.Contains(t, err.Error(), `seal "transit"`)
}

func TestConfigureWrapper_UnknownType(t *testing.T) {
	_, err := ConfigureWrapper(&config.KMS{Type: "bogus"}, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown KMS type "bogus"`)
}
