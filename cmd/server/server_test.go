package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/config"
)

func TestResolveDevSpiffeTLS(t *testing.T) {
	tests := []struct {
		name        string
		dev         bool
		spiffe      bool
		socket      string
		devTLS      bool
		certFile    string
		keyFile     string
		caFile      string
		wantEnabled bool
		wantErr     string
	}{
		{name: "not requested", dev: true},
		{name: "flag with -dev — enabled", dev: true, spiffe: true, wantEnabled: true},
		{name: "socket implies flag", dev: true, socket: "unix:///run/spire/agent.sock", wantEnabled: true},
		{name: "flag without -dev — error", spiffe: true, wantErr: "can only be used with -dev"},
		{name: "socket without -dev — error", socket: "unix:///x.sock", wantErr: "can only be used with -dev"},
		{name: "spiffe + dev-tls — error", dev: true, spiffe: true, devTLS: true, wantErr: "mutually exclusive"},
		{name: "spiffe + cert file — error", dev: true, spiffe: true, certFile: "/c.pem", wantErr: "mutually exclusive"},
		{name: "spiffe + ca file — error", dev: true, spiffe: true, caFile: "/ca.pem", wantErr: "mutually exclusive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDevSpiffeTLS(tt.dev, tt.spiffe, tt.socket, tt.devTLS, tt.certFile, tt.keyFile, tt.caFile)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.False(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantEnabled, got)
		})
	}
}

func TestBuildSpiffeSources_NoSpiffeListeners(t *testing.T) {
	conf := &config.Config{
		Listeners: []config.ListenerBlock{
			{Type: "tcp", Address: ":8400", TLSDisable: true},
			{Type: "tcp", Address: ":8410", TLSCertFile: "/c.pem", TLSKeyFile: "/k.pem"},
		},
	}
	sources, closeFn, err := buildSpiffeSources(context.Background(), conf)
	require.NoError(t, err)
	assert.Empty(t, sources)
	require.NotNil(t, closeFn)
	closeFn() // must be safe on an empty set
}

func TestBuildSpiffeSources_FailClosed(t *testing.T) {
	// A tls_spiffe listener pointing at an unreachable socket must fail closed
	// (rather than start without an identity), within the short startup budget.
	conf := &config.Config{
		Listeners: []config.ListenerBlock{
			{
				Type:                    "tcp",
				Address:                 ":8400",
				TLSSPIFFE:               true,
				TLSSPIFFESocket:         "unix:///nonexistent/warden-cmdtest.sock",
				TLSSPIFFEStartupTimeout: "300ms",
			},
		},
	}
	sources, closeFn, err := buildSpiffeSources(context.Background(), conf)
	require.Error(t, err)
	assert.Nil(t, sources)
	assert.Nil(t, closeFn)
	assert.Contains(t, err.Error(), "SPIFFE serving identity")
}
