package server

import (
	"context"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/config"
	wardenlogical "github.com/stephnangue/warden/logical"
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

func TestResolveDevListenAddress(t *testing.T) {
	tests := []struct {
		name     string
		dev      bool
		flagAddr string
		envAddr  string
		want     string
		wantErr  string
	}{
		{name: "neither set keeps the default", dev: true},
		{name: "flag", dev: true, flagAddr: "0.0.0.0:8400", want: "0.0.0.0:8400"},
		{name: "env", dev: true, envAddr: "0.0.0.0:8400", want: "0.0.0.0:8400"},
		{name: "flag overrides env", dev: true, flagAddr: "127.0.0.1:9400", envAddr: "0.0.0.0:8400", want: "127.0.0.1:9400"},
		{name: "empty host binds all interfaces", dev: true, flagAddr: ":8400", want: ":8400"},
		{name: "ipv6", dev: true, flagAddr: "[::]:8400", want: "[::]:8400"},
		{name: "env ignored outside dev", envAddr: "0.0.0.0:8400"},
		{name: "invalid env ignored outside dev", envAddr: "nonsense"},
		{name: "flag without -dev — error", flagAddr: "0.0.0.0:8400", wantErr: "can only be used with -dev"},
		{name: "missing port — error", dev: true, flagAddr: "0.0.0.0", wantErr: "invalid -dev-listen-address"},
		{name: "non-numeric port — error", dev: true, flagAddr: "0.0.0.0:http", wantErr: "port must be a number"},
		{name: "port out of range — error", dev: true, flagAddr: "0.0.0.0:70000", wantErr: "port must be a number"},
		{name: "port zero — error", dev: true, flagAddr: "0.0.0.0:0", wantErr: "port must be a number"},
		{name: "invalid env names the env var", dev: true, envAddr: "0.0.0.0", wantErr: "invalid " + envDevListenAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDevListenAddress(tt.dev, tt.flagAddr, tt.envAddr)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
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

// Every shipped provider skill must be named after its provider type under
// the Agent Skills naming rule, or SeedProviderSkill rejects it on mount.
func TestProviderSkills_NamedForProviderType(t *testing.T) {
	nameLine := regexp.MustCompile(`(?m)^name:\s*(\S+)\s*$`)
	for typ, md := range providerSkills {
		m := nameLine.FindStringSubmatch(md)
		if m == nil {
			t.Errorf("%s: skill.md has no name field", typ)
			continue
		}
		if want := wardenlogical.SkillNameForProvider(typ); m[1] != want {
			t.Errorf("%s: skill.md name = %q, want %q", typ, m[1], want)
		}
		if !wardenlogical.ValidSkillName(m[1]) {
			t.Errorf("%s: skill.md name %q is not a valid skill name", typ, m[1])
		}
	}
}
