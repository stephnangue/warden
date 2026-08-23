package dualgateway

import (
	"fmt"
	"net/http"

	"github.com/stephnangue/warden/framework"
)

// extraConfigKeys returns the provider-specific config keys this spec declares.
// A spec may describe them as full field schemas or as bare names; both forms
// must reach the same set, or a key lands in the config schema while the write
// path and the allow-list never learn of it.
func specExtraConfigKeys(spec *ProviderSpec) []string {
	if len(spec.ExtraConfigFields) > 0 {
		keys := make([]string, 0, len(spec.ExtraConfigFields))
		for k := range spec.ExtraConfigFields {
			keys = append(keys, k)
		}
		return keys
	}
	return spec.ExtraConfigKeys
}

func (b *dualgatewayBackend) extraConfigKeys() []string {
	return specExtraConfigKeys(b.spec)
}

// applyParsedConfig resolves conf into live backend state and returns the
// snapshot to persist. It is the only place configuration is applied — mount
// time, storage load and config write all route through it, so the three can
// never drift into honouring different subsets of the config surface.
//
// Nothing is mutated until every fallible step has succeeded: an unusable
// ca_data leaves a serving mount exactly as it was, rather than half-moved to a
// configuration that cannot reach its upstream.
//
// The returned snapshot is computed from conf alone rather than read back off
// the backend, so a writer racing in between resolution and Put cannot tear it.
//
// conf must already have passed validateConfig. This applies; it does not
// validate.
func (b *dualgatewayBackend) applyParsedConfig(conf map[string]any) (map[string]any, error) {
	parsed := parseConfig(b.spec, conf)

	// Build the transport first — the one step here that can fail.
	var (
		newTransport http.RoundTripper = sharedTransport
		perMount     *http.Transport
	)
	if parsed.TLSSkipVerify || parsed.CAData != "" {
		t, err := newTransportWithTLS(parsed.CAData, parsed.TLSSkipVerify)
		if err != nil {
			return nil, fmt.Errorf("invalid TLS configuration: %w", err)
		}
		newTransport = t
		perMount = t
	}

	autoAuthPath := framework.GetConfigString(conf, "auto_auth_path", "")
	defaultRole := framework.GetConfigString(conf, "default_role", "")
	userAuthPath := framework.GetConfigString(conf, "user_auth_path", "")
	userAuthRole := framework.GetConfigString(conf, "user_auth_role", "")

	extraKeys := b.extraConfigKeys()
	extraRaw := make(map[string]any, len(extraKeys))
	for _, k := range extraKeys {
		if v, ok := conf[k]; ok {
			extraRaw[k] = v
		}
	}

	var extraState map[string]any
	if b.spec.OnConfigParsed != nil {
		extraState = b.spec.OnConfigParsed(conf)
	}

	persist := map[string]any{
		b.spec.URLConfigKey: parsed.ProviderURL,
		"max_body_size":     parsed.MaxBodySize,
		"timeout":           parsed.Timeout.String(),
		"auto_auth_path":    autoAuthPath,
		"default_role":      defaultRole,
		"user_auth_path":    userAuthPath,
		"user_auth_role":    userAuthRole,
		"tls_skip_verify":   parsed.TLSSkipVerify,
		"ca_data":           parsed.CAData,
	}
	// Persist what the operator supplied for the extra keys, not what
	// OnConfigParsed resolved it to. A resolved value is a defaulting decision
	// made now; storing it would freeze today's default into the mount and
	// silently exempt it from a later one.
	for k, v := range extraRaw {
		persist[k] = v
	}

	b.mu.Lock()
	outgoing := b.installedTransport
	b.providerURL = parsed.ProviderURL
	b.tlsSkipVerify = parsed.TLSSkipVerify
	b.caData = parsed.CAData
	b.extraRaw = extraRaw
	b.extraState = extraState
	b.installedTransport = perMount
	b.mu.Unlock()

	// Framework-side fields carry their own atomics; no lock needed.
	b.SetMaxBodySize(parsed.MaxBodySize)
	b.SetTimeout(parsed.Timeout)
	b.SetTransport(newTransport)
	b.StreamingBackend.SetTransparentConfig(&framework.TransparentConfig{
		AutoAuthPath:    autoAuthPath,
		DefaultAuthRole: defaultRole,
		UserAuthPath:    userAuthPath,
		UserAuthRole:    userAuthRole,
	})

	// Release the connections of the transport just replaced. Only a per-mount
	// one is ours to close — sharedTransport serves every other mount of every
	// dual-mode provider. In-flight requests keep the connections they hold;
	// this reaches only idle ones.
	if outgoing != nil && outgoing != perMount {
		outgoing.CloseIdleConnections()
	}

	return persist, nil
}

// snapshotForMerge returns live configuration in the shape parseConfig expects,
// to serve as the base a partial config write is overlaid onto. Without it, a
// write naming one key would resolve every key it did not name to a default.
//
// Every key here must be one validateConfig allows, since the merged result is
// validated as a whole. Extra keys come from extraRaw — the operator's own
// values — for the reason applyParsedConfig persists those rather than the
// resolved ones.
func (b *dualgatewayBackend) snapshotForMerge() map[string]any {
	tc := b.TransparentConfig()

	b.mu.RLock()
	defer b.mu.RUnlock()

	conf := map[string]any{
		b.spec.URLConfigKey: b.providerURL,
		"max_body_size":     b.MaxBodySize(),
		"timeout":           b.Timeout().String(),
		"auto_auth_path":    tc.AutoAuthPath,
		"default_role":      tc.DefaultAuthRole,
		"user_auth_path":    tc.UserAuthPath,
		"user_auth_role":    tc.UserAuthRole,
		"tls_skip_verify":   b.tlsSkipVerify,
		"ca_data":           b.caData,
	}
	for k, v := range b.extraRaw {
		conf[k] = v
	}
	return conf
}
