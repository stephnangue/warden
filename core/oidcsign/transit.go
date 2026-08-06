package oidcsign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/stephnangue/warden/logger"
)

// backendTypeTransit is the persisted discriminator for the transit backend.
const backendTypeTransit = "transit"

// TransitConfig configures a transit-backed remote signer. It mirrors the fields
// of the `signer "transit"` HCL stanza.
type TransitConfig struct {
	Address        string
	Token          string // optional; falls back to VAULT_TOKEN via api.NewClient
	MountPath      string // transit mount, e.g. "transit"
	KeyNamePrefix  string // e.g. "warden-oidc" -> keys warden-oidc-rs256, warden-oidc-es256
	Namespace      string
	RequestTimeout time.Duration
	DisableRenewal bool

	TLSCACert     string
	TLSCAPath     string
	TLSClientCert string
	TLSClientKey  string
	TLSServerName string
	TLSSkipVerify bool
}

// TransitBackend signs OIDC assertions via an OpenBao/Vault transit engine, where
// the private key is created non-exportable and never leaves the KMS.
type TransitBackend struct {
	client        *api.Client
	mountPath     string
	keyNamePrefix string
	timeout       time.Duration
	watcher       *api.LifetimeWatcher
	log           *logger.GatedLogger
}

var _ Backend = (*TransitBackend)(nil)

// NewTransitBackend builds a transit-backed signer client. A construction failure
// (bad TLS material, malformed address) is a config error and is returned here;
// transit being unreachable is not detected until a key operation. log may be nil.
func NewTransitBackend(cfg TransitConfig, log *logger.GatedLogger) (*TransitBackend, error) {
	if strings.TrimSpace(cfg.MountPath) == "" {
		return nil, fmt.Errorf("oidcsign: transit mount_path is required")
	}
	if strings.TrimSpace(cfg.KeyNamePrefix) == "" {
		return nil, fmt.Errorf("oidcsign: transit key_name_prefix is required")
	}

	apiCfg := api.DefaultConfig()
	if cfg.Address != "" {
		apiCfg.Address = cfg.Address
	}
	if cfg.TLSCACert != "" || cfg.TLSCAPath != "" || cfg.TLSClientCert != "" ||
		cfg.TLSClientKey != "" || cfg.TLSServerName != "" || cfg.TLSSkipVerify {
		tls := &api.TLSConfig{
			CACert:        cfg.TLSCACert,
			CAPath:        cfg.TLSCAPath,
			ClientCert:    cfg.TLSClientCert,
			ClientKey:     cfg.TLSClientKey,
			TLSServerName: cfg.TLSServerName,
			Insecure:      cfg.TLSSkipVerify,
		}
		if err := apiCfg.ConfigureTLS(tls); err != nil {
			return nil, fmt.Errorf("oidcsign: configure transit TLS: %w", err)
		}
	}

	client, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("oidcsign: create transit client: %w", err)
	}
	if cfg.Token != "" {
		client.SetToken(cfg.Token)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	b := &TransitBackend{
		client:        client,
		mountPath:     strings.Trim(cfg.MountPath, "/"),
		keyNamePrefix: cfg.KeyNamePrefix,
		timeout:       cfg.RequestTimeout,
		log:           log,
	}
	b.startRenewal(cfg.DisableRenewal)
	return b, nil
}

// startRenewal keeps a renewable token alive for the life of the backend, mirroring
// the transit auto-seal wrapper. A non-renewable or short-lived static token simply
// runs without a watcher; signing fails closed once it expires.
func (b *TransitBackend) startRenewal(disable bool) {
	if disable || b.client.Token() == "" {
		return
	}
	// Bound the initial renew so a down KMS cannot hang construction (the HTTP
	// client's 60s default would otherwise apply). A non-renewable token simply
	// runs without a watcher and fails closed when it expires.
	renewTimeout := b.timeout
	if renewTimeout <= 0 {
		renewTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), renewTimeout)
	defer cancel()
	secret, err := b.client.Auth().Token().RenewTokenAsSelfWithContext(ctx, b.client.Token(), 0)
	if err != nil {
		b.logInfo("oidcsign: transit token not renewable, disabling renewal", logger.Err(err))
		return
	}
	watcher, err := b.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{Secret: secret})
	if err != nil {
		b.logInfo("oidcsign: failed to start transit token renewal", logger.Err(err))
		return
	}
	b.watcher = watcher
	go func() {
		for {
			select {
			case err := <-watcher.DoneCh():
				if err != nil {
					b.logError("oidcsign: transit token renewal stopped", logger.Err(err))
				}
				return
			case <-watcher.RenewCh():
			}
		}
	}()
	go watcher.Start()
}

func (b *TransitBackend) Type() string { return backendTypeTransit }

// Close stops token renewal.
func (b *TransitBackend) Close() {
	if b.watcher != nil {
		b.watcher.Stop()
	}
}

// keyNameFor derives the transit key name for a JWS alg, e.g. "warden-oidc-rs256".
func (b *TransitBackend) keyNameFor(alg string) string {
	return b.keyNamePrefix + "-" + strings.ToLower(alg)
}

// EnsureKey creates alg's key if absent (idempotent) and returns its latest version.
func (b *TransitBackend) EnsureKey(ctx context.Context, alg string) (KeyInfo, error) {
	p, ok := algParamsByAlg[alg]
	if !ok {
		return KeyInfo{}, fmt.Errorf("oidcsign: unsupported signing algorithm %q", alg)
	}
	name := b.keyNameFor(alg)
	ctx, cancel := b.withTimeout(ctx)
	defer cancel()
	if _, err := b.client.Logical().WriteWithContext(ctx, b.keysPath(name), map[string]interface{}{
		"type": p.transitKeyType,
	}); err != nil {
		return KeyInfo{}, fmt.Errorf("oidcsign: ensure transit key %q: %w", name, err)
	}
	return b.latestKeyInfo(ctx, alg)
}

// NewVersion rotates alg's key and returns the new latest version.
func (b *TransitBackend) NewVersion(ctx context.Context, alg string) (KeyInfo, error) {
	if _, ok := algParamsByAlg[alg]; !ok {
		return KeyInfo{}, fmt.Errorf("oidcsign: unsupported signing algorithm %q", alg)
	}
	name := b.keyNameFor(alg)
	ctx, cancel := b.withTimeout(ctx)
	defer cancel()
	if _, err := b.client.Logical().WriteWithContext(ctx, b.keysPath(name)+"/rotate", nil); err != nil {
		return KeyInfo{}, fmt.Errorf("oidcsign: rotate transit key %q: %w", name, err)
	}
	return b.latestKeyInfo(ctx, alg)
}

// PublicKey fetches one specific version's public key, re-asserting the key type
// and non-exportability (transit allows flipping a key to exportable after
// creation, so this rarer path cheaply re-checks the invariant).
func (b *TransitBackend) PublicKey(ctx context.Context, ref KeyRef) (crypto.PublicKey, error) {
	ctx, cancel := b.withTimeout(ctx)
	defer cancel()
	kd, err := b.readKey(ctx, ref.KeyName)
	if err != nil {
		return nil, err
	}
	if err := validateTransitKey(kd, ref.KeyName, ref.Alg); err != nil {
		return nil, err
	}
	return kd.publicKeyForVersion(ref.Version)
}

// validateTransitKey enforces the two invariants a signing key must hold: it is
// the type the alg expects, and it is non-exportable (the whole point of remote
// signing).
func validateTransitKey(kd *transitKeyData, name, alg string) error {
	p, ok := algParamsByAlg[alg]
	if !ok {
		return fmt.Errorf("oidcsign: unsupported signing algorithm %q", alg)
	}
	if kd.Type != p.transitKeyType {
		return fmt.Errorf("oidcsign: transit key %q has type %q, expected %q for %s", name, kd.Type, p.transitKeyType, alg)
	}
	if kd.Exportable {
		return fmt.Errorf("oidcsign: transit key %q is exportable; the OIDC issuer key must be non-exportable (recreate with exportable=false)", name)
	}
	return nil
}

// Sign signs an already-hashed digest with the exact version in ref via
// transit/sign. RSA is forced to PKCS#1 v1.5 (transit defaults to PSS); ECDSA is
// requested in ASN.1 form, matching the crypto.Signer contract.
func (b *TransitBackend) Sign(ctx context.Context, ref KeyRef, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("oidcsign: RSA-PSS is not supported by the transit signer")
	}
	p, ok := algParamsByAlg[ref.Alg]
	if !ok {
		return nil, fmt.Errorf("oidcsign: unsupported signing algorithm %q", ref.Alg)
	}
	if ref.Version < 1 {
		// A zero version resolves to "latest" server-side, so refuse it up front
		// rather than sign with the wrong (pre-published next) key.
		return nil, fmt.Errorf("oidcsign: key version must be >= 1, got %d", ref.Version)
	}
	// Guard the digest against an alg/hash mismatch. For ECDSA transit signs
	// whatever prehashed bytes arrive, so a wrong-hash digest would produce a
	// well-formed but permanently unverifiable signature — fail fast instead.
	if opts.HashFunc() != p.hash {
		return nil, fmt.Errorf("oidcsign: %s requires a %v digest, got %v", ref.Alg, p.hash, opts.HashFunc())
	}
	if len(digest) != p.hash.Size() {
		return nil, fmt.Errorf("oidcsign: %s digest must be %d bytes, got %d", ref.Alg, p.hash.Size(), len(digest))
	}

	data := map[string]interface{}{
		"input":                base64.StdEncoding.EncodeToString(digest),
		"prehashed":            true,
		"hash_algorithm":       p.hashName,
		"key_version":          ref.Version,
		"marshaling_algorithm": "asn1",
	}
	if p.isRSA {
		data["signature_algorithm"] = "pkcs1v15"
	}
	ctx, cancel := b.withTimeout(ctx)
	defer cancel()
	secret, err := b.client.Logical().WriteWithContext(ctx, b.signPath(ref.KeyName), data)
	if err != nil {
		return nil, fmt.Errorf("oidcsign: transit sign %q: %w", ref.KeyName, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("oidcsign: transit sign %q returned no data", ref.KeyName)
	}
	// The response's key_version is the authoritative, template-independent proof
	// of which version signed; verify it pinned to the version we asked for.
	if signedVer, err := asInt(secret.Data["key_version"]); err == nil && signedVer != ref.Version {
		return nil, fmt.Errorf("oidcsign: transit signed with key version %d, expected %d", signedVer, ref.Version)
	}
	raw, _ := secret.Data["signature"].(string)
	return decodeTransitSignature(raw)
}

// latestKeyInfo reads alg's key, validates it, and returns its latest version.
func (b *TransitBackend) latestKeyInfo(ctx context.Context, alg string) (KeyInfo, error) {
	name := b.keyNameFor(alg)
	kd, err := b.readKey(ctx, name)
	if err != nil {
		return KeyInfo{}, err
	}
	if err := validateTransitKey(kd, name, alg); err != nil {
		return KeyInfo{}, err
	}
	pub, err := kd.publicKeyForVersion(kd.LatestVersion)
	if err != nil {
		return KeyInfo{}, err
	}
	created, err := kd.creationTimeForVersion(kd.LatestVersion)
	if err != nil {
		return KeyInfo{}, err
	}
	return KeyInfo{
		Ref:       KeyRef{KeyName: name, Version: kd.LatestVersion, Alg: alg},
		Public:    pub,
		CreatedAt: created,
	}, nil
}

func (b *TransitBackend) keysPath(name string) string { return b.mountPath + "/keys/" + name }
func (b *TransitBackend) signPath(name string) string { return b.mountPath + "/sign/" + name }

func (b *TransitBackend) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if b.timeout > 0 {
		return context.WithTimeout(ctx, b.timeout)
	}
	return context.WithCancel(ctx)
}

func (b *TransitBackend) logInfo(msg string, f ...logger.TypedField) {
	if b.log != nil {
		b.log.Info(msg, f...)
	}
}

func (b *TransitBackend) logError(msg string, f ...logger.TypedField) {
	if b.log != nil {
		b.log.Error(msg, f...)
	}
}

// transitKeyData is the parsed subset of a transit/keys/<name> read response.
type transitKeyData struct {
	Type          string
	Exportable    bool
	LatestVersion int
	Keys          map[string]transitKeyVersion
}

type transitKeyVersion struct {
	PublicKey    string `json:"public_key"`
	CreationTime string `json:"creation_time"`
}

// readKey reads and parses a transit key's metadata (type, exportable, versions).
func (b *TransitBackend) readKey(ctx context.Context, name string) (*transitKeyData, error) {
	secret, err := b.client.Logical().ReadWithContext(ctx, b.keysPath(name))
	if err != nil {
		return nil, fmt.Errorf("oidcsign: read transit key %q: %w", name, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("oidcsign: transit key %q not found", name)
	}
	kd := &transitKeyData{}
	kd.Type, _ = secret.Data["type"].(string)
	kd.Exportable, _ = secret.Data["exportable"].(bool)
	lv, err := asInt(secret.Data["latest_version"])
	if err != nil {
		return nil, fmt.Errorf("oidcsign: transit key %q: bad latest_version: %w", name, err)
	}
	kd.LatestVersion = lv
	// Re-marshal the versions map through JSON to decode into typed structs. This
	// is best-effort: a symmetric key (AES/ChaCha) returns "keys" as a map of
	// creation timestamps (numbers), which fails to decode here — leaving Keys nil
	// so the caller's type check reports the clean "wrong key type" error instead.
	if rawKeys, ok := secret.Data["keys"]; ok {
		if buf, err := json.Marshal(rawKeys); err == nil {
			_ = json.Unmarshal(buf, &kd.Keys)
		}
	}
	return kd, nil
}

func (kd *transitKeyData) versionEntry(version int) (transitKeyVersion, error) {
	v, ok := kd.Keys[strconv.Itoa(version)]
	if !ok {
		return transitKeyVersion{}, fmt.Errorf("oidcsign: transit key has no version %d", version)
	}
	return v, nil
}

func (kd *transitKeyData) publicKeyForVersion(version int) (crypto.PublicKey, error) {
	v, err := kd.versionEntry(version)
	if err != nil {
		return nil, err
	}
	return parsePublicKeyPEM(v.PublicKey)
}

func (kd *transitKeyData) creationTimeForVersion(version int) (time.Time, error) {
	v, err := kd.versionEntry(version)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, v.CreationTime)
	if err != nil {
		return time.Time{}, fmt.Errorf("oidcsign: parse transit key creation_time %q: %w", v.CreationTime, err)
	}
	return t, nil
}

// parsePublicKeyPEM decodes a PKIX PEM public key and ensures it is RSA or ECDSA.
func parsePublicKeyPEM(pemStr string) (crypto.PublicKey, error) {
	if pemStr == "" {
		return nil, fmt.Errorf("oidcsign: empty public key")
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("oidcsign: public key is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oidcsign: parse public key: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("oidcsign: unsupported public key type %T", pub)
	}
}

// decodeTransitSignature extracts the raw signature bytes from transit's
// "<prefix>:v<N>:<base64>" envelope. The base64 payload is the final
// colon-delimited segment (standard base64 contains no colon), so this tolerates a
// custom version_template in the prefix; the key version itself is validated by the
// caller against the response's authoritative key_version field. asn1 marshaling
// uses standard base64.
func decodeTransitSignature(sig string) ([]byte, error) {
	if sig == "" {
		return nil, fmt.Errorf("oidcsign: transit returned an empty signature")
	}
	i := strings.LastIndex(sig, ":")
	if i < 0 || i == len(sig)-1 {
		return nil, fmt.Errorf("oidcsign: malformed transit signature")
	}
	raw, err := base64.StdEncoding.DecodeString(sig[i+1:])
	if err != nil {
		return nil, fmt.Errorf("oidcsign: decode transit signature: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("oidcsign: transit returned an empty signature payload")
	}
	return raw, nil
}

// asInt coerces a JSON-decoded number (json.Number, float64, int, or string) to int.
func asInt(v interface{}) (int, error) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case float64:
		return int(n), nil
	case int:
		return n, nil
	case string:
		i, err := strconv.Atoi(n)
		return i, err
	default:
		return 0, fmt.Errorf("not a number: %T", v)
	}
}
