package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/sdk/v2/physical/inmem"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/config"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createClusterTestCore creates a minimal Core suitable for cluster TLS tests.
// The Core has HA enabled and a cluster address set.
func createClusterTestCore(t *testing.T, clusterAddr string) *Core {
	t.Helper()

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})

	physBackend, _ := inmem.NewInmemHA(nil, nil)
	haBackend := physBackend.(physical.HABackend)

	conf := &CoreConfig{
		RawConfig:    &config.Config{},
		Physical:     physBackend.(*inmem.InmemHABackend).Backend,
		HAPhysical:   haBackend,
		RedirectAddr: "https://127.0.0.1:8400",
		ClusterAddr:  clusterAddr,
		StorageType:  "inmem_ha",
		Logger:       log,
		AuditDevices: map[string]audit.Factory{
			"file": &mockAuditFactory{},
		},
	}

	c, err := NewCore(conf)
	require.NoError(t, err)
	return c
}

// =============================================================================
// setupCluster Tests
// =============================================================================

func TestSetupCluster_GeneratesCertAndKey(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	// Private key should be stored
	key := c.localClusterPrivateKey.Load()
	require.NotNil(t, key, "private key should be stored")
	assert.Equal(t, elliptic.P521(), key.Curve, "key should use P-521 curve")

	// DER cert should be stored
	certPtr := c.localClusterCert.Load()
	require.NotNil(t, certPtr, "DER cert should be stored")
	assert.NotEmpty(t, *certPtr)

	// Parsed cert should be stored
	parsed := c.localClusterParsedCert.Load()
	require.NotNil(t, parsed, "parsed cert should be stored")
}

func TestSetupCluster_CertProperties(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	parsed := c.localClusterParsedCert.Load()
	require.NotNil(t, parsed)

	// CN should start with "fw-" prefix
	assert.Contains(t, parsed.Subject.CommonName, "fw-", "CN should have fw- prefix")

	// Should be a CA
	assert.True(t, parsed.IsCA, "cert should be a CA")
	assert.True(t, parsed.BasicConstraintsValid, "BasicConstraintsValid should be set")

	// EKU: serverAuth + clientAuth
	assert.Contains(t, parsed.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, parsed.ExtKeyUsage, x509.ExtKeyUsageClientAuth)

	// KeyUsage
	assert.NotZero(t, parsed.KeyUsage&x509.KeyUsageDigitalSignature)
	assert.NotZero(t, parsed.KeyUsage&x509.KeyUsageKeyEncipherment)
	assert.NotZero(t, parsed.KeyUsage&x509.KeyUsageKeyAgreement)
	assert.NotZero(t, parsed.KeyUsage&x509.KeyUsageCertSign)

	// Validity: NotBefore should be slightly in the past (clock skew grace)
	assert.False(t, parsed.NotBefore.IsZero())
	assert.False(t, parsed.NotAfter.IsZero())
	assert.True(t, parsed.NotAfter.After(parsed.NotBefore))

	// Self-signed: issuer == subject
	assert.Equal(t, parsed.Issuer.CommonName, parsed.Subject.CommonName)
}

func TestSetupCluster_SelfSignedVerification(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	parsed := c.localClusterParsedCert.Load()
	require.NotNil(t, parsed)

	// The cert should verify against itself (self-signed CA)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	_, err = parsed.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "self-signed cert should verify against itself")
}

func TestSetupCluster_UniquePerCall(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// First call
	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	cert1 := c.localClusterParsedCert.Load()
	key1 := c.localClusterPrivateKey.Load()

	// Second call (simulating leadership transition)
	c.clearClusterTLS()
	err = c.setupCluster(context.Background())
	require.NoError(t, err)

	cert2 := c.localClusterParsedCert.Load()
	key2 := c.localClusterPrivateKey.Load()

	// Each call should generate different certs and keys
	assert.NotEqual(t, cert1.SerialNumber, cert2.SerialNumber, "serial numbers should differ")
	assert.NotEqual(t, cert1.Subject.CommonName, cert2.Subject.CommonName, "CNs should differ")
	assert.False(t, key1.Equal(key2), "keys should differ")
}

func TestSetupCluster_NoHABackend_Noop(t *testing.T) {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	c := &Core{
		logger:    log,
		rawConfig: new(atomic.Value),
	}
	c.rawConfig.Store(&config.Config{})
	// ha is nil — setupCluster should be a no-op

	err := c.setupCluster(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, c.localClusterPrivateKey.Load())
	assert.Nil(t, c.localClusterCert.Load())
	assert.Nil(t, c.localClusterParsedCert.Load())
}

func TestSetupCluster_NoClusterAddr_Noop(t *testing.T) {
	c := createClusterTestCore(t, "") // empty cluster addr
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, c.localClusterPrivateKey.Load())
	assert.Nil(t, c.localClusterCert.Load())
}

// =============================================================================
// clearClusterTLS Tests
// =============================================================================

func TestClearClusterTLS(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// Generate identity
	err := c.setupCluster(context.Background())
	require.NoError(t, err)
	require.NotNil(t, c.localClusterPrivateKey.Load())

	// Clear it
	c.clearClusterTLS()

	assert.Nil(t, c.localClusterCert.Load())
	assert.Nil(t, c.localClusterParsedCert.Load())
	assert.Nil(t, c.localClusterPrivateKey.Load())
}

func TestClearClusterTLS_Idempotent(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// Clear without any identity set — should not panic
	c.clearClusterTLS()
	c.clearClusterTLS()

	assert.Nil(t, c.localClusterCert.Load())
}

// =============================================================================
// ClusterTLSConfig Tests
// =============================================================================

func TestClusterTLSConfig_NilWhenNoIdentity(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// No setupCluster called — should return nil
	cfg := c.ClusterTLSConfig()
	assert.Nil(t, cfg, "should return nil when no cluster identity is loaded")
}

func TestClusterTLSConfig_ValidAfterSetup(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	cfg := c.ClusterTLSConfig()
	require.NotNil(t, cfg)

	// Should have exactly one certificate
	assert.Len(t, cfg.Certificates, 1)
	assert.NotNil(t, cfg.Certificates[0].PrivateKey)
	assert.NotEmpty(t, cfg.Certificates[0].Certificate)
	assert.NotNil(t, cfg.Certificates[0].Leaf)

	// Should have CA pools set
	assert.NotNil(t, cfg.RootCAs, "RootCAs should be set")
	assert.NotNil(t, cfg.ClientCAs, "ClientCAs should be set")

	// Should enforce mTLS
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)

	// Min TLS version
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

func TestClusterTLSConfig_NilAfterClear(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)
	require.NotNil(t, c.ClusterTLSConfig())

	c.clearClusterTLS()

	cfg := c.ClusterTLSConfig()
	assert.Nil(t, cfg, "should return nil after clearing cluster TLS")
}

func TestClusterTLSConfig_PartialState_ReturnsNil(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// Set only the cert but not the key or parsed cert
	certBytes := []byte{1, 2, 3}
	c.localClusterCert.Store(&certBytes)

	cfg := c.ClusterTLSConfig()
	assert.Nil(t, cfg, "should return nil when identity is incomplete")
}

// =============================================================================
// clusterKeyParams Tests
// =============================================================================

func TestClusterKeyParams_NilWhenNoKey(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	params := c.clusterKeyParams()
	assert.Nil(t, params)
}

func TestClusterKeyParams_ValidAfterSetup(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	params := c.clusterKeyParams()
	require.NotNil(t, params)

	assert.Equal(t, corePrivateKeyTypeP521, params.Type)
	assert.NotNil(t, params.X, "X coordinate should be set")
	assert.NotNil(t, params.Y, "Y coordinate should be set")
	assert.NotNil(t, params.D, "D (private) should be set")
}

// =============================================================================
// clusterCertDER Tests
// =============================================================================

func TestClusterCertDER_NilWhenNoCert(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	der := c.clusterCertDER()
	assert.Nil(t, der)
}

func TestClusterCertDER_ReturnsCopy(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	der1 := c.clusterCertDER()
	der2 := c.clusterCertDER()
	require.NotNil(t, der1)
	require.NotNil(t, der2)

	// Should be equal content but different slices (defensive copy)
	assert.Equal(t, der1, der2)

	// Modifying one should not affect the other
	der1[0] ^= 0xFF
	assert.NotEqual(t, der1, der2, "modifying one copy should not affect the other")
}

// =============================================================================
// loadLocalClusterTLS Tests
// =============================================================================

func TestLoadLocalClusterTLS_Success(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// Generate identity on the "active" core
	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	// Extract the advertisement data
	certDER := c.clusterCertDER()
	keyParams := c.clusterKeyParams()
	originalParsed := c.localClusterParsedCert.Load()

	// Clear identity (simulating a different "standby" node)
	c.clearClusterTLS()
	require.Nil(t, c.ClusterTLSConfig())

	// Load from the advertisement
	adv := activeAdvertisement{
		ClusterAddr:      "https://127.0.0.1:8401",
		ClusterCert:      certDER,
		ClusterKeyParams: keyParams,
	}
	err = c.loadLocalClusterTLS(adv)
	require.NoError(t, err)

	// Verify the loaded identity matches
	loadedKey := c.localClusterPrivateKey.Load()
	require.NotNil(t, loadedKey)
	assert.Equal(t, elliptic.P521(), loadedKey.Curve)
	assert.Equal(t, keyParams.X, loadedKey.X)
	assert.Equal(t, keyParams.Y, loadedKey.Y)
	assert.Equal(t, keyParams.D, loadedKey.D)

	loadedParsed := c.localClusterParsedCert.Load()
	require.NotNil(t, loadedParsed)
	assert.Equal(t, originalParsed.SerialNumber, loadedParsed.SerialNumber)
	assert.Equal(t, originalParsed.Subject.CommonName, loadedParsed.Subject.CommonName)

	// The loaded TLS config should be valid
	cfg := c.ClusterTLSConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
}

func TestLoadLocalClusterTLS_EmptyClusterAddr_Noop(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	adv := activeAdvertisement{
		ClusterAddr: "", // empty = clustering disabled on leader
	}
	err := c.loadLocalClusterTLS(adv)
	assert.NoError(t, err)
	assert.Nil(t, c.ClusterTLSConfig())
}

func TestLoadLocalClusterTLS_MissingKeyParams(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	adv := activeAdvertisement{
		ClusterAddr:      "https://127.0.0.1:8401",
		ClusterCert:      []byte{1, 2, 3},
		ClusterKeyParams: nil,
	}
	err := c.loadLocalClusterTLS(adv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no cluster key params")
}

func TestLoadLocalClusterTLS_IncompleteKeyParams(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	adv := activeAdvertisement{
		ClusterAddr: "https://127.0.0.1:8401",
		ClusterCert: []byte{1, 2, 3},
		ClusterKeyParams: &certutil.ClusterKeyParams{
			Type: corePrivateKeyTypeP521,
			X:    nil, // incomplete
		},
	}
	err := c.loadLocalClusterTLS(adv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete cluster key params")
}

func TestLoadLocalClusterTLS_WrongKeyType(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// Generate valid identity to get real key params
	err := c.setupCluster(context.Background())
	require.NoError(t, err)
	keyParams := c.clusterKeyParams()
	certDER := c.clusterCertDER()
	c.clearClusterTLS()

	keyParams.Type = "ed25519" // wrong type
	adv := activeAdvertisement{
		ClusterAddr:      "https://127.0.0.1:8401",
		ClusterCert:      certDER,
		ClusterKeyParams: keyParams,
	}
	err = c.loadLocalClusterTLS(adv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown cluster key type")
}

func TestLoadLocalClusterTLS_MissingCert(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)
	keyParams := c.clusterKeyParams()
	c.clearClusterTLS()

	adv := activeAdvertisement{
		ClusterAddr:      "https://127.0.0.1:8401",
		ClusterCert:      nil, // missing
		ClusterKeyParams: keyParams,
	}
	err = c.loadLocalClusterTLS(adv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no cluster cert")
}

func TestLoadLocalClusterTLS_InvalidCertDER(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)
	keyParams := c.clusterKeyParams()
	c.clearClusterTLS()

	adv := activeAdvertisement{
		ClusterAddr:      "https://127.0.0.1:8401",
		ClusterCert:      []byte{0xDE, 0xAD, 0xBE, 0xEF}, // invalid DER
		ClusterKeyParams: keyParams,
	}
	err = c.loadLocalClusterTLS(adv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse cluster cert")
}

// =============================================================================
// Roundtrip Test: setup → extract → load → verify
// =============================================================================

func TestClusterTLS_Roundtrip(t *testing.T) {
	// Simulate the full flow: active generates cert, standby loads it from
	// the advertisement, both get the same TLS config that can mutually
	// authenticate.

	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	// Active generates identity
	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	activeCfg := c.ClusterTLSConfig()
	require.NotNil(t, activeCfg)

	// Extract what goes into the leader advertisement
	certDER := c.clusterCertDER()
	keyParams := c.clusterKeyParams()

	// Simulate standby loading the identity
	c.clearClusterTLS()
	adv := activeAdvertisement{
		ClusterAddr:      "https://127.0.0.1:8401",
		ClusterCert:      certDER,
		ClusterKeyParams: keyParams,
	}
	err = c.loadLocalClusterTLS(adv)
	require.NoError(t, err)

	standbyCfg := c.ClusterTLSConfig()
	require.NotNil(t, standbyCfg)

	// Both configs should produce equivalent TLS state:
	// same cert, same CA pools, same client auth requirement
	assert.Equal(t, len(activeCfg.Certificates), len(standbyCfg.Certificates))
	assert.Equal(t, activeCfg.ClientAuth, standbyCfg.ClientAuth)
	assert.Equal(t, activeCfg.MinVersion, standbyCfg.MinVersion)

	// The DER cert bytes should match
	assert.Equal(t, activeCfg.Certificates[0].Certificate[0], standbyCfg.Certificates[0].Certificate[0])

	// Both keys should be equivalent (can sign/verify with each other's cert)
	activeKey := activeCfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	standbyKey := standbyCfg.Certificates[0].PrivateKey.(*ecdsa.PrivateKey)
	assert.True(t, activeKey.Equal(standbyKey), "keys should match after roundtrip")
}

// =============================================================================
// activeAdvertisement JSON Serialization Tests
// =============================================================================

func TestActiveAdvertisement_JSON_WithClusterTLS(t *testing.T) {
	c := createClusterTestCore(t, "https://127.0.0.1:8401")
	defer c.Shutdown()

	err := c.setupCluster(context.Background())
	require.NoError(t, err)

	adv := activeAdvertisement{
		RedirectAddr:     "https://127.0.0.1:8400",
		ClusterAddr:      "https://127.0.0.1:8401",
		ClusterCert:      c.clusterCertDER(),
		ClusterKeyParams: c.clusterKeyParams(),
	}

	// Serialize
	data, err := json.Marshal(adv)
	require.NoError(t, err)

	// Deserialize
	var decoded activeAdvertisement
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, adv.RedirectAddr, decoded.RedirectAddr)
	assert.Equal(t, adv.ClusterAddr, decoded.ClusterAddr)
	assert.Equal(t, adv.ClusterCert, decoded.ClusterCert)
	assert.Equal(t, adv.ClusterKeyParams.Type, decoded.ClusterKeyParams.Type)
	assert.Equal(t, adv.ClusterKeyParams.X.Bytes(), decoded.ClusterKeyParams.X.Bytes())
	assert.Equal(t, adv.ClusterKeyParams.Y.Bytes(), decoded.ClusterKeyParams.Y.Bytes())
	assert.Equal(t, adv.ClusterKeyParams.D.Bytes(), decoded.ClusterKeyParams.D.Bytes())

	// Should be loadable
	err = c.loadLocalClusterTLS(decoded)
	require.NoError(t, err)
	assert.NotNil(t, c.ClusterTLSConfig())
}

func TestActiveAdvertisement_JSON_WithoutClusterTLS(t *testing.T) {
	// Backward compatibility: advertisement without cluster TLS fields
	adv := activeAdvertisement{
		RedirectAddr: "https://127.0.0.1:8400",
	}

	data, err := json.Marshal(adv)
	require.NoError(t, err)

	var decoded activeAdvertisement
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "https://127.0.0.1:8400", decoded.RedirectAddr)
	assert.Empty(t, decoded.ClusterAddr)
	assert.Nil(t, decoded.ClusterCert)
	assert.Nil(t, decoded.ClusterKeyParams)
}

// =============================================================================
// HA Integration: Cluster TLS in leader advertisement
// =============================================================================

func TestHA_LeaderAdvertisement_IncludesClusterTLS(t *testing.T) {
	physBackend, haBackend := newInmemHABackends(t)

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	conf := &CoreConfig{
		RawConfig:    &config.Config{},
		Physical:     physBackend,
		HAPhysical:   haBackend,
		RedirectAddr: "https://127.0.0.1:8400",
		ClusterAddr:  "https://127.0.0.1:8401",
		StorageType:  "inmem_ha",
		Logger:       log,
		AuditDevices: map[string]audit.Factory{
			"file": &mockAuditFactory{},
		},
	}

	c, err := NewCore(conf)
	require.NoError(t, err)
	defer c.Shutdown()

	// Initialize and unseal to become active
	initAndUnsealCore(t, c)
	active := waitForActiveNode(t, []*Core{c}, 5*time.Second)
	require.NotNil(t, active)

	// Active node should have generated cluster TLS identity
	require.NotNil(t, active.localClusterPrivateKey.Load(), "active should have cluster private key")
	require.NotNil(t, active.localClusterCert.Load(), "active should have cluster cert")
	require.NotNil(t, active.localClusterParsedCert.Load(), "active should have parsed cluster cert")

	// Read the leader advertisement and verify it includes cluster TLS
	ctx := context.Background()
	keys, err := active.barrier.List(ctx, leaderPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, keys)

	adv, err := active.readLeaderAdvertisement(ctx, keys[0])
	require.NoError(t, err)
	require.NotNil(t, adv)

	assert.Equal(t, "https://127.0.0.1:8400", adv.RedirectAddr)
	assert.Equal(t, "https://127.0.0.1:8401", adv.ClusterAddr)
	assert.NotEmpty(t, adv.ClusterCert, "advertisement should include cluster cert")
	assert.NotNil(t, adv.ClusterKeyParams, "advertisement should include key params")
	assert.Equal(t, corePrivateKeyTypeP521, adv.ClusterKeyParams.Type)

	// Verify the cert in the advertisement matches the active's identity
	assert.Equal(t, c.clusterCertDER(), adv.ClusterCert)
}

func TestHA_LeaderAdvertisement_NoClusterTLS_WithoutClusterAddr(t *testing.T) {
	physBackend, haBackend := newInmemHABackends(t)

	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	conf := &CoreConfig{
		RawConfig:    &config.Config{},
		Physical:     physBackend,
		HAPhysical:   haBackend,
		RedirectAddr: "http://127.0.0.1:8400",
		ClusterAddr:  "", // No cluster addr — no cluster TLS
		StorageType:  "inmem_ha",
		Logger:       log,
		AuditDevices: map[string]audit.Factory{
			"file": &mockAuditFactory{},
		},
	}

	c, err := NewCore(conf)
	require.NoError(t, err)
	defer c.Shutdown()

	initAndUnsealCore(t, c)
	active := waitForActiveNode(t, []*Core{c}, 5*time.Second)
	require.NotNil(t, active)

	// Without cluster_addr, no cluster TLS identity should be generated
	assert.Nil(t, active.localClusterPrivateKey.Load())
	assert.Nil(t, active.localClusterCert.Load())

	// The advertisement should not include cluster TLS fields
	ctx := context.Background()
	keys, err := active.barrier.List(ctx, leaderPrefix)
	require.NoError(t, err)
	require.NotEmpty(t, keys)

	adv, err := active.readLeaderAdvertisement(ctx, keys[0])
	require.NoError(t, err)
	require.NotNil(t, adv)

	assert.Nil(t, adv.ClusterCert)
	assert.Nil(t, adv.ClusterKeyParams)
}
