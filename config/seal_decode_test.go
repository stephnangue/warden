package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHCLTags_NoDuplicateNames guards against two fields of one block
// declaring the same HCL key. The decoder maps a key to a single field, the
// last one declared, so a duplicate silently steals the value from the
// field the operator meant.
func TestHCLTags_NoDuplicateNames(t *testing.T) {
	for _, v := range []any{Config{}, ListenerBlock{}, StorageBlock{}, KMS{}, AuditBlock{}, SignerBlock{}} {
		typ := reflect.TypeOf(v)
		seen := map[string]string{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := f.Tag.Get("hcl")
			if tag == "" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			if prev, dup := seen[name]; dup {
				t.Errorf("%s: HCL key %q is declared on both %s and %s", typ.Name(), name, prev, f.Name)
				continue
			}
			seen[name] = f.Name
		}
	}
}

// TestSealConfig_HCLRoundTrip parses each seal type from real HCL and checks
// that Config() hands the wrapper every attribute under the key name the
// wrapper reads.
func TestSealConfig_HCLRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		hcl  string
		want map[string]string
	}{
		{
			name: "transit",
			hcl: `seal "transit" {
  address         = "https://bao.example.com:8200"
  token           = "s.abc"
  key_name        = "warden-unseal"
  mount_path      = "transit/"
  namespace       = "ops"
  disable_renewal = "true"
  key_id_prefix   = "wd-"
  tls_ca_cert     = "/ca.pem"
  tls_ca_path     = "/cas"
  tls_server_name = "bao"
}`,
			want: map[string]string{
				"type": "transit", "address": "https://bao.example.com:8200", "token": "s.abc",
				"key_name": "warden-unseal", "mount_path": "transit/", "namespace": "ops",
				"disable_renewal": "true", "key_id_prefix": "wd-", "tls_ca_cert": "/ca.pem",
				"tls_ca_path": "/cas", "tls_server_name": "bao",
			},
		},
		{
			name: "awskms",
			hcl: `seal "awskms" {
  region     = "eu-west-1"
  kms_key_id = "arn:aws:kms:eu-west-1:111:key/abc"
  endpoint   = "https://kms.eu-west-1.amazonaws.com"
  access_key = "AKIA"
  secret_key = "secret"
}`,
			want: map[string]string{
				"type": "awskms", "region": "eu-west-1", "kms_key_id": "arn:aws:kms:eu-west-1:111:key/abc",
				"endpoint": "https://kms.eu-west-1.amazonaws.com", "access_key": "AKIA", "secret_key": "secret",
			},
		},
		{
			name: "gcpckms",
			hcl: `seal "gcpckms" {
  credentials = "/sa.json"
  project     = "p"
  region      = "global"
  key_ring    = "ring"
  crypto_key  = "key"
}`,
			want: map[string]string{
				"type": "gcpckms", "credentials": "/sa.json", "project": "p", "region": "global",
				"key_ring": "ring", "crypto_key": "key",
			},
		},
		{
			name: "azurekeyvault",
			hcl: `seal "azurekeyvault" {
  tenant_id     = "t"
  client_id     = "c"
  client_secret = "s"
  vault_name    = "v"
  key_name      = "warden-unseal"
  resource      = "vault.azure.net"
}`,
			want: map[string]string{
				"type": "azurekeyvault", "tenant_id": "t", "client_id": "c", "client_secret": "s",
				"vault_name": "v", "key_name": "warden-unseal", "resource": "vault.azure.net",
			},
		},
		{
			name: "kmip",
			hcl: `seal "kmip" {
  endpoint    = "kmip.example.com:5696"
  kms_key_id  = "k1"
  client_cert = "/c.pem"
  client_key  = "/k.pem"
  ca_cert     = "/ca.pem"
  timeout     = 10
}`,
			want: map[string]string{
				"type": "kmip", "endpoint": "kmip.example.com:5696", "kms_key_id": "k1",
				"client_cert": "/c.pem", "client_key": "/k.pem", "ca_cert": "/ca.pem", "timeout": "10",
			},
		},
		{
			name: "ocikms",
			hcl: `seal "ocikms" {
  key_id              = "ocid1.key.oc1..x"
  crypto_endpoint     = "https://crypto"
  management_endpoint = "https://mgmt"
}`,
			want: map[string]string{
				"type": "ocikms", "key_id": "ocid1.key.oc1..x",
				"crypto_endpoint": "https://crypto", "management_endpoint": "https://mgmt",
			},
		},
		{
			name: "alicloudkms",
			hcl: `seal "alicloudkms" {
  region     = "cn-hangzhou"
  domain     = "kms.cn-hangzhou.aliyuncs.com"
  access_key = "ak"
  secret_key = "sk"
  kms_key_id = "k1"
}`,
			want: map[string]string{
				"type": "alicloudkms", "region": "cn-hangzhou", "domain": "kms.cn-hangzhou.aliyuncs.com",
				"access_key": "ak", "secret_key": "sk", "kms_key_id": "k1",
			},
		},
		{
			name: "static",
			hcl: `seal "static" {
  current_key_id = "k1"
  current_key    = "file:///k"
}`,
			want: map[string]string{
				"type": "static", "current_key_id": "k1", "current_key": "file:///k",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &collectingWarner{}
			cfg, err := decodeConfig("warden.hcl", []byte(tc.hcl), w)
			require.NoError(t, err)
			assert.Empty(t, w.msgs, "no attribute of a supported seal should be pruned")
			require.Len(t, cfg.Seals, 1)
			assert.Equal(t, tc.want, cfg.Seals[0].Config())
		})
	}
}
