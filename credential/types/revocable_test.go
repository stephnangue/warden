package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Revoking a credential means releasing a lease at the source, which needs a
// handle to release. A credential carrying a TTL but no leaseID has nothing to
// release, so it is not revocable however long it lives — the invariant
// base_token_type.go already states as `t.Revocable && leaseID != ""`.
//
// Marking such a credential revocable registered an expiration-manager entry per
// mint whose revocation reduced to a cache delete the cache's own TTL was going
// to do anyway, and reported the wrong Revocable in the audit log.
//
// Three of these types could actually be handed a TTL with no leaseID; the other
// three could not, and are covered here so the invariant holds by construction
// rather than by whichever mint paths happen to exist today.
func TestRevocableRequiresLeaseID(t *testing.T) {
	tests := []struct {
		name string
		// reachable records whether a driver can currently produce a TTL with no
		// leaseID for this type. It documents the audit; the assertions below are
		// the same either way.
		reachable bool
		credType  credential.Type
		rawData   map[string]interface{}
		leaseID   string
	}{
		{
			// The alicloud driver's only mint path returns self-expiring STS
			// session credentials and no leaseID.
			name:      "alicloud_keys",
			reachable: true,
			credType:  &AlicloudKeysCredType{},
			rawData: map[string]interface{}{
				"access_key_id":     "STS.abc",
				"access_key_secret": "secret",
				"security_token":    "token",
			},
			leaseID: "sts-session",
		},
		{
			// The IBM driver's own IAM-token paths return no leaseID; only the
			// Vault dynamic_ibm path carries one.
			name:      "ibmcloud_keys",
			reachable: true,
			credType:  &IBMCloudKeysCredType{},
			rawData:   map[string]interface{}{"access_token": "test-access-token"},
			leaseID:   "ibm/creds/role/abc123",
		},
		{
			// No OVH mint path returns a leaseID: a bearer token expires on its own,
			// and an access_keys pair was never created here to be deleted. The row
			// still passes a leaseID so the invariant is asserted rather than left
			// to whichever paths happen to exist.
			name:      "ovh_keys",
			reachable: true,
			credType:  &OVHKeysCredType{},
			rawData:   map[string]interface{}{"api_token": "test-api-token"},
			leaseID:   "project/user/accesskey",
		},
		{
			// Every AWS path returning a TTL also returns a leaseID today.
			name:      "aws_iam_keys",
			reachable: false,
			credType:  &AWSIAMAccessKeysCredType{},
			rawData: map[string]interface{}{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
			},
			leaseID: "sts:AKIAIOSFODNN7EXAMPLE",
		},
		{
			// Scaleway's static path returns no TTL; its dynamic path returns a
			// leaseID.
			name:      "scaleway_keys",
			reachable: false,
			credType:  &ScalewayKeysCredType{},
			rawData: map[string]interface{}{
				"access_key": "SCWXXXXXXXXXXXXXXXXX",
				"secret_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			},
			leaseID: "SCWXXXXXXXXXXXXXXXXX",
		},
		{
			// Cloudflare keys only come from a local source, which returns neither
			// a TTL nor a leaseID.
			name:      "cloudflare_keys",
			reachable: false,
			credType:  &CloudflareKeysCredType{},
			rawData:   map[string]interface{}{"api_token": "v1.0-test-token"},
			leaseID:   "cf-lease",
		},
		{
			// api_key is served by two families, and the leaseID is what tells
			// them apart. The store-backed readers — the apikey and local specs,
			// the vault static_apikey read, the aws secrets_manager read — return
			// neither a TTL nor a leaseID, and must stay non-revocable: the key is
			// someone else's to destroy. The drivers that create a key upstream
			// (elastic, grafana, honeycomb) return both, and are revoked at
			// session end.
			//
			// Not reachable: no api_key path returns a TTL without a leaseID.
			name:      "api_key",
			reachable: false,
			credType:  NewAPIKeyCredType(),
			rawData:   map[string]interface{}{"api_key": "sk-xxxxxxxxxxxxxxxxxxxx"},
			leaseID:   "elastic:abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("a TTL with no leaseID is not revocable", func(t *testing.T) {
				cred, err := tt.credType.Parse(tt.rawData, nil, time.Hour, "")
				require.NoError(t, err)
				assert.False(t, cred.Revocable,
					"nothing to release, so it cannot be revoked (reachable today: %v)", tt.reachable)
			})

			t.Run("a TTL with a leaseID is revocable", func(t *testing.T) {
				cred, err := tt.credType.Parse(tt.rawData, nil, time.Hour, tt.leaseID)
				require.NoError(t, err)
				assert.True(t, cred.Revocable)
			})

			t.Run("a static credential is not revocable", func(t *testing.T) {
				cred, err := tt.credType.Parse(tt.rawData, nil, 0, "")
				require.NoError(t, err)
				assert.False(t, cred.Revocable)
			})
		})
	}
}
