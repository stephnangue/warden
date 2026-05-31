package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// KubernetesRoleTokenType implements Kubernetes ServiceAccount JWT handling
// with role binding. Used for implicit authentication where clients present
// a K8s SA JWT directly and Warden authenticates them by calling TokenReview
// on the issuing kube-apiserver (no JWKS fetch needed on the hub side).
//
// The (mountAccessor, JWT, role) tuple is the lookup value; its hash becomes
// the token ID. mountAccessor prevents cache contamination across two
// kubernetes mounts that share a role name and an SA token (e.g. workloads
// in different spoke clusters that happen to use identical role names).
type KubernetesRoleTokenType struct{}

func (t *KubernetesRoleTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        TypeKubernetesRole,
		IDPrefix:    "kubr_",
		ValuePrefix: "", // MUST be empty: K8s SA tokens are JWTs (eyJ...) but
		// JWTRoleTokenType owns that prefix in the registry. K8s tokens reach
		// LookupTransparentTokenWithRole via performImplicitAuth's mount-type
		// dispatch, not via prefix-based DetectType.
		Description:    "Kubernetes ServiceAccount token validated via TokenReview, bound to a role",
		DefaultTTL:     1 * time.Hour,
		AuthMethodType: "kubernetes",
	}
}

func (t *KubernetesRoleTokenType) Generate(_ context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	// K8s SA tokens come from the workload (just like generic JWTs); Warden
	// does not mint them. We store a hash of (mountAccessor, JWT, role)
	// rather than the raw JWT for:
	// - Security: SA tokens may carry sensitive bound-claim information.
	// - ID computation: ComputeID() uses this to derive the token ID.
	// - Mount isolation: cache entries cannot collide across mounts.
	if authData == nil {
		return entry.Data, nil
	}
	jwt := authData.TokenValue
	if jwt == "" {
		return entry.Data, nil
	}
	entry.Data["jwt"] = t.LookupValue(jwt, authData.MountAccessor, authData.RoleName)
	return entry.Data, nil
}

func (t *KubernetesRoleTokenType) ValidateValue(tokenValue string) bool {
	// Same JWT shape check as JWTRoleTokenType — three base64url segments
	// separated by dots, starting with the standard JWT header prefix.
	if !strings.HasPrefix(tokenValue, "eyJ") {
		return false
	}
	parts := strings.Split(tokenValue, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && len(parts[2]) > 0
}

func (t *KubernetesRoleTokenType) ComputeID(lookupValue string) string {
	h := sha256.New()
	h.Write([]byte(lookupValue))
	hash := hex.EncodeToString(h.Sum(nil))[:32]
	return t.Metadata().IDPrefix + hash
}

func (t *KubernetesRoleTokenType) LookupKey() string {
	return "jwt"
}

// LookupValue computes the SHA-256 hash of (mountAccessor, jwt, role) that
// ComputeID hashes into the byID-cache key. Same shape as
// JWTRoleTokenType.LookupValue and CertRoleTokenType.LookupValue.
func (t *KubernetesRoleTokenType) LookupValue(jwt, mountAccessor, role string) string {
	h := sha256.Sum256([]byte(mountAccessor + ":" + jwt + ":" + role))
	return hex.EncodeToString(h[:])
}

// IsTransparent always returns true; opts KubernetesRoleTokenType into the
// transparent-auth family behaviors (cache-only persistence, the
// explicit-login guard, the "transparent" display alias, deterministic-ID
// collision handling) via the registry.
func (t *KubernetesRoleTokenType) IsTransparent() bool { return true }

// CredentialFormat reports "k8s_sa_jwt" — same wire shape as a generic JWT
// (Authorization: Bearer eyJ...), but a distinct discovery-level kind so
// the introspect aggregator only fans K8s SA tokens out to kubernetes
// mounts (avoiding TokenReview round-trips against spokes that cannot
// authenticate the token). performImplicitAuth groups "jwt" and
// "k8s_sa_jwt" into a shared extraction case since the wire-level parse
// is identical.
func (t *KubernetesRoleTokenType) CredentialFormat() string { return "k8s_sa_jwt" }

var _ TransparentTokenType = (*KubernetesRoleTokenType)(nil)
