package profiles

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/stephnangue/warden/credential"
)

// AWSProfileName is the aws profile's name. Permanent, like every profile name.
const AWSProfileName = "aws"

// AWS session-tag contract, as documented by AWS for AssumeRoleWithWebIdentity
// ("Pass session tags in AWS STS" and "Rules for tagging in IAM and AWS STS"). These
// are AWS's limits, not choices: a token exceeding them is refused by STS, so the
// profile refuses to mint it instead, with an error that says why.
const (
	// awsSessionTagsClaim is the namespaced claim AWS reads session tags from, in
	// its nested format: {"principal_tags": {"<key>": ["<value>"]}}.
	awsSessionTagsClaim = "https://aws.amazon.com/tags"
	awsPrincipalTagsKey = "principal_tags"

	// awsRoleTagKey carries the Warden role the principal logged in under.
	awsRoleTagKey = "warden_role"

	awsMaxSessionTags   = 50
	awsMaxTagKeyChars   = 128
	awsMaxTagValueChars = 256
	// awsReservedTagPrefix may begin neither a tag key nor a tag value. Checked
	// case-insensitively: AWS reserves the prefix, and refusing "AWS:" too costs
	// nothing.
	awsReservedTagPrefix = "aws:"

	// awsMaxSubjectChars is the documented maximum length of the subject AWS STS
	// returns for a web identity token (SubjectFromWebIdentityToken).
	awsMaxSubjectChars = 255
)

// AWSProfile shapes the assertion for AWS IAM's AssumeRoleWithWebIdentity.
//
// An IAM trust policy for a self-hosted OIDC issuer can condition on the token's
// sub and aud (plus amr, email and oaud), and on SESSION TAGS carried in the
// https://aws.amazon.com/tags claim — nothing else. The provider-specific claim keys
// AWS maps for GitHub, GitLab.com and others are not available to a custom issuer.
// So every warden_* claim the default profile emits is unreadable to AWS, and the
// facts an operator wants to bind — the role, the projected login metadata — have to
// travel as session tags. This profile puts them there:
//
//   - sub stays the composite "wid:{nsID}:{mountAccessor}:{principalID}", so a
//     StringLike prefix on sub still pins a namespace and auth mount;
//   - the role becomes the "warden_role" session tag, and each projected metadata
//     key becomes a session tag of the same name, so a trust policy conditions on
//     each one independently (aws:RequestTag/<key>), in any order, and adding a key
//     to a spec later breaks no existing condition. The tags then persist on the
//     session as aws:PrincipalTag/<key>, for attribute-based access control in the
//     role's permission policies.
//
// The rule is: emit only what AWS can bind. Every warden_* claim is dropped — the
// ones whose fact now travels in sub or a tag, so no fact crosses the trust boundary
// twice, and warden_resource too. As a claim AWS cannot read it; as a tag it would be
// either tautological (for sts_assume_role it names the very role whose trust policy
// is evaluating the token) or malformed (a templated secret_id is derived unresolved,
// and its braces are not a legal tag value). So an explicit assertion_resource is
// rejected at spec-create — its sole effect is output this profile never renders.
//
// Operators must allow sts:TagSession as well as sts:AssumeRoleWithWebIdentity in the
// role's trust policy; AWS refuses a token carrying tags without it.
//
// THIS SHAPE IS FROZEN once shipped, like every profile's: trust policies bind to it.
// A different AWS shape ships as a new profile name.
type AWSProfile struct{}

var (
	_ credential.AssertionProfile             = (*AWSProfile)(nil)
	_ credential.AssertionProfileSourcePinned = (*AWSProfile)(nil)
)

// Name returns the profile name an operator writes in assertion_profile.
func (AWSProfile) Name() string { return AWSProfileName }

// Typ returns the JOSE typ header.
func (AWSProfile) Typ() string { return "JWT" }

// SourceTypes pins the profile to AWS sources: the shape is meaningful only to an
// AWS STS verifier. The pin is one-directional — an AWS source never requires it.
func (AWSProfile) SourceTypes() []string { return []string{credential.SourceTypeAWS} }

// ValidateSpec checks, at spec-create, everything about the session tags that config
// alone decides: the projected metadata keys become tag keys, so each must be a valid
// AWS tag key, unique ignoring case (AWS treats session-tag keys case-insensitively,
// so "Team" and "team" would overwrite one another), clear of the key the role
// occupies, and few enough that role + metadata stay within AWS's tag count.
//
// It rejects an explicit assertion_resource other than "none": that key's sole effect
// is the warden_resource claim, which this profile never emits. Unset is accepted — it
// means "derive", which is invisible to a config-only check, and the profile simply
// ignores the derived value.
//
// It never rejects assertion_user_claims: this profile does not render warden_user,
// but that key also drives {{user.<claim>}} request templating on AWS specs.
func (AWSProfile) ValidateSpec(config credential.Config) error {
	if r := config.Get(credential.ConfigAssertionResource); r != "" && r != credential.AssertionResourceNone {
		return fmt.Errorf("field '%s': profile '%s' never emits warden_resource, so an explicit resource would have no effect; remove it or set it to '%s'",
			credential.ConfigAssertionResource, AWSProfileName, credential.AssertionResourceNone)
	}

	keys := credential.AssertionMetadataKeys(config)

	// One tag is always reserved for the role.
	if len(keys) > awsMaxSessionTags-1 {
		return fmt.Errorf("field '%s': profile '%s' carries each key as an AWS session tag, and AWS allows at most %d tags, one of which is the role; %d keys is too many",
			credential.ConfigAssertionMetadataClaims, AWSProfileName, awsMaxSessionTags, len(keys))
	}

	seen := map[string]string{strings.ToLower(awsRoleTagKey): awsRoleTagKey}
	for _, k := range keys {
		if err := validateAWSTagText(k, awsMaxTagKeyChars); err != nil {
			return fmt.Errorf("field '%s': key %q is not a valid AWS session tag key: %w",
				credential.ConfigAssertionMetadataClaims, k, err)
		}
		folded := strings.ToLower(k)
		if prior, dup := seen[folded]; dup {
			return fmt.Errorf("field '%s': key %q collides with %q: AWS session tag keys are case-insensitive",
				credential.ConfigAssertionMetadataClaims, k, prior)
		}
		seen[folded] = k
	}
	return nil
}

// Claims renders the AWS claim set.
//
// A role-less identity (a root token) simply gets no warden_role tag, and a
// configured metadata key the login lacks gets no tag either. Neither makes anything
// ambiguous — sub is unchanged — and a trust policy that conditions on the missing
// tag fails closed at AWS, as it should.
//
// It errors, minting nothing, when a metadata VALUE is not a valid AWS tag value (the
// values arrive per login, so unlike the keys they can only be checked here), or when
// sub exceeds the length AWS documents for a web identity subject.
func (AWSProfile) Claims(req credential.AssertionRequest) (map[string]any, error) {
	sub := req.Identity.WardenSubject()
	if n := utf8.RuneCountInString(sub); n > awsMaxSubjectChars {
		return nil, fmt.Errorf("subject is %d characters; AWS accepts a web identity subject of at most %d (the principal ID is likely too long)",
			n, awsMaxSubjectChars)
	}

	tags := make(map[string][]string, len(req.Metadata)+1)
	if req.Identity.RoleName != "" {
		if err := validateAWSTagText(req.Identity.RoleName, awsMaxTagValueChars); err != nil {
			return nil, fmt.Errorf("role %q is not a valid AWS session tag value: %w", req.Identity.RoleName, err)
		}
		tags[awsRoleTagKey] = []string{req.Identity.RoleName}
	}
	for k, v := range req.Metadata {
		// Keys were validated at spec-create; re-checked here because it is cheap
		// and a key that slipped through would otherwise surface as an opaque STS
		// rejection.
		if err := validateAWSTagText(k, awsMaxTagKeyChars); err != nil {
			return nil, fmt.Errorf("metadata key %q is not a valid AWS session tag key: %w", k, err)
		}
		if err := validateAWSTagText(v, awsMaxTagValueChars); err != nil {
			return nil, fmt.Errorf("metadata %q has a value that is not a valid AWS session tag value: %w", k, err)
		}
		tags[k] = []string{v}
	}

	claims := map[string]any{
		"iss": req.Issuer,
		"sub": sub,
		"aud": req.Audience,
		"iat": req.IssuedAt.Unix(),
		"nbf": req.NotBefore.Unix(),
		"exp": req.ExpiresAt.Unix(),
		"jti": req.JTI,
	}
	// No tags, no tags claim: an empty principal_tags object would say nothing and
	// could still make STS demand sts:TagSession.
	if len(tags) > 0 {
		claims[awsSessionTagsClaim] = map[string]any{awsPrincipalTagsKey: tags}
	}
	// req.Resource is deliberately ignored — see the type comment.
	return claims, nil
}

// validateAWSTagText checks s against AWS's tag rules: at most max characters,
// letters, numbers, spaces and _ . : / = + - @ only, and not beginning with the
// reserved "aws:" prefix. An empty string passes — AWS allows an empty tag value —
// so a caller validating a KEY must not pass one (splitClaimKeys never yields one).
func validateAWSTagText(s string, max int) error {
	if n := utf8.RuneCountInString(s); n > max {
		return fmt.Errorf("%d characters exceeds AWS's limit of %d", n, max)
	}
	if strings.HasPrefix(strings.ToLower(s), awsReservedTagPrefix) {
		return fmt.Errorf("the %q prefix is reserved by AWS", awsReservedTagPrefix)
	}
	// AWS's tag pattern is [\p{L}\p{Z}\p{N}_.:/=+\-@]: letters, separators
	// ("spaces"), numbers, and the listed symbols.
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Z, r) || strings.ContainsRune("_.:/=+-@", r) {
			continue
		}
		return fmt.Errorf("character %q is not allowed (AWS permits letters, numbers, spaces and _ . : / = + - @)", r)
	}
	return nil
}
