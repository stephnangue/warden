//go:build e2e

package fullchain

import (
	"encoding/base64"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// github and gitlab are the two providers whose credential extractor is selected
// per request rather than per mount: git smart-HTTP paths get a Basic credential
// built for git, and every other path falls back to the mount's REST extractor.
// github is the one the seed set carries; gitlab's REST leg is equally untested
// end to end and belongs with the rest of that provider's coverage.
//
// e2e/githttp covers github's git half in depth — passthrough, minting,
// attribution, the placeholder-password rule and a real clone — but every one of
// those drives a smart-HTTP path, so the REST half of the same mount has never
// been driven end to end.
//
// It is also the only member of the seed set using TypedTokenExtractor, the one
// shared SDK extractor shape the other providers do not reach.

const githubPAT = "fc-github-not-a-real-token"

var githubEnv = h.ProviderEnv{
	Mount:    "fc-github",
	Type:     "github",
	URLKey:   "github_url",
	CredType: "github_token",
	// A local source carries the token statically and mints nothing, so only
	// the field the credential needs is set. mint_method would be required of a
	// real github source and is not consulted here — the local driver would
	// simply copy it into the minted credential as a stray field.
	CredConfig: map[string]string{"token": githubPAT},
}

// TestGitHub_RESTLegInjectsTokenScheme drives a REST path and pins two things at
// once: the credential shape, and that the request took the REST branch at all.
//
// Nothing positively selects that branch — the git dispatch declines a path it
// does not recognise and the mount-level extractor applies by fallback — so the
// evidence is circumstantial and needs two independent signals:
//
//   - the scheme. REST authenticates with "token <pat>" where the git leg on
//     this same mount sends Basic base64("x-access-token:<pat>"), so a misfiring
//     dispatch would carry the same secret in a visibly different form.
//   - the REST-only headers. The git dispatch suppresses the default Accept and
//     the dynamic headers, so their presence is a signal the credential scheme
//     cannot give on its own. X-GitHub-Api-Version is also the only end-to-end
//     coverage of DynamicHeaders in this suite.
func TestGitHub_RESTLegInjectsTokenScheme(t *testing.T) {
	ensureEnv(t)

	probe := h.ProbePath("github-rest")
	status, body, _ := h.ChainRequest(t, leaderPort, githubEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         githubEnv.CertRole(),
		Path:         probe,
		Headers:      h.InertDecoyHeaders(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		Injected: map[string]string{
			"Authorization":        "token " + githubPAT,
			"Accept":               "application/vnd.github+json",
			"X-GitHub-Api-Version": "2022-11-28",
		},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	// The user is resolved by the same function the git leg uses, here through
	// its Bearer branch rather than the Basic-password one — the dispatch
	// changes which credential goes out, not who the request is for.
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// TestGitHub_RESTLegAcceptsUserInBasicPassword covers the other slot the user can
// arrive in. github resolves the second principal through the same helper on
// every path, and that helper accepts either a Bearer token or a JWT-shaped HTTP
// Basic password — the latter existing because git can only send credentials that
// way.
//
// Nothing exercises that slot on a REST path: e2e/githttp drives it only on
// smart-HTTP paths, and the test above supplies a Bearer. The two differ in both
// the path shape and the credential the upstream receives, so this duplicates
// neither.
//
// The Basic username is the agent's role, which is how a git client selects one
// with no configuration beyond the clone URL. The certificate is what actually
// authenticates the agent.
func TestGitHub_RESTLegAcceptsUserInBasicPassword(t *testing.T) {
	ensureEnv(t)

	userJWT := h.FullChainUserJWT(t)
	basic := base64.StdEncoding.EncodeToString([]byte(githubEnv.CertRole() + ":" + userJWT))

	probe := h.ProbePath("github-rest-basic-user")
	status, body, _ := h.ChainRequest(t, leaderPort, githubEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		RawAuthz:     "Basic " + basic,
		Role:         githubEnv.CertRole(),
		Path:         probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "token " + githubPAT},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}
