package github

import (
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/provider/sdk/githttp"
)

// Git smart-HTTP support: the github provider mount carries two protocols
// at once. REST paths (/repos, /user, /orgs, ...) proxy to api.github.com
// with a Bearer token. Git smart-HTTP paths (<owner>/<repo>.git/info/refs,
// .git/git-upload-pack, .git/git-receive-pack) proxy to github.com with
// HTTP Basic Auth carrying the PAT as the password.
//
// All git-protocol scaffolding lives in provider/sdk/githttp; this file
// holds only the GitHub-specific URL derivation and the wiring that binds
// that derivation plus the GitHub credential type into the shared hooks.

// deriveGitURL derives the Git host URL from the configured REST API URL.
//
//	https://api.github.com           -> https://github.com
//	https://ghe.example.com/api/v3   -> https://ghe.example.com
//	(GHE host that does not match)   -> input with /api/v3 suffix stripped
//
// Trailing slashes on the input are tolerated.
func deriveGitURL(apiURL string) string {
	apiURL = strings.TrimRight(apiURL, "/")
	if apiURL == "https://api.github.com" || apiURL == "http://api.github.com" {
		return strings.Replace(apiURL, "://api.github.com", "://github.com", 1)
	}
	if strings.HasSuffix(apiURL, "/api/v3") {
		return strings.TrimSuffix(apiURL, "/api/v3")
	}
	return apiURL
}

// gitHooks bundles the three ProviderSpec hooks the mount wires for git
// smart-HTTP. The shared githttp SDK provides the dispatch, credential
// formatting (Basic x-access-token:<PAT>), role extraction from the Basic
// Auth username, and the unauthenticated-probe gate; this provider supplies
// only the host-specific URL derivation and credential type.
var gitHooks = githttp.BuildHooks(githttp.Options{
	BasicAuthUsername: "x-access-token",
	CredentialType:    credential.TypeGitHubToken,
	TokenField:        "token",
	DeriveGitURL:      deriveGitURL,
})
