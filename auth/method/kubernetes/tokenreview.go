package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/helper/httputil"
)

// TokenReview request/response shapes from authentication.k8s.io/v1.
// Locally typed rather than importing k8s.io/api to keep the dependency
// surface small — TokenReview is a stable, narrow API and the four
// structs below are all we need to (de)serialize.
type tokenReviewRequest struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       tokenReviewSpec `json:"spec"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type tokenReviewResponse struct {
	Status tokenReviewStatus `json:"status"`
}

type tokenReviewStatus struct {
	Authenticated bool            `json:"authenticated"`
	User          tokenReviewUser `json:"user,omitempty"`
	Audiences     []string        `json:"audiences,omitempty"`
	Error         string          `json:"error,omitempty"`
}

type tokenReviewUser struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups,omitempty"`
}

const (
	tokenReviewPath  = "/apis/authentication.k8s.io/v1/tokenreviews"
	tokenReviewKind  = "TokenReview"
	tokenReviewAPIv1 = "authentication.k8s.io/v1"

	// defaultHTTPTimeout caps each TokenReview round-trip. Generous enough
	// to tolerate a cold apiserver but short enough that a workload's
	// login latency stays bounded.
	defaultHTTPTimeout = 10 * time.Second
)

// reviewToken POSTs a TokenReview to the kube-apiserver and returns the
// authenticated status. Uses bearerJWT as the Authorization header —
// when the operator configured token_reviewer_jwt this is that
// hub-side service account token (standard Vault path); otherwise it
// is the workload's own JWT (self-reviewing mode, requires the
// workload SA to have system:auth-delegator).
//
// audiences is passed through to spec.audiences; if non-empty, the
// kube-apiserver rejects the review if the token's natural audiences
// do not include all requested values. For login, callers pass the
// role's required audience; for introspection, callers pass nil to
// learn the token's natural audiences from the response.
func reviewToken(
	ctx context.Context,
	client *http.Client,
	kubernetesHost string,
	bearerJWT string,
	workloadJWT string,
	audiences []string,
) (*tokenReviewStatus, error) {
	body, err := json.Marshal(tokenReviewRequest{
		APIVersion: tokenReviewAPIv1,
		Kind:       tokenReviewKind,
		Spec: tokenReviewSpec{
			Token:     workloadJWT,
			Audiences: audiences,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tokenreview request: %w", err)
	}

	req := httputil.HTTPRequest{
		Method: http.MethodPost,
		URL:    kubernetesHost + tokenReviewPath,
		Body:   body,
		Headers: map[string]string{
			"Authorization": "Bearer " + bearerJWT,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
		// TokenReview returns 201 Created on success in some apiserver
		// versions, 200 OK in others — both signal a valid review.
		OKStatuses: []int{http.StatusOK, http.StatusCreated},
	}

	retry := httputil.DefaultHTTPRetryConfig()
	// Retry on transient apiserver 5xx errors in addition to the default
	// 429 (rate limit). 5xx during auth typically means the apiserver is
	// briefly unavailable — retrying is the right call.
	retry.RetryableStatuses = []int{http.StatusTooManyRequests, 500}

	respBody, status, err := httputil.ExecuteWithRetry(ctx, client, req, retry)
	if err != nil {
		return nil, fmt.Errorf("tokenreview call to %s failed (status %d): %w", kubernetesHost, status, err)
	}

	var resp tokenReviewResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal tokenreview response: %w", err)
	}
	return &resp.Status, nil
}
