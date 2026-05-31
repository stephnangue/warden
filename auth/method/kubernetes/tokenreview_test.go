package kubernetes

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/helper/httputil"
)

func TestReviewToken_AuthenticatedHappyPath(t *testing.T) {
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{
			Authenticated: true,
			User: tokenReviewUser{
				Username: "system:serviceaccount:default:myapp",
				UID:      "abc-uid",
			},
			Audiences: []string{"https://kubernetes.default.svc"},
		},
	})

	client, err := httputil.BuildHTTPClient(nil, false, 0)
	require.NoError(t, err)

	status, err := reviewToken(context.Background(), client, fake.URL,
		"reviewer-jwt", "workload-jwt", []string{"https://kubernetes.default.svc"})
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, "system:serviceaccount:default:myapp", status.User.Username)
	assert.Equal(t, "abc-uid", status.User.UID)
	assert.Contains(t, fake.AudsSeen, "https://kubernetes.default.svc")
	assert.Equal(t, "workload-jwt", fake.TokenSeen)
	assert.Equal(t, "Bearer reviewer-jwt", fake.BearerSeen,
		"reviewer JWT should be the Authorization bearer when supplied")
}

func TestReviewToken_SelfReviewingMode_UsesWorkloadJWTAsBearer(t *testing.T) {
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{Authenticated: true, User: tokenReviewUser{Username: "system:serviceaccount:default:app"}},
	})
	client, _ := httputil.BuildHTTPClient(nil, false, 0)

	// Caller passes the workload JWT as the bearer (production path
	// sets bearer = workloadJWT when TokenReviewerJWT is empty).
	_, err := reviewToken(context.Background(), client, fake.URL,
		"workload-jwt", "workload-jwt", nil)
	require.NoError(t, err)
	assert.Equal(t, "Bearer workload-jwt", fake.BearerSeen)
}

func TestReviewToken_DeniedTokenIsNotAnError(t *testing.T) {
	// TokenReview returning authenticated=false is a normal response,
	// not an HTTP error. reviewToken must surface it cleanly so the
	// caller can apply errAuthFailed without leaking the spoke's reason.
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{
			Authenticated: false,
			Error:         "token expired",
		},
	})
	client, _ := httputil.BuildHTTPClient(nil, false, 0)

	status, err := reviewToken(context.Background(), client, fake.URL, "bearer", "workload", nil)
	require.NoError(t, err)
	assert.False(t, status.Authenticated)
	assert.Equal(t, "token expired", status.Error)
}

func TestReviewToken_RetriesOn5xxThenSucceeds(t *testing.T) {
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Failures:       2, // 500 twice, then succeed
		FailWithStatus: http.StatusInternalServerError,
		Response:       tokenReviewStatus{Authenticated: true, User: tokenReviewUser{Username: "system:serviceaccount:default:app"}},
	})
	client, _ := httputil.BuildHTTPClient(nil, false, 0)

	status, err := reviewToken(context.Background(), client, fake.URL, "bearer", "workload", nil)
	require.NoError(t, err)
	assert.True(t, status.Authenticated)
	assert.Equal(t, int32(3), fake.Calls, "expected two retries before the third call succeeds")
}

func TestReviewToken_FailsAfterMaxRetries(t *testing.T) {
	// Default retry config is 3 attempts; fake fails 5 times so all attempts fail.
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Failures:       5,
		FailWithStatus: http.StatusInternalServerError,
	})
	client, _ := httputil.BuildHTTPClient(nil, false, 0)

	_, err := reviewToken(context.Background(), client, fake.URL, "bearer", "workload", nil)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "tokenreview call"), "error should mention the call: %v", err)
}

func TestReviewToken_SpecAudiencesArePassedThrough(t *testing.T) {
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{Authenticated: true, User: tokenReviewUser{Username: "system:serviceaccount:default:app"}},
	})
	client, _ := httputil.BuildHTTPClient(nil, false, 0)

	_, err := reviewToken(context.Background(), client, fake.URL, "bearer", "workload", []string{"api", "internal"})
	require.NoError(t, err)
	assert.Equal(t, []string{"api", "internal"}, fake.AudsSeen)
}

func TestReviewToken_NilAudiencesOmittedFromRequest(t *testing.T) {
	// audiences=nil should produce no spec.audiences field (omitempty),
	// which TokenReview interprets as "any audience the token has".
	fake := newFakeAPIServer(t, fakeAPIServerOpts{
		Response: tokenReviewStatus{
			Authenticated: true,
			Audiences:     []string{"https://kubernetes.default.svc"},
			User:          tokenReviewUser{Username: "system:serviceaccount:default:app"},
		},
	})
	client, _ := httputil.BuildHTTPClient(nil, false, 0)

	status, err := reviewToken(context.Background(), client, fake.URL, "bearer", "workload", nil)
	require.NoError(t, err)
	assert.Empty(t, fake.AudsSeen, "no audiences should be sent when nil is passed")
	assert.Equal(t, []string{"https://kubernetes.default.svc"}, status.Audiences,
		"response audiences are the token's natural set")
}
