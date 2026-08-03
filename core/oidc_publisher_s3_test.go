package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestS3Publisher(t *testing.T) {
	seen := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			seen[r.URL.Path] = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := s3.New(s3.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("AKIA", "secret", ""),
		BaseEndpoint: aws.String(srv.URL),
		UsePathStyle: true,
	})
	p := &s3Publisher{client: client, bucket: "warden-oidc", prefix: "prod"}

	require.NoError(t, p.Publish(context.Background(), []byte(`{"issuer":"x"}`), []byte(`{"keys":[]}`)))

	assert.True(t, seen["/warden-oidc/prod/.well-known/openid-configuration"], "discovery object must be PUT")
	assert.True(t, seen["/warden-oidc/prod/oidc/jwks"], "jwks object must be PUT")
}

// --- fake AWS server (IAM/STS query protocol + S3 REST) ---------------------

// fakeAWSState is a stateful stub for the handful of IAM/STS operations rotation uses,
// plus S3 PutObject. IAM/STS speak the AWS query protocol (form-encoded POST, XML reply);
// S3 is a path-style PUT. One server handles all three (BaseEndpoint points them here).
type fakeAWSState struct {
	mu                  sync.Mutex
	existingKeys        []string // returned by ListAccessKeys
	newKeyID            string   // returned by CreateAccessKey
	newSecret           string
	verifyFailRemaining int // GetCallerIdentity failures before success (verify propagation)
	created             []string
	deleted             []string
}

func (s *fakeAWSState) server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut { // S3 upload (path-style /bucket/key)
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
			return
		}
		body, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(body))
		action := vals.Get("Action")

		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "GetCallerIdentity":
			if s.verifyFailRemaining > 0 {
				s.verifyFailRemaining--
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, awsErrorXML("https://sts.amazonaws.com/doc/2011-06-15/", "InvalidClientTokenId"))
				return
			}
			_, _ = io.WriteString(w, getCallerIdentityXML)
		case "ListAccessKeys":
			_, _ = io.WriteString(w, listAccessKeysXML(s.existingKeys))
		case "CreateAccessKey":
			s.created = append(s.created, s.newKeyID)
			s.existingKeys = append(s.existingKeys, s.newKeyID)
			_, _ = io.WriteString(w, createAccessKeyXML(s.newKeyID, s.newSecret))
		case "DeleteAccessKey":
			id := vals.Get("AccessKeyId")
			for i, k := range s.existingKeys {
				if k == id {
					s.existingKeys = append(s.existingKeys[:i], s.existingKeys[i+1:]...)
					break
				}
			}
			s.deleted = append(s.deleted, id)
			_, _ = io.WriteString(w, deleteAccessKeyXML)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

const getCallerIdentityXML = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/warden</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetCallerIdentityResponse>`

const deleteAccessKeyXML = `<DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></DeleteAccessKeyResponse>`

func createAccessKeyXML(id, secret string) string {
	return `<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><CreateAccessKeyResult><AccessKey><UserName>warden</UserName><AccessKeyId>` + id + `</AccessKeyId><Status>Active</Status><SecretAccessKey>` + secret + `</SecretAccessKey><CreateDate>2024-01-01T00:00:00Z</CreateDate></AccessKey></CreateAccessKeyResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></CreateAccessKeyResponse>`
}

func listAccessKeysXML(ids []string) string {
	members := ""
	for _, id := range ids {
		members += `<member><UserName>warden</UserName><AccessKeyId>` + id + `</AccessKeyId><Status>Active</Status><CreateDate>2024-01-01T00:00:00Z</CreateDate></member>`
	}
	return `<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata>` + members + `</AccessKeyMetadata></ListAccessKeysResult><ResponseMetadata><RequestId>r</RequestId></ListAccessKeysResponse>`
}

func awsErrorXML(ns, code string) string {
	return `<ErrorResponse xmlns="` + ns + `"><Error><Type>Sender</Type><Code>` + code + `</Code><Message>msg</Message></Error><RequestId>r</RequestId></ErrorResponse>`
}

func withAWSIAMEndpoint(t *testing.T, url string) {
	t.Helper()
	prev := awsIAMEndpoint
	awsIAMEndpoint = url
	t.Cleanup(func() { awsIAMEndpoint = prev })
}

func withAWSVerifyTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := awsRotationVerifyTimeout
	awsRotationVerifyTimeout = d
	t.Cleanup(func() { awsRotationVerifyTimeout = prev })
}

func newTestS3Publisher(endpoint, ak, sk string) *s3Publisher {
	return &s3Publisher{
		client:          news3Client("us-east-1", endpoint, ak, sk),
		accessKeyID:     ak,
		secretAccessKey: sk,
		region:          "us-east-1",
		endpoint:        endpoint,
		bucket:          "b",
	}
}

// --- mechanism tests --------------------------------------------------------

func TestS3Publisher_SupportsRotation(t *testing.T) {
	assert.True(t, newTestS3Publisher("http://x", "AKIAEXAMPLE", "s").SupportsRotation())
	assert.False(t, newTestS3Publisher("http://x", "ASIATEMPCREDS", "s").SupportsRotation(),
		"STS temp credentials (ASIA) cannot self-rotate")
}

func TestS3Publisher_RotateFullCycle(t *testing.T) {
	st := &fakeAWSState{existingKeys: []string{"AKIAOLD"}, newKeyID: "AKIANEW", newSecret: "newsecret"}
	srv := st.server(t)
	defer srv.Close()
	withAWSIAMEndpoint(t, srv.URL)

	p := newTestS3Publisher(srv.URL, "AKIAOLD", "oldsecret")

	newFields, prevFields, cleanup, err := p.PrepareRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIANEW", newFields["access_key_id"])
	assert.Equal(t, "newsecret", newFields["secret_access_key"])
	assert.Equal(t, "AKIAOLD", prevFields["access_key_id"])
	assert.Equal(t, "AKIAOLD", cleanup["old_access_key_id"])
	assert.Contains(t, st.created, "AKIANEW")

	require.NoError(t, p.CommitRotation(newFields))
	p.mu.RLock()
	assert.Equal(t, "AKIANEW", p.accessKeyID)
	p.mu.RUnlock()

	require.NoError(t, p.CleanupRotation(context.Background(), cleanup))
	assert.Contains(t, st.deleted, "AKIAOLD")
}

func TestS3Publisher_RotateVerifyRetry(t *testing.T) {
	st := &fakeAWSState{existingKeys: []string{"AKIAOLD"}, newKeyID: "AKIANEW", newSecret: "s", verifyFailRemaining: 1}
	srv := st.server(t)
	defer srv.Close()
	withAWSIAMEndpoint(t, srv.URL)

	p := newTestS3Publisher(srv.URL, "AKIAOLD", "oldsecret")
	newFields, _, _, err := p.PrepareRotation(context.Background())
	require.NoError(t, err, "verify must retry past the initial InvalidClientTokenId")
	assert.Equal(t, "AKIANEW", newFields["access_key_id"])
	assert.Empty(t, st.deleted, "a key that verifies after retry must not be deleted")
}

func TestS3Publisher_RotateVerifyFailureDeletesNewKey(t *testing.T) {
	st := &fakeAWSState{existingKeys: []string{"AKIAOLD"}, newKeyID: "AKIANEW", newSecret: "s", verifyFailRemaining: 1 << 30}
	srv := st.server(t)
	defer srv.Close()
	withAWSIAMEndpoint(t, srv.URL)
	withAWSVerifyTimeout(t, 300*time.Millisecond)

	p := newTestS3Publisher(srv.URL, "AKIAOLD", "oldsecret")
	_, _, _, err := p.PrepareRotation(context.Background())
	require.Error(t, err, "an unusable new key must fail rotation")
	assert.Contains(t, st.deleted, "AKIANEW", "the unusable new key must be deleted to protect the 2-key cap")
}

func TestS3Publisher_RotateOrphanPrune(t *testing.T) {
	// Already at the 2-key max (current + an orphan from a prior failed cleanup).
	st := &fakeAWSState{existingKeys: []string{"AKIAOLD", "AKIAORPHAN"}, newKeyID: "AKIANEW", newSecret: "s"}
	srv := st.server(t)
	defer srv.Close()
	withAWSIAMEndpoint(t, srv.URL)

	p := newTestS3Publisher(srv.URL, "AKIAOLD", "oldsecret")
	_, _, _, err := p.PrepareRotation(context.Background())
	require.NoError(t, err)
	assert.Contains(t, st.deleted, "AKIAORPHAN", "the orphan must be pruned before creating a new key")
	assert.NotContains(t, st.deleted, "AKIAOLD", "the current key must not be pruned")
	assert.Contains(t, st.created, "AKIANEW")
}

func TestS3Publisher_RollbackRotation(t *testing.T) {
	st := &fakeAWSState{existingKeys: []string{"AKIAOLD", "AKIANEW"}, newKeyID: "AKIANEW", newSecret: "s"}
	srv := st.server(t)
	defer srv.Close()
	withAWSIAMEndpoint(t, srv.URL)

	p := newTestS3Publisher(srv.URL, "AKIAOLD", "oldsecret")
	require.NoError(t, p.RollbackRotation(context.Background(), map[string]string{"access_key_id": "AKIANEW"}))
	assert.Contains(t, st.deleted, "AKIANEW")
}

// TestS3Publisher_ConcurrentPublishAndCommit exercises the s3Publisher mutex under -race.
func TestS3Publisher_ConcurrentPublishAndCommit(t *testing.T) {
	st := &fakeAWSState{}
	srv := st.server(t)
	defer srv.Close()

	p := newTestS3Publisher(srv.URL, "AKIAK1", "s1")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = p.Publish(context.Background(), []byte(`{}`), []byte(`{}`))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = p.CommitRotation(map[string]string{"access_key_id": "AKIAK2", "secret_access_key": "s2"})
		}
	}()
	wg.Wait()
}
