package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsec2query "github.com/aws/aws-sdk-go-v2/aws/protocol/ec2query"
	awsxml "github.com/aws/aws-sdk-go-v2/aws/protocol/xml"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/traits"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/aws/smithy-go/transport/http/protocol/awsjson"
	"github.com/aws/smithy-go/transport/http/protocol/ec2query"
	"github.com/aws/smithy-go/transport/http/protocol/restjson1"
	"github.com/aws/smithy-go/transport/http/protocol/restxml"
	"github.com/aws/smithy-go/transport/http/protocol/rpcv2"
	"github.com/hashicorp/go-multierror"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests put the rendered errors in front of the real AWS SDK clients:
// each client signs a real request, the renderer answers it as the gateway
// would, and the client's own deserializer and retryer must read the error
// Warden meant — code, message, status and request id — and retry it exactly
// when it should.

// renderingGateway answers every request with the renderer's rendering of the
// failure currently set, counting attempts.
type renderingGateway struct {
	*httptest.Server
	failure  atomic.Pointer[logical.GatewayFailure]
	attempts atomic.Int32
}

func newRenderingGateway(t *testing.T) *renderingGateway {
	t.Helper()
	g := &renderingGateway{}
	b := &awsBackend{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.attempts.Add(1)
		f := *g.failure.Load()
		resp := b.RenderGatewayError(&logical.Request{HTTPRequest: r}, &f)
		if resp == nil {
			http.Error(w, "the renderer declined", http.StatusTeapot)
			return
		}
		// What the HTTP layer does with a rendered response.
		for k, vs := range resp.Headers {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(resp.Body)
	}))
	t.Cleanup(g.Close)
	return g
}

// sdkConfig is a client config aimed at url, as an agent configures its SDK for
// the gateway, with a retryer that retries at once so retries can be counted.
func sdkConfig(url string) aws.Config {
	return aws.Config{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(url),
		Credentials:  credentials.NewStaticCredentialsProvider("my-role", "eyJhbGciOiJSUzI1NiJ9.e30.sig", "eyJhbGciOiJSUzI1NiJ9.e30.sig"),
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = 3
				o.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
				o.RateLimiter = ratelimit.None
			})
		},
	}
}

// realSTSError has a real STS client receive an STS error response and
// returns the error it produces — the exact chain a driver wraps when a mint
// fails upstream.
func realSTSError(t *testing.T, status int, code, message string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.Header().Set("X-Amzn-RequestId", "sts-request-id")
		w.WriteHeader(status)
		fmt.Fprintf(w, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error>
  <RequestId>sts-request-id</RequestId>
</ErrorResponse>`, code, message)
	}))
	defer srv.Close()

	client := sts.New(sts.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(srv.URL),
		RetryMaxAttempts: 1,
	})
	_, err := client.AssumeRoleWithWebIdentity(context.Background(), &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String("arn:aws:iam::123456789012:role/orders"),
		RoleSessionName:  aws.String("s"),
		WebIdentityToken: aws.String("jwt"),
	})
	require.Error(t, err)
	return err
}

// sdkFailure is a failure the gateway renders, and what every client must make
// of it.
type sdkFailure struct {
	name    string
	failure logical.GatewayFailure
	status  int
	codes   errorCodes
	message string
	retried bool
}

func sdkFailures(t *testing.T) []sdkFailure {
	same := func(code string) errorCodes { return errorCodes{code, code, code, code} }
	mint := func(cause error) logical.GatewayFailure {
		return *mintFailure(cause)
	}
	return []sdkFailure{
		{
			name:    "authentication",
			failure: logical.GatewayFailure{Class: logical.GatewayFailureAuth, Status: 401, Err: logical.ErrUnauthorized("authentication failed")},
			status:  403, codes: codesAuth, message: "Warden: authentication failed",
		},
		{
			name:    "policy denial",
			failure: logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403, Err: multierror.Append(nil, sdklogical.ErrPermissionDenied)},
			status:  403, codes: codesDenied, message: "Warden: permission denied",
		},
		{
			name:    "bad request",
			failure: logical.GatewayFailure{Class: logical.GatewayFailureBadRequest, Status: 400, Err: logical.ErrBadRequest("no credential spec bound")},
			status:  400, codes: codesBadRequest, message: "Warden: no credential spec bound",
		},
		{
			name:    "mint refused by STS",
			failure: mint(realSTSError(t, 403, "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")),
			status:  403, codes: same("AccessDenied"),
			message: "Warden: could not obtain AWS credentials: Not authorized to perform sts:AssumeRoleWithWebIdentity",
		},
		{
			name:    "mint throttled by STS",
			failure: mint(realSTSError(t, 400, "Throttling", "Rate exceeded")),
			status:  400, codes: same("Throttling"),
			message: "Warden: could not obtain AWS credentials: Rate exceeded",
			retried: true,
		},
		{
			name:    "mint failure on Warden's side",
			failure: mint(errors.New("the OIDC issuer is not enabled/ready")),
			status:  500, codes: codesInternal,
			retried: true,
		},
		{
			name:    "unavailable",
			failure: logical.GatewayFailure{Class: logical.GatewayFailureUnavailable, Status: 503, Err: logical.ErrServiceUnavailable("sealed")},
			status:  503, codes: codesUnavailable, message: "Warden: sealed",
			retried: true,
		},
	}
}

func TestRenderedErrors_RealSDKClients(t *testing.T) {
	g := newRenderingGateway(t)
	cfg := sdkConfig(g.URL)
	ctx := context.Background()

	stsClient := sts.NewFromConfig(cfg)
	iamClient := iam.NewFromConfig(cfg)
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = true })
	smClient := secretsmanager.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)
	oidcClient := ssooidc.NewFromConfig(cfg)

	clients := []struct {
		name string
		call func() error
		// code picks the family's code; nil means the response has no body
		// and the client derives the code from the status.
		code func(errorCodes) string
	}{
		{"sts (awsQuery)", func() error { _, err := stsClient.GetCallerIdentity(ctx, nil); return err },
			func(c errorCodes) string { return c.query }},
		{"iam (awsQuery)", func() error { _, err := iamClient.ListUsers(ctx, nil); return err },
			func(c errorCodes) string { return c.query }},
		{"s3 (restXml)", func() error { _, err := s3Client.ListBuckets(ctx, nil); return err },
			func(c errorCodes) string { return c.s3 }},
		{"s3 HEAD (no body)", func() error {
			_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String("my-bucket")})
			return err
		}, nil},
		{"secretsmanager (awsJson 1.1)", func() error { _, err := smClient.ListSecrets(ctx, nil); return err },
			func(c errorCodes) string { return c.json }},
		{"kms (awsJson 1.1)", func() error { _, err := kmsClient.ListKeys(ctx, nil); return err },
			func(c errorCodes) string { return c.json }},
		{"ssooidc (restJson1)", func() error {
			_, err := oidcClient.CreateTokenWithIAM(ctx, &ssooidc.CreateTokenWithIAMInput{
				ClientId: aws.String("client"), GrantType: aws.String("urn:ietf:params:oauth:grant-type:jwt-bearer"),
			})
			return err
		}, func(c errorCodes) string { return c.json }},
	}

	for _, f := range sdkFailures(t) {
		for i, c := range clients {
			t.Run(f.name+"/"+c.name, func(t *testing.T) {
				failure := f.failure
				failure.RequestID = fmt.Sprintf("rid-%d", i)
				g.failure.Store(&failure)
				g.attempts.Store(0)

				err := c.call()
				require.Error(t, err)

				var apiErr smithy.APIError
				require.ErrorAs(t, err, &apiErr, "the client must parse the body: %v", err)
				retried := f.retried
				if c.code != nil {
					assert.Equal(t, c.code(f.codes), apiErr.ErrorCode())
					// ssooidc models AccessDeniedException OAuth-style, reading
					// only error/error_description/reason, so no message member
					// ever reaches it — from AWS or from Warden.
					var oauthDenied *oidctypes.AccessDeniedException
					switch {
					case errors.As(err, &oauthDenied):
					case f.message != "":
						assert.Equal(t, f.message, apiErr.ErrorMessage())
					default:
						assert.True(t, strings.HasPrefix(apiErr.ErrorMessage(), "Warden: "), apiErr.ErrorMessage())
					}
				} else {
					// A HEAD response has no body, so the client knows only the
					// status: it derives the code from it, and retries by it alone
					// — a passed-through 400 Throttling is not retried here, just
					// as S3's own bodiless 4xx errors are not.
					assert.Equal(t, strings.ReplaceAll(http.StatusText(f.status), " ", ""), apiErr.ErrorCode())
					retried = f.status >= 500
				}

				var respErr *awshttp.ResponseError
				require.ErrorAs(t, err, &respErr)
				assert.Equal(t, f.status, respErr.HTTPStatusCode())
				assert.Equal(t, failure.RequestID, respErr.ServiceRequestID())

				wantAttempts := int32(1)
				if retried {
					wantAttempts = 3
				}
				assert.Equal(t, wantAttempts, g.attempts.Load(), "retried: %v", retried)
			})
		}
	}

	t.Run("unsigned requests are declined", func(t *testing.T) {
		g.failure.Store(&logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403})
		resp, err := http.Get(g.URL)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	})
}

// renderFor renders failure for a request carrying headers, as a response the
// SDK's deserializers take.
func renderFor(t *testing.T, service string, headers map[string]string, failure logical.GatewayFailure) *smithyhttp.Response {
	t.Helper()
	r := gatewayRequest(http.MethodPost, "", service, headers)
	failure.RequestID = "rid"
	resp := (&awsBackend{}).RenderGatewayError(&logical.Request{HTTPRequest: r}, &failure)
	require.NotNil(t, resp)
	return &smithyhttp.Response{Response: &http.Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Headers,
		Body:       io.NopCloser(bytes.NewReader(resp.Body)),
	}}
}

var deniedFailure = logical.GatewayFailure{
	Class: logical.GatewayFailureDenied, Status: 403, Err: sdklogical.ErrPermissionDenied,
}

// Protocols with no client in this module are checked against the SDK's own
// protocol deserializers: the helpers generated clients call today, and
// smithy-go's protocol implementations.
func TestRenderedErrors_SDKProtocolDeserializers(t *testing.T) {
	ctx := context.Background()
	service := func(name string, ts ...smithy.Trait) *smithy.ServiceSchema {
		return smithy.NewServiceSchema(smithy.NewSchema(
			smithy.ShapeID{Namespace: "com.amazonaws." + name, Name: name}, smithy.ShapeTypeService, 0, ts...), "")
	}
	form := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	t.Run("ec2Query", func(t *testing.T) {
		comps, err := awsec2query.GetErrorResponseComponents(renderFor(t, "ec2", form, deniedFailure).Body)
		require.NoError(t, err)
		assert.Equal(t, "UnauthorizedOperation", comps.Code)
		assert.Equal(t, "Warden: permission denied", comps.Message)
		assert.Equal(t, "rid", comps.RequestID)

		err = ec2query.New(service("ec2")).DeserializeResponse(ctx, nil, &smithy.TypeRegistry{},
			renderFor(t, "ec2", form, deniedFailure), nil)
		assertAPIError(t, err, "UnauthorizedOperation", "Warden: permission denied")
	})

	for _, tc := range []struct {
		name, service string
		headers       map[string]string
	}{
		{"restXml wrapped: route53", "route53", nil},
		{"restXml wrapped: cloudfront", "cloudfront", nil},
		{"restXml wrapped: s3 control", "s3", map[string]string{"X-Amz-Account-Id": "123456789012"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			comps, err := awsxml.GetErrorResponseComponents(renderFor(t, tc.service, tc.headers, deniedFailure).Body, false)
			require.NoError(t, err)
			assert.Equal(t, "AccessDenied", comps.Code)
			assert.Equal(t, "Warden: permission denied", comps.Message)
			assert.Equal(t, "rid", comps.RequestID)

			err = restxml.New(service(tc.service)).DeserializeResponse(ctx, nil, &smithy.TypeRegistry{},
				renderFor(t, tc.service, tc.headers, deniedFailure), nil)
			assertAPIError(t, err, "AccessDenied", "Warden: permission denied")
		})
	}

	t.Run("restJson1", func(t *testing.T) {
		err := restjson1.New(service("lambda")).DeserializeResponse(ctx, nil, &smithy.TypeRegistry{},
			renderFor(t, "lambda", map[string]string{"Content-Type": "application/json"}, deniedFailure), nil)
		assertAPIError(t, err, "AccessDeniedException", "Warden: permission denied")
	})

	t.Run("awsJson 1.0", func(t *testing.T) {
		headers := map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables", "Content-Type": "application/x-amz-json-1.0"}
		resp := renderFor(t, "dynamodb", headers, deniedFailure)
		assert.Equal(t, "application/x-amz-json-1.0", resp.Header.Get("Content-Type"))
		err := awsjson.New10(service("dynamodb")).DeserializeResponse(ctx, nil, &smithy.TypeRegistry{}, resp, nil)
		assertAPIError(t, err, "AccessDeniedException", "Warden: permission denied")
	})

	cbor := map[string]string{"Smithy-Protocol": "rpc-v2-cbor", "Content-Type": "application/cbor"}
	t.Run("rpc-v2-cbor", func(t *testing.T) {
		err := rpcv2.NewCBOR(service("monitoring")).DeserializeResponse(ctx, nil, &smithy.TypeRegistry{},
			renderFor(t, "monitoring", cbor, deniedFailure), nil)
		assertAPIError(t, err, "AccessDeniedException", "Warden: permission denied")
	})

	t.Run("rpc-v2-cbor, query-compatible", func(t *testing.T) {
		headers := map[string]string{"Smithy-Protocol": "rpc-v2-cbor", "X-Amzn-Query-Mode": "true"}
		err := rpcv2.NewCBOR(service("monitoring", &traits.AWSQueryCompatible{})).DeserializeResponse(ctx, nil,
			&smithy.TypeRegistry{}, renderFor(t, "monitoring", headers, deniedFailure), nil)
		assertAPIError(t, err, "AccessDenied", "Warden: permission denied")
		var apiErr smithy.APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, smithy.FaultClient, apiErr.ErrorFault())
	})
}

func assertAPIError(t *testing.T, err error, code, message string) {
	t.Helper()
	var apiErr smithy.APIError
	require.ErrorAs(t, err, &apiErr, "the deserializer must parse the body: %v", err)
	assert.Equal(t, code, apiErr.ErrorCode())
	assert.Equal(t, message, apiErr.ErrorMessage())
}
