package aws

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithycbor "github.com/aws/smithy-go/encoding/cbor"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/go-multierror"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sigV4Auth is an Authorization header signed for service.
func sigV4Auth(service string) string {
	return "AWS4-HMAC-SHA256 Credential=my-role/20260923/us-east-1/" + service +
		"/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123"
}

func gatewayRequest(method, target, service string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, "/v1/aws/gateway"+target, nil)
	r.Header.Set("Authorization", sigV4Auth(service))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestInferProtocol(t *testing.T) {
	const (
		form   = "application/x-www-form-urlencoded"
		json11 = "application/x-amz-json-1.1"
		json10 = "application/x-amz-json-1.0"
	)
	for _, tc := range []struct {
		name            string
		method, target  string
		service         string
		headers         map[string]string
		want            awsProtocol
		wantContentType string
		wantQueryCompat bool
	}{
		{name: "awsQuery form post", method: "POST", service: "sts",
			headers: map[string]string{"Content-Type": form}, want: protocolQuery},
		{name: "awsQuery form post with charset", method: "POST", service: "iam",
			headers: map[string]string{"Content-Type": "Application/X-WWW-Form-Urlencoded; charset=utf-8"}, want: protocolQuery},
		{name: "awsQuery GET with Action", method: "GET", target: "?Action=GetCallerIdentity&Version=2011-06-15",
			service: "sts", want: protocolQuery},
		{name: "ec2Query", method: "POST", service: "ec2",
			headers: map[string]string{"Content-Type": form}, want: protocolEC2Query},
		{name: "ec2Query GET with Action", method: "GET", target: "?Action=DescribeRegions", service: "ec2",
			want: protocolEC2Query},
		{name: "awsJson 1.1", method: "POST", service: "secretsmanager",
			headers: map[string]string{"X-Amz-Target": "secretsmanager.ListSecrets", "Content-Type": json11},
			want:    protocolAWSJSON, wantContentType: json11},
		{name: "awsJson 1.0 echoed", method: "POST", service: "dynamodb",
			headers: map[string]string{"X-Amz-Target": "DynamoDB_20120810.ListTables", "Content-Type": json10},
			want:    protocolAWSJSON, wantContentType: json10},
		{name: "awsJson by target alone", method: "POST", service: "kms",
			headers: map[string]string{"X-Amz-Target": "TrentService.ListKeys"},
			want:    protocolAWSJSON, wantContentType: json11},
		{name: "awsJson by content type alone", method: "POST", service: "kms",
			headers: map[string]string{"Content-Type": json11},
			want:    protocolAWSJSON, wantContentType: json11},
		{name: "awsJson query-compatible", method: "POST", service: "sqs",
			headers: map[string]string{"X-Amz-Target": "AmazonSQS.ListQueues", "Content-Type": json10, "X-Amzn-Query-Mode": "true"},
			want:    protocolAWSJSON, wantContentType: json10, wantQueryCompat: true},
		{name: "rpc-v2-cbor", method: "POST", target: "/service/GraniteServiceVersion20100801/operation/ListMetrics",
			service: "monitoring",
			headers: map[string]string{"Smithy-Protocol": "rpc-v2-cbor", "Content-Type": "application/cbor"},
			want:    protocolCBOR},
		{name: "rpc-v2-cbor query-compatible", method: "POST", service: "monitoring",
			headers: map[string]string{"Smithy-Protocol": "rpc-v2-cbor", "X-Amzn-Query-Mode": "true"},
			want:    protocolCBOR, wantQueryCompat: true},
		{name: "query mode is meaningless to awsQuery itself", method: "POST", service: "sts",
			headers: map[string]string{"Content-Type": form, "X-Amzn-Query-Mode": "true"}, want: protocolQuery},
		{name: "s3", method: "GET", target: "/my-bucket?list-type=2", service: "s3", want: protocolS3},
		// An object upload carries whatever Content-Type its caller chose.
		{name: "s3 upload with a form content type", method: "PUT", target: "/my-bucket/k", service: "s3",
			headers: map[string]string{"Content-Type": form}, want: protocolS3},
		{name: "s3 upload with an awsJson content type", method: "PUT", target: "/my-bucket/k", service: "s3",
			headers: map[string]string{"Content-Type": json11}, want: protocolS3},
		{name: "s3express", method: "GET", target: "/b--usw2-az1--x-s3?session", service: "s3express", want: protocolS3},
		{name: "s3-object-lambda", method: "GET", target: "/k", service: "s3-object-lambda", want: protocolS3},
		// S3 Control signs as s3; its account-id header tells it apart.
		{name: "s3 control", method: "GET", target: "/v20180820/tags/arn", service: "s3",
			headers: map[string]string{"X-Amz-Account-Id": "123456789012"}, want: protocolRestXML},
		{name: "s3-control signing name", method: "GET", target: "/v20180820/jobs", service: "s3-control",
			want: protocolRestXML},
		{name: "route53", method: "GET", target: "/2013-04-01/hostedzone", service: "route53", want: protocolRestXML},
		{name: "cloudfront", method: "GET", target: "/2020-05-31/distribution", service: "cloudfront", want: protocolRestXML},
		{name: "restJson1 GET", method: "GET", target: "/2015-03-31/functions/", service: "lambda", want: protocolRestJSON},
		{name: "restJson1 POST", method: "POST", target: "/token", service: "sso-oauth",
			headers: map[string]string{"Content-Type": "application/json"}, want: protocolRestJSON},
		{name: "GET without Action is REST", method: "GET", target: "/?Version=2011-06-15", service: "sts",
			want: protocolRestJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := inferProtocol(gatewayRequest(tc.method, tc.target, tc.service, tc.headers))
			assert.Equal(t, tc.want, got.protocol)
			assert.Equal(t, tc.service, got.service)
			assert.Equal(t, tc.wantContentType, got.contentType)
			assert.Equal(t, tc.wantQueryCompat, got.queryCompatible)
		})
	}

	t.Run("unparseable authorization", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/v1/aws/gateway/", nil)
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 garbage")
		got := inferProtocol(r)
		assert.Equal(t, protocolRestJSON, got.protocol)
		assert.Empty(t, got.service)
	})
}

// sdkAPIError is an error shaped exactly as an AWS SDK client returns one for
// an error response: an OperationError around an HTTP ResponseError around the
// API error.
func sdkAPIError(status int, code, message string) error {
	return &smithy.OperationError{
		ServiceID:     "STS",
		OperationName: "AssumeRoleWithWebIdentity",
		Err: &awshttp.ResponseError{
			RequestID: "sts-request-id",
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      &smithy.GenericAPIError{Code: code, Message: message},
			},
		},
	}
}

// mintFailure wraps cause the way the driver, the minting service and core do.
func mintFailure(cause error) *logical.GatewayFailure {
	err := &logical.CredentialIssueError{
		Spec: "orders",
		Err: fmt.Errorf("failed to fetch credential: %w",
			fmt.Errorf("STS AssumeRoleWithWebIdentity failed for arn:aws:iam::123456789012:role/orders: %w", cause)),
	}
	return &logical.GatewayFailure{
		Class:     logical.GatewayFailureMint,
		Status:    logical.GetErrorCode(err),
		Err:       err,
		RequestID: "rid",
	}
}

func TestMapGatewayFailure(t *testing.T) {
	same := func(code string) errorCodes { return errorCodes{code, code, code, code} }
	for _, tc := range []struct {
		name        string
		failure     *logical.GatewayFailure
		wantStatus  int
		wantCodes   errorCodes
		wantMessage string
	}{
		{
			name:        "authentication",
			failure:     &logical.GatewayFailure{Class: logical.GatewayFailureAuth, Status: 401, Err: logical.ErrUnauthorized("authentication failed")},
			wantStatus:  403,
			wantCodes:   codesAuth,
			wantMessage: "Warden: authentication failed",
		},
		{
			// Core's shape: the sentinel in a multierror, whose bulleted text is
			// reduced to the message.
			name:        "policy denial",
			failure:     &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403, Err: multierror.Append(nil, sdklogical.ErrPermissionDenied)},
			wantStatus:  403,
			wantCodes:   codesDenied,
			wantMessage: "Warden: permission denied",
		},
		{
			name:        "bad request",
			failure:     &logical.GatewayFailure{Class: logical.GatewayFailureBadRequest, Status: 400, Err: logical.ErrBadRequest("no credential spec bound")},
			wantStatus:  400,
			wantCodes:   codesBadRequest,
			wantMessage: "Warden: no credential spec bound",
		},
		{
			name:        "unavailable",
			failure:     &logical.GatewayFailure{Class: logical.GatewayFailureUnavailable, Status: 503, Err: logical.ErrServiceUnavailable("sealed")},
			wantStatus:  503,
			wantCodes:   codesUnavailable,
			wantMessage: "Warden: sealed",
		},
		{
			name:        "internal",
			failure:     &logical.GatewayFailure{Class: logical.GatewayFailureInternal, Status: 500, Err: errors.New("internal error")},
			wantStatus:  500,
			wantCodes:   codesInternal,
			wantMessage: "Warden: internal error",
		},
		{
			name:        "no error text",
			failure:     &logical.GatewayFailure{Class: logical.GatewayFailureInternal, Status: 500},
			wantStatus:  500,
			wantCodes:   codesInternal,
			wantMessage: "Warden: request failed",
		},
		{
			// The live failure: the role's trust policy refuses the assume-role.
			name:        "mint refused by STS passes through",
			failure:     mintFailure(sdkAPIError(403, "AccessDenied", "Not authorized to perform sts:AssumeRoleWithWebIdentity")),
			wantStatus:  403,
			wantCodes:   same("AccessDenied"),
			wantMessage: "Warden: could not obtain AWS credentials: Not authorized to perform sts:AssumeRoleWithWebIdentity",
		},
		{
			name:        "mint throttled passes through",
			failure:     mintFailure(sdkAPIError(400, "Throttling", "Rate exceeded")),
			wantStatus:  400,
			wantCodes:   same("Throttling"),
			wantMessage: "Warden: could not obtain AWS credentials: Rate exceeded",
		},
		{
			name:        "mint upstream 5xx passes through",
			failure:     mintFailure(sdkAPIError(503, "ServiceUnavailable", "try later")),
			wantStatus:  503,
			wantCodes:   same("ServiceUnavailable"),
			wantMessage: "Warden: could not obtain AWS credentials: try later",
		},
		{
			// STS sends it as a 400, but it is transient.
			name:        "mint IDPCommunicationError becomes retryable",
			failure:     mintFailure(sdkAPIError(400, "IDPCommunicationError", "could not reach the IdP")),
			wantStatus:  503,
			wantCodes:   same("IDPCommunicationError"),
			wantMessage: "Warden: could not obtain AWS credentials: could not reach the IdP",
		},
		{
			name: "mint upstream unreachable",
			failure: mintFailure(&smithy.OperationError{ServiceID: "STS", OperationName: "AssumeRole",
				Err: &smithyhttp.RequestSendError{Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}}),
			wantStatus: 503,
			wantCodes:  codesUnavailable,
		},
		{
			name:       "mint timed out",
			failure:    mintFailure(context.DeadlineExceeded),
			wantStatus: 503,
			wantCodes:  codesUnavailable,
		},
		{
			// A Warden-side failure with no status of its own — the identity
			// issuer not being ready during unseal — is transient: retryable.
			name:        "mint failure on Warden's side",
			failure:     mintFailure(errors.New(`spec "orders" requires warden_identity but the OIDC issuer is not enabled/ready`)),
			wantStatus:  500,
			wantCodes:   codesInternal,
			wantMessage: `Warden: failed to issue credential: failed to fetch credential: STS AssumeRoleWithWebIdentity failed for arn:aws:iam::123456789012:role/orders: spec "orders" requires warden_identity but the OIDC issuer is not enabled/ready`,
		},
		{
			name:       "mint spec fault keeps its 4xx",
			failure:    mintFailure(logical.ErrBadRequest("invalid ttl")),
			wantStatus: 400,
			wantCodes:  codesBadRequest,
		},
		{
			// An API error without the HTTP response carries no status to pass
			// through; it is treated as Warden's own failure.
			name:       "mint API error without a response",
			failure:    mintFailure(&smithy.GenericAPIError{Code: "AccessDenied", Message: "x"}),
			wantStatus: 500,
			wantCodes:  codesInternal,
		},
		{
			name: "mint API error with an empty response",
			failure: mintFailure(&awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{},
				Err:      &smithy.GenericAPIError{Code: "AccessDenied", Message: "x"},
			}}),
			wantStatus: 500,
			wantCodes:  codesInternal,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapGatewayFailure(tc.failure)
			assert.Equal(t, tc.wantStatus, got.status)
			assert.Equal(t, tc.wantCodes, got.codes)
			if tc.wantMessage != "" {
				assert.Equal(t, tc.wantMessage, got.message)
			}
			assert.True(t, strings.HasPrefix(got.message, "Warden: "), "every message is marked as Warden's: %q", got.message)
		})
	}
}

func TestRenderAWSError(t *testing.T) {
	e := awsError{status: 403, codes: codesDenied, message: `Warden: <denied> & "quoted"`}

	t.Run("awsQuery", func(t *testing.T) {
		resp := renderAWSError(awsTarget{protocol: protocolQuery, service: "sts"}, e, "rid-1")
		assert.Equal(t, 403, resp.StatusCode)
		assert.Equal(t, "text/xml", resp.Headers.Get("Content-Type"))
		assert.Equal(t, "rid-1", resp.Headers.Get("X-Amzn-RequestId"))
		var got struct {
			XMLName xml.Name `xml:"ErrorResponse"`
			Type    string   `xml:"Error>Type"`
			Code    string   `xml:"Error>Code"`
			Message string   `xml:"Error>Message"`
			ReqID   string   `xml:"RequestId"`
		}
		require.NoError(t, xml.Unmarshal(resp.Body, &got))
		assert.Equal(t, "Sender", got.Type)
		assert.Equal(t, "AccessDenied", got.Code)
		assert.Equal(t, e.message, got.Message, "escaped on the wire, intact once parsed")
		assert.Equal(t, "rid-1", got.ReqID)
	})

	t.Run("restXml wrapped, a 5xx is the receiver's fault", func(t *testing.T) {
		resp := renderAWSError(awsTarget{protocol: protocolRestXML, service: "route53"},
			awsError{status: 500, codes: codesInternal, message: "Warden: boom"}, "rid")
		assert.Contains(t, string(resp.Body), "<Type>Receiver</Type><Code>InternalFailure</Code>")
	})

	t.Run("ec2Query", func(t *testing.T) {
		resp := renderAWSError(awsTarget{protocol: protocolEC2Query, service: "ec2"}, e, "rid-2")
		assert.Equal(t, "text/xml", resp.Headers.Get("Content-Type"))
		var got struct {
			XMLName xml.Name `xml:"Response"`
			Code    string   `xml:"Errors>Error>Code"`
			Message string   `xml:"Errors>Error>Message"`
			ReqID   string   `xml:"RequestID"`
		}
		require.NoError(t, xml.Unmarshal(resp.Body, &got))
		assert.Equal(t, "UnauthorizedOperation", got.Code)
		assert.Equal(t, e.message, got.Message)
		assert.Equal(t, "rid-2", got.ReqID)
	})

	t.Run("s3", func(t *testing.T) {
		resp := renderAWSError(awsTarget{protocol: protocolS3, service: "s3"}, e, "rid-3")
		assert.Equal(t, "application/xml", resp.Headers.Get("Content-Type"))
		assert.Equal(t, "rid-3", resp.Headers.Get("X-Amz-Request-Id"), "S3 clients read their own request-id header")
		var got struct {
			XMLName xml.Name `xml:"Error"`
			Code    string   `xml:"Code"`
			Message string   `xml:"Message"`
			ReqID   string   `xml:"RequestId"`
		}
		require.NoError(t, xml.Unmarshal(resp.Body, &got))
		assert.Equal(t, "AccessDenied", got.Code)
		assert.Equal(t, e.message, got.Message)
		assert.Equal(t, "rid-3", got.ReqID)
	})

	for _, tc := range []struct {
		name        string
		target      awsTarget
		contentType string
	}{
		{"awsJson", awsTarget{protocol: protocolAWSJSON, service: "kms", contentType: "application/x-amz-json-1.0"}, "application/x-amz-json-1.0"},
		{"restJson1", awsTarget{protocol: protocolRestJSON, service: "lambda"}, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := renderAWSError(tc.target, e, "rid-4")
			assert.Equal(t, tc.contentType, resp.Headers.Get("Content-Type"))
			assert.Equal(t, "AccessDeniedException", resp.Headers.Get("X-Amzn-ErrorType"))
			assert.Equal(t, "rid-4", resp.Headers.Get("X-Amzn-RequestId"))
			assert.Empty(t, resp.Headers.Get("X-Amzn-Query-Error"))
			var got struct {
				Type    string `json:"__type"`
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal(resp.Body, &got))
			assert.Equal(t, "AccessDeniedException", got.Type)
			assert.Equal(t, e.message, got.Message)
		})
	}

	t.Run("rpc-v2-cbor", func(t *testing.T) {
		resp := renderAWSError(awsTarget{protocol: protocolCBOR, service: "monitoring"}, e, "rid-5")
		assert.Equal(t, "application/cbor", resp.Headers.Get("Content-Type"))
		assert.Equal(t, "rpc-v2-cbor", resp.Headers.Get("Smithy-Protocol"))
		v, err := smithycbor.Decode(resp.Body)
		require.NoError(t, err)
		m, ok := v.(smithycbor.Map)
		require.True(t, ok)
		assert.Equal(t, smithycbor.String("com.amazonaws.monitoring#AccessDeniedException"), m["__type"])
		assert.Equal(t, smithycbor.String(e.message), m["message"])
	})

	t.Run("query-compatible JSON also carries the awsQuery code", func(t *testing.T) {
		resp := renderAWSError(awsTarget{protocol: protocolAWSJSON, service: "sqs", contentType: "application/x-amz-json-1.0", queryCompatible: true}, e, "rid")
		assert.Equal(t, "AccessDenied;Sender", resp.Headers.Get("X-Amzn-Query-Error"))
		resp = renderAWSError(awsTarget{protocol: protocolCBOR, service: "monitoring", queryCompatible: true},
			awsError{status: 503, codes: codesUnavailable, message: "Warden: x"}, "rid")
		assert.Equal(t, "ServiceUnavailable;Receiver", resp.Headers.Get("X-Amzn-Query-Error"))
	})

	t.Run("no request id, no request-id header", func(t *testing.T) {
		resp := renderAWSError(awsTarget{protocol: protocolS3, service: "s3"}, e, "")
		assert.Empty(t, resp.Headers.Values("X-Amzn-RequestId"))
		assert.Empty(t, resp.Headers.Values("X-Amz-Request-Id"))
	})
}

func TestRenderGatewayError(t *testing.T) {
	b := &awsBackend{}
	denied := &logical.GatewayFailure{Class: logical.GatewayFailureDenied, Status: 403,
		Err: sdklogical.ErrPermissionDenied, RequestID: "rid"}

	t.Run("SigV4 request is rendered", func(t *testing.T) {
		r := gatewayRequest("POST", "", "sts", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
		resp := b.RenderGatewayError(&logical.Request{HTTPRequest: r}, denied)
		require.NotNil(t, resp)
		assert.Equal(t, 403, resp.StatusCode)
		assert.Contains(t, string(resp.Body), "<Code>AccessDenied</Code>")
		assert.Contains(t, string(resp.Body), "<RequestId>rid</RequestId>", "the failure's request id, not the request's")
	})

	t.Run("declines", func(t *testing.T) {
		bearer := httptest.NewRequest("GET", "/v1/aws/gateway/", nil)
		bearer.Header.Set("Authorization", "Bearer eyJhbGciOi")
		unsigned := httptest.NewRequest("GET", "/v1/aws/gateway/", nil)
		for name, req := range map[string]*logical.Request{
			"bearer token keeps Warden's JSON": {HTTPRequest: bearer},
			"unsigned request":                 {HTTPRequest: unsigned},
			"no HTTP request":                  {},
		} {
			assert.Nil(t, b.RenderGatewayError(req, denied), name)
		}
		assert.Nil(t, b.RenderGatewayError(nil, denied))
		r := gatewayRequest("GET", "", "s3", nil)
		assert.Nil(t, b.RenderGatewayError(&logical.Request{HTTPRequest: r}, nil))
	})
}
