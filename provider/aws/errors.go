package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"mime"
	"net"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	smithycbor "github.com/aws/smithy-go/encoding/cbor"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/hashicorp/go-multierror"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
)

// Compile-time interface assertion
var _ logical.GatewayErrorRenderer = (*awsBackend)(nil)

// RenderGatewayError answers a gateway request that Warden failed itself —
// authentication, policy, credential issuance — as the AWS service the request
// targets would, so the client's AWS SDK can parse the error, surface its real
// cause, and retry only what is transient. Warden's generic JSON error is
// unreadable to every AWS SDK.
//
// A request that is not SigV4-signed did not come from an AWS SDK, so it keeps
// Warden's JSON error: the renderer declines.
func (b *awsBackend) RenderGatewayError(req *logical.Request, failure *logical.GatewayFailure) *logical.Response {
	if req == nil || req.HTTPRequest == nil || failure == nil || !sigv4.IsSigV4Request(req.HTTPRequest) {
		return nil
	}
	return renderAWSError(inferProtocol(req.HTTPRequest), mapGatewayFailure(failure), failure.RequestID)
}

// awsProtocol is the wire protocol of the AWS service a request targets, which
// fixes the shape an error answer must take for the client's SDK to parse it.
type awsProtocol uint8

const (
	// protocolRestJSON is restJson1, the protocol of most REST services.
	protocolRestJSON awsProtocol = iota
	// protocolAWSJSON is awsJson1_0 or awsJson1_1.
	protocolAWSJSON
	// protocolCBOR is Smithy RPC v2 CBOR.
	protocolCBOR
	// protocolQuery is awsQuery.
	protocolQuery
	// protocolEC2Query is ec2Query, EC2's own variant of awsQuery.
	protocolEC2Query
	// protocolRestXML is restXml with errors wrapped in <ErrorResponse>: S3
	// Control, Route 53 and CloudFront.
	protocolRestXML
	// protocolS3 is S3's restXml, whose errors are an unwrapped <Error>.
	protocolS3
)

// awsTarget is what an error answer needs to know about the service a request
// targets.
type awsTarget struct {
	protocol awsProtocol
	// service is the SigV4 signing name, from the credential scope.
	service string
	// contentType is the awsJson content type the client sent, echoed back.
	contentType string
	// queryCompatible is set when a JSON or CBOR client of a service that moved
	// off awsQuery asks for the awsQuery error code as well.
	queryCompatible bool
}

// s3Services are the signing names whose requests speak S3's protocol.
var s3Services = map[string]bool{
	"s3":               true,
	"s3-control":       true,
	"s3-object-lambda": true,
	"s3-outposts":      true,
	"s3express":        true,
}

// inferProtocol works out the target service's wire protocol from what the
// client's SDK put on the request because of that protocol — the service's
// headers and URL. The body is never read.
func inferProtocol(r *http.Request) awsTarget {
	service, _, _, _ := sigv4.ExtractFromAuthHeader(r.Header.Get("Authorization"))
	t := awsTarget{service: service}
	// ParseMediaType lowercases the type and drops parameters such as charset.
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	switch {
	// S3 first: an object upload carries whatever Content-Type its caller
	// chose, so for S3 the content type says nothing about the protocol.
	case s3Services[service]:
		t.protocol = protocolS3
		// S3 Control signs as s3 too; the account-id header, required on every
		// S3 Control operation, tells it apart.
		if service == "s3-control" || r.Header.Get("X-Amz-Account-Id") != "" {
			t.protocol = protocolRestXML
		}
	case strings.EqualFold(r.Header.Get("Smithy-Protocol"), "rpc-v2-cbor"):
		t.protocol = protocolCBOR
	case r.Header.Get("X-Amz-Target") != "" || strings.HasPrefix(mediaType, "application/x-amz-json-"):
		t.protocol = protocolAWSJSON
		t.contentType = "application/x-amz-json-1.1"
		if mediaType == "application/x-amz-json-1.0" {
			t.contentType = mediaType
		}
	case mediaType == "application/x-www-form-urlencoded" ||
		(r.Method == http.MethodGet && r.URL.Query().Has("Action")):
		t.protocol = protocolQuery
		if service == "ec2" {
			t.protocol = protocolEC2Query
		}
	case service == "route53" || service == "cloudfront":
		t.protocol = protocolRestXML
	default:
		t.protocol = protocolRestJSON
	}

	if t.protocol == protocolAWSJSON || t.protocol == protocolCBOR {
		t.queryCompatible = strings.EqualFold(r.Header.Get("X-Amzn-Query-Mode"), "true")
	}
	return t
}

// errorCodes is an error's code in each protocol family's vocabulary: awsQuery
// and wrapped restXml, ec2Query, S3, and the JSON and CBOR protocols.
type errorCodes struct {
	query, ec2, s3, json string
}

// forProtocol returns the code a client of protocol p expects.
func (c errorCodes) forProtocol(p awsProtocol) string {
	switch p {
	case protocolQuery, protocolRestXML:
		return c.query
	case protocolEC2Query:
		return c.ec2
	case protocolS3:
		return c.s3
	default:
		return c.json
	}
}

// The codes each AWS protocol family uses for the failures Warden raises
// itself. None of the 4xx codes is on an AWS SDK's retry list, so a client
// gives up on them at once; every failure meant to be retried is a 5xx.
var (
	codesAuth = errorCodes{
		query: "InvalidClientTokenId", ec2: "AuthFailure",
		s3: "InvalidAccessKeyId", json: "UnrecognizedClientException",
	}
	codesDenied = errorCodes{
		query: "AccessDenied", ec2: "UnauthorizedOperation",
		s3: "AccessDenied", json: "AccessDeniedException",
	}
	codesBadRequest = errorCodes{
		query: "ValidationError", ec2: "ValidationError",
		s3: "InvalidRequest", json: "ValidationException",
	}
	codesInternal = errorCodes{
		query: "InternalFailure", ec2: "InternalError",
		s3: "InternalError", json: "InternalFailure",
	}
	codesUnavailable = errorCodes{
		query: "ServiceUnavailable", ec2: "Unavailable",
		s3: "ServiceUnavailable", json: "ServiceUnavailableException",
	}
	// codesSignature is a request whose signature did not verify. The AWS SDK
	// for Go treats each as a possible clock skew, retrying it only when the
	// response's Date header shows its clock is off.
	codesSignature = errorCodes{
		query: "SignatureDoesNotMatch", ec2: "AuthFailure",
		s3: "SignatureDoesNotMatch", json: "InvalidSignatureException",
	}
)

// awsError is a failure put in AWS's terms: the status and code an AWS SDK acts
// on, and the message it shows.
type awsError struct {
	status  int
	codes   errorCodes
	message string
}

// mapGatewayFailure puts a gateway failure in AWS's terms.
func mapGatewayFailure(f *logical.GatewayFailure) awsError {
	if f.Class != logical.GatewayFailureMint {
		return classError(f.Class, f.Err)
	}

	// An AWS API refused to issue the credential (STS turning down the
	// assume-role, say): pass its code and status through, so the client
	// sees the real cause and retries it exactly when AWS says to.
	if e, ok := upstreamAPIError(f.Err); ok {
		return e
	}
	// The upstream could not be reached in time: transient.
	if isUnreachable(f.Err) {
		return awsError{status: http.StatusServiceUnavailable, codes: codesUnavailable, message: wardenMessage(f.Err)}
	}
	// Anything else failed on Warden's side: go by the status Warden derived
	// for it, so a spec fault (a 4xx) is not retried while a transient failure
	// — the identity issuer not being ready yet during unseal, say — is.
	return classError(logical.ClassifyGatewayFailure(f.Status, nil), f.Err)
}

// classError maps a failure class to its AWS status and codes.
func classError(class logical.GatewayFailureClass, err error) awsError {
	e := awsError{message: wardenMessage(err)}
	switch class {
	case logical.GatewayFailureAuth:
		e.status, e.codes = http.StatusForbidden, codesAuth
	case logical.GatewayFailureDenied:
		e.status, e.codes = http.StatusForbidden, codesDenied
	case logical.GatewayFailureBadRequest:
		e.status, e.codes = http.StatusBadRequest, codesBadRequest
	case logical.GatewayFailureUnavailable:
		e.status, e.codes = http.StatusServiceUnavailable, codesUnavailable
	default:
		e.status, e.codes = http.StatusInternalServerError, codesInternal
	}
	return e
}

// upstreamAPIError finds the error an AWS API answered with in err's chain,
// and puts it back on the wire as that API sent it.
func upstreamAPIError(err error) (awsError, bool) {
	var apiErr smithy.APIError
	var respErr *awshttp.ResponseError
	if !errors.As(err, &apiErr) || !errors.As(err, &respErr) || apiErr.ErrorCode() == "" ||
		respErr.ResponseError == nil || respErr.Response == nil || respErr.Response.Response == nil {
		return awsError{}, false
	}
	status := respErr.HTTPStatusCode()
	if status < http.StatusBadRequest || status > 599 {
		return awsError{}, false
	}
	code := apiErr.ErrorCode()
	// STS answers a failure to reach the identity provider with a 400 but
	// documents it as transient; give it a status every SDK retries.
	if code == "IDPCommunicationError" {
		status = http.StatusServiceUnavailable
	}
	return awsError{
		status:  status,
		codes:   errorCodes{query: code, ec2: code, s3: code, json: code},
		message: "Warden: could not obtain AWS credentials: " + apiErr.ErrorMessage(),
	}, true
}

// isUnreachable reports whether err is a failure to reach an upstream at all,
// or to hear back from it in time.
func isUnreachable(err error) bool {
	var sendErr *smithyhttp.RequestSendError
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &sendErr) || errors.As(err, &netErr)
}

// wardenMessage is the message Warden's own error carried, marked as Warden's
// so it cannot be mistaken for one from AWS.
func wardenMessage(err error) string {
	if err == nil {
		return "Warden: request failed"
	}
	// Core collects some failures in a multierror, whose text is a bulleted
	// list ("1 error occurred:\n\t* permission denied\n\n"); keep the messages.
	if merr, ok := err.(*multierror.Error); ok && len(merr.Errors) > 0 {
		msgs := make([]string, len(merr.Errors))
		for i, e := range merr.Errors {
			msgs[i] = e.Error()
		}
		return "Warden: " + strings.Join(msgs, "; ")
	}
	return "Warden: " + err.Error()
}

// writeAWSError answers a gateway request the provider failed itself, once
// core has let it through: status and codes are the failure in AWS's terms,
// text is Warden's message for it. A SigV4 request gets the error as the
// service it targets would send it; anything else keeps the plain-text
// answer, since its client is not an AWS SDK.
func writeAWSError(w http.ResponseWriter, req *logical.Request, status int, codes errorCodes, text string) {
	if !sigv4.IsSigV4Request(req.HTTPRequest) {
		http.Error(w, text, status)
		return
	}
	resp := renderAWSError(inferProtocol(req.HTTPRequest),
		awsError{status: status, codes: codes, message: "Warden: " + text}, req.RequestID)
	h := w.Header()
	for k, v := range resp.Headers {
		h[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(resp.Body)
}

// forwardError answers, through writeAWSError, a failure sigv4's forward
// raised itself: it could not build the request (500), or the upstream could
// not be reached (502) or did not answer in time (504).
func forwardError(req *logical.Request) func(http.ResponseWriter, int, string) {
	return func(w http.ResponseWriter, status int, text string) {
		codes := codesInternal
		if status == http.StatusBadGateway || status == http.StatusGatewayTimeout {
			codes = codesUnavailable
		}
		writeAWSError(w, req, status, codes, text)
	}
}

// renderAWSError writes e in the wire format of protocol t, as a response the
// HTTP layer sends verbatim.
func renderAWSError(t awsTarget, e awsError, requestID string) *logical.Response {
	code := e.codes.forProtocol(t.protocol)
	h := make(http.Header, 6)
	var body []byte

	switch t.protocol {
	case protocolQuery, protocolRestXML:
		body = xmlErrorResponse(code, e.message, e.status, requestID)
		h.Set("Content-Type", "text/xml")
	case protocolEC2Query:
		body = ec2ErrorResponse(code, e.message, requestID)
		h.Set("Content-Type", "text/xml")
	case protocolS3:
		body = s3ErrorResponse(code, e.message, requestID)
		h.Set("Content-Type", "application/xml")
		if requestID != "" {
			h.Set("X-Amz-Request-Id", requestID)
		}
	case protocolCBOR:
		// The CBOR protocol names the error by its full shape ID; clients keep
		// what follows the '#'.
		body = smithycbor.Encode(smithycbor.Map{
			"__type":  smithycbor.String("com.amazonaws." + t.service + "#" + code),
			"message": smithycbor.String(e.message),
		})
		h.Set("Content-Type", "application/cbor")
		h.Set("Smithy-Protocol", "rpc-v2-cbor")
	case protocolAWSJSON:
		body = jsonErrorBody(code, e.message)
		h.Set("Content-Type", t.contentType)
		h.Set("X-Amzn-ErrorType", code)
	default:
		body = jsonErrorBody(code, e.message)
		h.Set("Content-Type", "application/json")
		h.Set("X-Amzn-ErrorType", code)
	}

	if t.queryCompatible {
		h.Set("X-Amzn-Query-Error", e.codes.query+";"+faultType(e.status))
	}
	if requestID != "" {
		h.Set("X-Amzn-RequestId", requestID)
	}
	return &logical.Response{StatusCode: e.status, Headers: h, Body: body}
}

// faultType is awsQuery's word for who is at fault: the caller for a 4xx, the
// service for a 5xx.
func faultType(status int) string {
	if status >= http.StatusInternalServerError {
		return "Receiver"
	}
	return "Sender"
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

// xmlErrorResponse is the awsQuery error, also restXml's wrapped one:
// <ErrorResponse><Error>…</Error><RequestId/></ErrorResponse>.
func xmlErrorResponse(code, message string, status int, requestID string) []byte {
	var b bytes.Buffer
	b.Grow(256 + len(message))
	b.WriteString(xmlHeader)
	b.WriteString("<ErrorResponse><Error>")
	writeXMLElement(&b, "Type", faultType(status))
	writeXMLElement(&b, "Code", code)
	writeXMLElement(&b, "Message", message)
	b.WriteString("</Error>")
	writeXMLElement(&b, "RequestId", requestID)
	b.WriteString("</ErrorResponse>")
	return b.Bytes()
}

// ec2ErrorResponse is the ec2Query error:
// <Response><Errors><Error>…</Error></Errors><RequestID/></Response>.
func ec2ErrorResponse(code, message, requestID string) []byte {
	var b bytes.Buffer
	b.Grow(256 + len(message))
	b.WriteString(xmlHeader)
	b.WriteString("<Response><Errors><Error>")
	writeXMLElement(&b, "Code", code)
	writeXMLElement(&b, "Message", message)
	b.WriteString("</Error></Errors>")
	writeXMLElement(&b, "RequestID", requestID)
	b.WriteString("</Response>")
	return b.Bytes()
}

// s3ErrorResponse is S3's unwrapped error: <Error><Code/><Message/><RequestId/></Error>.
func s3ErrorResponse(code, message, requestID string) []byte {
	var b bytes.Buffer
	b.Grow(192 + len(message))
	b.WriteString(xmlHeader)
	b.WriteString("<Error>")
	writeXMLElement(&b, "Code", code)
	writeXMLElement(&b, "Message", message)
	writeXMLElement(&b, "RequestId", requestID)
	b.WriteString("</Error>")
	return b.Bytes()
}

func writeXMLElement(b *bytes.Buffer, name, text string) {
	b.WriteString("<" + name + ">")
	// Writing to a bytes.Buffer cannot fail.
	_ = xml.EscapeText(b, []byte(text))
	b.WriteString("</" + name + ">")
}

// jsonErrorBody is the JSON protocols' error body.
func jsonErrorBody(code, message string) []byte {
	body, _ := json.Marshal(struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
	}{code, message})
	return body
}
