package core

import (
	"errors"
	"fmt"
	"time"

	"github.com/stephnangue/warden/helper/dpop"
	"github.com/stephnangue/warden/logical"
)

// ticketProof is what a request offers to prove it holds the key a bound
// ticket names. Only admitTicket builds one. Every other lookup passes nil,
// which refuses a bound ticket, so no caller can open one without its proof
// and no new caller has to remember to check it.
type ticketProof struct {
	req *logical.Request

	// bearer is whether the ticket rides Authorization: Bearer, where a bound
	// ticket is never accepted (RFC 9449 §7.2).
	bearer bool

	// body is whether the proof signs the request's body: on the branch where
	// core reads it whole, not where it streams through.
	body bool
}

// The error a refused proof's DPoP challenge names: RFC 6750's when a bound
// ticket is presented where no proof can open it, RFC 9449's when its proof
// fails.
const (
	proofErrInvalidToken = "invalid_token"
	proofErrInvalidProof = "invalid_dpop_proof"
)

// ticketProofError refuses a bound ticket for its proof. Its cause is for the
// server's log; the caller learns only the code and a fixed message. It is
// also ErrTokenNotFound, so a lookup outside admitTicket refuses the ticket as
// it refuses any token it cannot open.
type ticketProofError struct {
	code string
	err  error
}

func (e *ticketProofError) Error() string        { return e.err.Error() }
func (e *ticketProofError) Unwrap() error        { return e.err }
func (e *ticketProofError) Is(target error) bool { return target == ErrTokenNotFound }

// checkTicketProof checks the proof a request offers for the ticket b binds,
// and records the proof's id on the request for the audit. The proof must sign
// the request's method and path, the ticket, and the request's selectors,
// query and, where core reads it whole, body (dpop.Context).
func (c *Core) checkTicketProof(b *logical.KeyBinding, proof *ticketProof) error {
	if proof == nil || proof.req == nil || proof.req.HTTPRequest == nil {
		return &ticketProofError{proofErrInvalidToken, errors.New("a bound ticket was looked up without its proof")}
	}
	if proof.bearer {
		return &ticketProofError{proofErrInvalidToken, errors.New("a bound ticket was presented as a bearer token")}
	}
	req, r := proof.req, proof.req.HTTPRequest
	path, ok := dpop.RequestPath(r)
	if !ok {
		return &ticketProofError{proofErrInvalidProof, errors.New("the request line's target does not parse")}
	}
	want := &dpop.Want{
		JKT:    b.JKT,
		Method: r.Method,
		Path:   path,
		Now:    req.ReceivedAt,
		ATH:    b.ATH,
		Context: &dpop.Context{
			Role:        r.Header.Get("X-Warden-Role"),
			Namespace:   r.Header.Get("X-Warden-Namespace"),
			Provider:    r.Header.Get("X-Warden-Provider"),
			Request:     r.Header.Get("X-Warden-Request"),
			ContentType: r.Header.Get("Content-Type"),
			Query:       dpop.Hash([]byte(r.URL.RawQuery)),
		},
		Body: proof.body,
	}
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	if proof.body {
		body, err := c.proofBody(req)
		if err != nil {
			return err
		}
		want.Context.Body = dpop.Hash(body)
	}
	p, err := dpop.Verify(r.Header.Values(dpop.HeaderName), want)
	if err != nil {
		return &ticketProofError{proofErrInvalidProof, err}
	}
	req.ProofID = dpop.Hash([]byte(p.JTI))[:16]
	return nil
}

// proofBody returns the body a proof signs: the one core buffered to parse it,
// else the body buffered now under the same cap, for a body parseRequestBody
// does not read (a GET's or DELETE's, or one of a type it does not parse).
func (c *Core) proofBody(req *logical.Request) ([]byte, error) {
	if b, ok := req.BufferedBody(); ok {
		return b, nil
	}
	if req.HTTPRequest.Body == nil {
		return nil, nil
	}
	return c.readAndRestoreBody(req, maxRequestBodySize)
}

// ticketProofRefusal renders err when it refuses a bound ticket for its proof,
// on every surface alike: a 401 with the DPoP challenge, since the surfaces'
// own refusals (a 403, a Bearer challenge) would send the client the wrong
// way. A coded error (a body over the cap) keeps its own status. Nil for any
// other error.
func ticketProofRefusal(err error) *logical.Response {
	var pe *ticketProofError
	if errors.As(err, &pe) {
		msg := "the request's DPoP proof is not valid"
		if pe.code == proofErrInvalidToken {
			msg = "this ticket is bound to a key: present it on " + logical.HeaderWardenToken + " with a DPoP proof"
		}
		resp := logical.ErrorResponse(logical.ErrUnauthorized(msg))
		resp.AddHeader("WWW-Authenticate", fmt.Sprintf(`DPoP error=%q, algs=%q`, pe.code, dpop.Alg))
		return resp
	}
	var coded *logical.CodedError
	if errors.As(err, &coded) {
		return logical.ErrorResponse(coded)
	}
	return nil
}
