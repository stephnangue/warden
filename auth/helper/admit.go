package helper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// AdmitPattern is the path, relative to an auth mount, of the admission check
// core runs for discovery: the presented credential verified against the
// mount's configuration alone, with no role.
const AdmitPattern = "introspect/admit"

// Keys of an AdmitPath response's Data.
const (
	// AdmittedKey holds a bool: whether the mount admitted the credential.
	AdmittedKey = "admitted"
	// AdmissionKey holds the *logical.Admission when it did. In-process only:
	// an admission never encodes (logical.ErrAdmissionNotSerializable).
	AdmissionKey = "admission"
)

// errAdmitInternal refuses an introspect/admit request core did not build.
var errAdmitInternal = logical.ErrForbidden(AdmitPattern + " is internal to Warden")

// ErrAgentAudiencesRequired is why a mount that admits agents and binds no
// audience cannot admit a bearer credential: without bound_audiences any
// token its issuer signs would be admitted, including tokens minted for other
// relying parties. A config write is refused with it, and a stored config
// without bound_audiences (written before audience binding was required)
// refuses admission with it.
var ErrAgentAudiencesRequired = errors.New("bound_audiences is required on agent mounts")

// The classes of the errors an AdmitFunc returns, each a reason the mount
// could not decide. Discovery answers any bearer holder, so it reports a
// failed mount by its class alone (errors.Is), never by the error's own text,
// which may name a verifier's host or repeat its reply. A method's error joins
// its class through AdmitError and keeps its own text for the server log.
// ErrAgentAudiencesRequired is a class of its own.
var (
	// ErrAdmitNotConfigured: the mount has no configuration.
	ErrAdmitNotConfigured = errors.New("not configured")
	// ErrAdmitUnverified: the verifier the mount relies on could not be
	// reached or did not answer, so nothing was decided about the credential.
	ErrAdmitUnverified = errors.New("could not verify the credential")
	// ErrAdmitNoTrustBundle: the mount has no trust bundle loaded.
	ErrAdmitNoTrustBundle = errors.New("no trust bundle")
	// ErrAdmitNoTrustedCA: the mount has no trusted CA.
	ErrAdmitNoTrustedCA = errors.New("no trusted CA")
	// ErrAdmitNoAudiences: the mount binds no audience, so it admits no
	// credential that must carry one.
	ErrAdmitNoAudiences = errors.New("bound_audiences is not set")
)

// admitError is an error reading text that errors.Is matches to its class.
type admitError struct {
	class error
	text  string
}

func (e *admitError) Error() string { return e.text }
func (e *admitError) Unwrap() error { return e.class }

// AdmitError returns an error reading text that errors.Is matches to class,
// one of the ErrAdmit classes. A method declares its sentinel with it, so the
// sentinel keeps its own text and still reports as its class.
func AdmitError(class error, text string) error {
	return &admitError{class: class, text: text}
}

// RequireAgentAudiences returns ErrAgentAudiencesRequired when a mount of
// entity kind kind binds no audience, unless the kind is human: a human mount
// may leave its audience to the resource identifier of the request. Any kind
// other than human is held to the agent rule, so a kind that does not parse
// fails closed.
func RequireAgentAudiences(kind string, audiences []string) error {
	if kind == logical.EntityKindHuman || len(audiences) > 0 {
		return nil
	}
	return ErrAgentAudiencesRequired
}

// AgentAudiencesWriteError is the refusal of a config write that would leave
// an agent mount without bound_audiences, saying how to fix it.
func AgentAudiencesWriteError() error {
	return fmt.Errorf("%w: set bound_audiences to the audiences tokens for Warden carry, or set entity_kind to human for a mount that admits users", ErrAgentAudiencesRequired)
}

// AdmitFunc verifies the credential req presents against the mount's
// configuration at now and returns what it verified. (nil, nil) means the
// mount does not admit the credential (none presented, or a check on the
// credential failing; the method may log why), which the caller does not
// report. An error means the mount could not decide (no configuration, no
// trust anchors, the verifier unreachable), which the caller reports per
// mount by its class (the ErrAdmit classes, ErrAgentAudiencesRequired); its
// text names the mount's condition only, never a fact, claim or group, and
// reaches the server log alone. It never logs in, mints a token, writes
// storage or records the caller; MountPath is left for core to set.
type AdmitFunc func(ctx context.Context, req *logical.Request, now time.Time) (*logical.Admission, error)

// AdmitPath returns the introspect/admit path of an auth method whose
// admission check is admit. The path refuses every request without
// req.Internal, which only core sets on requests it routes in process, so an
// HTTP caller, root included, is refused before admit runs. A mount must not
// list it among its unauthenticated paths.
//
// The response's Data holds AdmittedKey and, when admitted, AdmissionKey. An
// error from admit is returned as the request's error.
func AdmitPath(admit AdmitFunc) *framework.Path {
	return &framework.Path{
		Pattern: AdmitPattern,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
					if !req.Internal {
						return logical.ErrorResponse(errAdmitInternal), nil
					}
					adm, err := admit(ctx, req, time.Now())
					if err != nil {
						return nil, err
					}
					if adm == nil {
						return &logical.Response{
							StatusCode: http.StatusOK,
							Data:       map[string]any{AdmittedKey: false},
						}, nil
					}
					return &logical.Response{
						StatusCode: http.StatusOK,
						Data:       map[string]any{AdmittedKey: true, AdmissionKey: adm},
					}, nil
				},
				Summary: "Admit the presented credential against the mount configuration (internal)",
			},
		},
		HelpSynopsis: "Admit the presented credential against the mount configuration (internal)",
		HelpDescription: "Verifies the presented credential against this mount's configuration, with no role, " +
			"and hands what it verified to Warden's discovery in process. Not callable over HTTP.",
	}
}
