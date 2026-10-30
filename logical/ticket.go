package logical

import (
	"encoding/base64"
	"encoding/json"
)

// TicketValuePrefix starts every ticket token value.
const TicketValuePrefix = "wdt."

// MaxTicketLen bounds a ticket token value, prefix included. Reverse proxies
// bound a request header line to about 8 KiB (nginx 8192, Apache 8190), and a
// ticket travels in one header, so a longer value would be refused far from its
// cause. A value over the bound is refused before it is decoded, and a login
// that would issue one is refused.
const MaxTicketLen = 8000

// TicketPayloadVersion is the only TicketPayload.V this release reads or
// writes.
const TicketPayloadVersion = 1

// ticketSealOverhead is what sealing adds to a payload: key term (4), format
// version (1), nonce (12) and authentication tag (16).
const ticketSealOverhead = 4 + 1 + 12 + 16

// TicketPayload is what a ticket token value carries, sealed: who it admits,
// what the issuing mount verified, and until when. It carries no role, no
// policies and no credential of the identity provider.
type TicketPayload struct {
	V           int    `json:"v"`
	Alias       string `json:"alias"`
	PrincipalID string `json:"pid"`
	Kind        string `json:"kind"`
	IssuedAt    int64  `json:"iat"`
	ExpiresAt   int64  `json:"exp"`
	AuthTime    int64  `json:"auth_time,omitempty"`
	NamespaceID string `json:"ns"`

	// MountAccessor names the issuing mount; the ticket is refused once that
	// mount is gone.
	MountAccessor string `json:"acc"`

	// Facts are the raw facts kept at login, a JSON object, resolved through
	// the issuing mount's live mapping on every request.
	Facts json.RawMessage `json:"facts"`

	// Cnf is reserved for a proof-of-possession key binding. This release
	// issues none and refuses a ticket that carries one.
	Cnf json.RawMessage `json:"cnf,omitempty"`
}

// TicketLen returns the length of the ticket token value whose payload
// encodes to payloadLen bytes.
func TicketLen(payloadLen int) int {
	return len(TicketValuePrefix) + base64.RawURLEncoding.EncodedLen(payloadLen+ticketSealOverhead)
}
