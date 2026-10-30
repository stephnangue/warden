package core

import (
	"context"
	"strings"
	"time"
)

// Ticket token values and IDs. A value is its prefix followed by the base64url
// of the sealed payload; an ID is its prefix followed by the hash of the value
// (hashTokenID), so every node derives the same ID from the same value.
const (
	ticketValuePrefix = "wdt."
	ticketIDPrefix    = "wdt_"
)

// TicketTokenType implements the self-contained session token an explicit
// login hands out: the verified identity, its facts and an expiry, sealed under
// the barrier's key. It carries no role and no policies; a role grants them per
// request, as for an identity token. It is never stored: an entry is the
// cache's, or rebuilt from the value by lookupTicket. It has no accessor and
// cannot be renewed or revoked; it lives until its expiry, or until the mount
// that issued it is gone.
type TicketTokenType struct {
	core *Core
}

func (t *TicketTokenType) Metadata() TokenTypeMetadata {
	return TokenTypeMetadata{
		Name:        TypeTicketToken,
		IDPrefix:    ticketIDPrefix,
		ValuePrefix: ticketValuePrefix,
		Description: "Self-contained session token: a sealed identity and its facts, granted a role per request",
		DefaultTTL:  1 * time.Hour,
		Stateless:   true,
	}
}

// Generate seals the login's admission into a ticket value. The entry is
// brought in line with what decoding that value rebuilds, so a cached login
// entry and a decoded one answer alike: times at second precision, no
// policies, no metadata (a role grant projects them per request), no actors
// and no IP binding. It reassigns entry's fields, writing into none of its
// maps or slices, on an entry still being built.
func (t *TicketTokenType) Generate(ctx context.Context, authData *AuthData, entry *TokenEntry) (map[string]string, error) {
	value, payload, err := t.core.encodeTicket(ctx, authData, entry)
	if err != nil {
		return nil, err
	}
	entry.CreatedAt = time.Unix(payload.IssuedAt, 0)
	entry.ExpireAt = time.Unix(payload.ExpiresAt, 0)
	entry.Policies = nil
	entry.Metadata = nil
	entry.Actors = nil
	entry.CreatedByIP = ""
	entry.Data = map[string]string{"token": value}
	return map[string]string{"token": value}, nil
}

// ValidateValue reports whether tokenValue has the shape of a ticket value: the
// prefix and a length within bounds. Only decoding tells more.
func (t *TicketTokenType) ValidateValue(tokenValue string) bool {
	return isTicketValue(tokenValue) && len(tokenValue) >= minTicketLen && len(tokenValue) <= maxTicketLen
}

func (t *TicketTokenType) ComputeID(lookupValue string) string {
	return tokenID(ticketIDPrefix, lookupValue)
}

func (t *TicketTokenType) LookupKey() string { return "token" }

var _ TokenType = (*TicketTokenType)(nil)

// isTicketValue reports whether a presented credential is a ticket value. It is
// the only test core applies before deciding to decode one.
func isTicketValue(v string) bool {
	return strings.HasPrefix(v, ticketValuePrefix)
}
