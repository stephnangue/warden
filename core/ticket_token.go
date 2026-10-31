package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/logical"
)

// ticketContext is the context every ticket is sealed under: the barrier binds
// it to the ciphertext as additional data. No storage path and no backend's
// sealer context (they all start with backendSealerPrefix) equals it, so no
// other ciphertext opens as a ticket and a ticket opens as nothing else.
const ticketContext = "ticket-token/v1"

// maxTicketLen and minTicketLen bound a presented ticket value before anything
// decodes it. The shortest value seals an empty JSON object.
var (
	maxTicketLen = logical.MaxTicketLen
	minTicketLen = logical.TicketLen(len("{}"))
)

var (
	errTicketTooLarge  = fmt.Errorf("the ticket would exceed %d bytes", logical.MaxTicketLen)
	errTicketMalformed = errors.New("ticket is malformed")
)

// encodeTicket seals the ticket a login issues. The admission must be complete
// (setAdmissionMount has run), carry its facts as selector.Claims and have an
// alias: a ticket nobody can be named by is never issued. It records on the
// admission, which is still being built (LoginCreateToken has not shared it
// yet), the kind the mount admitted the credential as and the ticket's issue
// time, so a cached entry and a decoded one carry the same: a ticket's
// admission is issued when the ticket is. A ticket's admission is never
// audience-bound (AudienceBound): a ticket never rides the user leg.
//
// The size is checked against maxTicketLen here as a backstop; the issuing
// mount checks it first (logical.TicketLen), so the caller gets a reason and
// not an internal error.
func (c *Core) encodeTicket(ctx context.Context, authData *AuthData, entry *TokenEntry) (string, *logical.TicketPayload, error) {
	if authData == nil || authData.Admission == nil {
		return "", nil, errors.New("a ticket is issued only for an admission")
	}
	adm := authData.Admission
	claims, ok := adm.Facts.(*selector.Claims)
	if !ok {
		return "", nil, errors.New("a ticket carries claims facts only")
	}
	naming := adm.Mount.Load()
	if naming == nil {
		return "", nil, errors.New("the issuing mount publishes no naming")
	}
	if adm.AliasName == "" {
		return "", nil, errors.New("a ticket is issued only for an admission with an alias")
	}
	if authData.MountAccessor == "" || entry.NamespaceID == "" {
		return "", nil, errors.New("a ticket must name its mount and namespace")
	}
	facts, err := claims.EncodeJSON()
	if err != nil {
		return "", nil, fmt.Errorf("encoding ticket facts: %w", err)
	}

	p := &logical.TicketPayload{
		V:             logical.TicketPayloadVersion,
		Alias:         adm.AliasName,
		PrincipalID:   authData.PrincipalID,
		Kind:          naming.Kind,
		IssuedAt:      entry.CreatedAt.Unix(),
		ExpiresAt:     authData.ExpireAt.Unix(),
		AuthTime:      unixOrZero(adm.AuthTime),
		NamespaceID:   entry.NamespaceID,
		MountAccessor: authData.MountAccessor,
		Facts:         facts,
	}
	if authData.ExpireAt.IsZero() || p.ExpiresAt <= p.IssuedAt {
		return "", nil, errors.New("a ticket must expire after it is issued")
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return "", nil, fmt.Errorf("encoding ticket: %w", err)
	}
	if logical.TicketLen(len(plain)) > maxTicketLen {
		return "", nil, errTicketTooLarge
	}
	sealed, err := c.barrier.Encrypt(ctx, ticketContext, plain)
	if err != nil {
		return "", nil, fmt.Errorf("sealing ticket: %w", err)
	}
	adm.Kind = p.Kind
	adm.IssuedAt = time.Unix(p.IssuedAt, 0)
	adm.AudienceBound = false
	return ticketValuePrefix + base64.RawURLEncoding.EncodeToString(sealed), p, nil
}

// decodeTicket opens a presented ticket value and checks its structure: the
// payload version, the fields every ticket carries, an expiry after issue, and
// no proof-of-possession binding (reserved, refused in this release). It does
// not check expiry against the clock, nor the mount or the namespace: those are
// lookupTicket's per-request checks. The facts are returned decoded, as
// selector.Claims reads them.
//
// The format byte is checked before decrypting: the barrier ignores the context
// for a version-1 ciphertext, so only version 2 binds a value to ticketContext.
func (c *Core) decodeTicket(ctx context.Context, value string) (*logical.TicketPayload, map[string]any, error) {
	if len(value) < minTicketLen || len(value) > maxTicketLen || !isTicketValue(value) {
		return nil, nil, errTicketMalformed
	}
	sealed, err := base64.RawURLEncoding.DecodeString(value[len(ticketValuePrefix):])
	if err != nil || !boundCiphertext(sealed) {
		return nil, nil, errTicketMalformed
	}
	plain, err := c.barrier.Decrypt(ctx, ticketContext, sealed)
	if err != nil {
		return nil, nil, fmt.Errorf("opening ticket: %w", err)
	}

	var p logical.TicketPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, nil, errTicketMalformed
	}
	switch {
	case p.V != logical.TicketPayloadVersion:
		return nil, nil, fmt.Errorf("ticket payload version %d is not supported", p.V)
	case len(p.Cnf) != 0:
		return nil, nil, errors.New("ticket is bound to a key, which this release does not support")
	case !logical.ValidAliasName(p.Alias):
		return nil, nil, errors.New("ticket carries no valid alias")
	case p.Kind != logical.EntityKindAgent && p.Kind != logical.EntityKindHuman:
		return nil, nil, errors.New("ticket carries no valid kind")
	case p.NamespaceID == "" || p.MountAccessor == "":
		return nil, nil, errors.New("ticket names no mount or namespace")
	case p.ExpiresAt <= p.IssuedAt:
		return nil, nil, errors.New("ticket expires before it is issued")
	}
	var facts map[string]any
	if err := json.Unmarshal(p.Facts, &facts); err != nil || facts == nil {
		return nil, nil, errTicketMalformed
	}
	return &p, facts, nil
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// timeOrZero is unixOrZero's inverse.
func timeOrZero(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}
