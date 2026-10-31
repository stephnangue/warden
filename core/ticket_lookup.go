package core

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/stephnangue/warden/helper/selector"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// lookupTicket returns this request's copy of the entry a ticket value
// stands for: the cached one, or one rebuilt from the value and cached. Every
// request, hit or miss, then passes the same checks. Each refuses with
// ErrTokenNotFound, except an expired ticket (ErrTokenExpired) and a request
// outside the ticket's namespaces (ErrTokenNamespaceMismatch), as for every
// token; the request path answers all of them alike:
//
//  0. the entry holds this very value (the cache key is a truncated hash);
//  1. the ticket has not expired;
//  2. the issuing mount still exists in the ticket's namespace (the accessor
//     is looked up exactly) and publishes facts;
//  3. that mount still admits the kind the ticket was issued for;
//  4. the request's namespace is the ticket's or one of its children.
//
// Disabling the issuing mount, or deleting its namespace, therefore refuses
// every ticket it issued from the next request on: a mount enabled again has a
// new accessor. A ticket has no IP binding.
//
// Only a value that decrypts under the ticket context, passes decodeTicket and
// has not expired is ever cached, so the cache cannot be filled with values
// nobody issued, nor with old ones replayed. On
// a hit it takes the router's read lock once and an atomic load; a miss also
// decrypts.
func (c *Core) lookupTicket(ctx context.Context, value string) (*TokenEntry, error) {
	if c.Sealed() {
		return nil, errors.New("the core is sealed")
	}
	s := c.tokenStore
	if s == nil {
		return nil, ErrTokenNotFound
	}
	if len(value) < minTicketLen || len(value) > maxTicketLen || !isTicketValue(value) {
		return nil, ErrTokenNotFound
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return nil, errors.New("namespace not found in context")
	}

	id := tokenID(ticketIDPrefix, value)
	entry, found := s.byID.Get(id)
	if found {
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheHits()
		}
	} else {
		if s.config.EnableMetrics {
			s.metrics.IncrementCacheMisses()
		}
		entry, err = c.ticketEntry(ctx, id, value)
		if err != nil {
			s.logger.Debug("ticket refused", logger.String("token_id", id), logger.Err(err))
			return nil, ErrTokenNotFound
		}
		// An expired ticket is refused below and never cached: its cache TTL
		// would be 0, which the cache reads as never expiring.
		if time.Now().Before(entry.ExpireAt) {
			s.byID.SetWithTTL(id, entry, entryCost(entry), s.computeCacheTTL(entry))
		}
	}

	if err := c.checkTicket(entry, value, ns, time.Now()); err != nil {
		s.logger.Debug("ticket refused", logger.String("token_id", id), logger.Err(err))
		switch {
		case errors.Is(err, ErrTokenExpired):
			if s.config.EnableMetrics {
				s.metrics.IncrementTokensExpired()
			}
		case errors.Is(err, ErrTokenNamespaceMismatch):
			if s.config.EnableMetrics {
				s.metrics.IncrementNamespaceMismatches()
			}
		default:
			err = ErrTokenNotFound
		}
		return nil, err
	}

	if s.config.EnableMetrics {
		s.metrics.IncrementTokensResolved()
	}
	return entry.Copy(), nil
}

// ticketEntry decodes value into the entry a login of it issued: the same
// fields, and an admission that answers every fact as the issuing node's did.
// The issuing mount must exist (its path and live naming complete the
// admission); checkTicket checks the rest.
func (c *Core) ticketEntry(ctx context.Context, id, value string) (*TokenEntry, error) {
	p, facts, err := c.decodeTicket(ctx, value)
	if err != nil {
		return nil, err
	}
	me, fp, err := c.ticketMount(p.MountAccessor, p.NamespaceID)
	if err != nil {
		return nil, err
	}
	adm := &logical.Admission{
		MountPath:     me.APIPathNoNamespace(),
		MountAccessor: p.MountAccessor,
		AliasName:     p.Alias,
		Facts:         selector.NewClaims(facts),
		PrincipalID:   p.PrincipalID,
		Mount:         fp.MountFacts(),
		IssuedAt:      time.Unix(p.IssuedAt, 0),
		Kind:          p.Kind,
		AuthTime:      timeOrZero(p.AuthTime),
		Bytes:         int64(len(p.Facts)),
	}
	return &TokenEntry{
		ID:            id,
		Type:          TypeTicketToken,
		NamespaceID:   p.NamespaceID,
		NamespacePath: me.Namespace().Path,
		CreatedAt:     time.Unix(p.IssuedAt, 0),
		PrincipalID:   p.PrincipalID,
		MountAccessor: p.MountAccessor,
		ExpireAt:      time.Unix(p.ExpiresAt, 0),
		Data:          map[string]string{"token": value},
		Admission:     adm,
	}, nil
}

// ticketMount returns the mount whose accessor is exactly accessor, provided it
// lives in the namespace nsID and its backend publishes facts.
func (c *Core) ticketMount(accessor, nsID string) (*MountEntry, logical.FactsProvider, error) {
	me, backend := c.router.MatchingBackendByAccessor(accessor)
	if me == nil || me.NamespaceID != nsID || me.Namespace() == nil {
		return nil, nil, fmt.Errorf("issuing mount %q is gone", accessor)
	}
	fp, ok := backend.(logical.FactsProvider)
	if !ok {
		return nil, nil, fmt.Errorf("issuing mount %q publishes no facts", accessor)
	}
	return me, fp, nil
}

// checkTicket runs lookupTicket's per-request checks on entry, cached or just
// decoded.
func (c *Core) checkTicket(entry *TokenEntry, value string, ns *namespace.Namespace, now time.Time) error {
	if entry.Type != TypeTicketToken || entry.Admission == nil ||
		subtle.ConstantTimeCompare([]byte(entry.Data["token"]), []byte(value)) != 1 {
		return errors.New("ticket value mismatch")
	}
	if !now.Before(entry.ExpireAt) {
		return ErrTokenExpired
	}
	me, fp, err := c.ticketMount(entry.MountAccessor, entry.NamespaceID)
	if err != nil {
		return err
	}
	naming := fp.MountFacts().Load()
	if naming == nil || naming.Kind != entry.Admission.Kind {
		return fmt.Errorf("issuing mount %q no longer admits %q", entry.MountAccessor, entry.Admission.Kind)
	}
	tokenNs := me.Namespace()
	if ns.UUID != tokenNs.UUID && !ns.HasParent(tokenNs) {
		return ErrTokenNamespaceMismatch
	}
	return nil
}
