//go:build e2e

package fullchain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A stand-in Grafana, shared by the inline and chained grafana suites so the two
// cannot drift apart in what they think a Grafana does.
//
// It answers the four calls the driver makes and records what it was asked,
// because most of what these rows assert is not the response — it is which
// credential authenticated the call, which account the token was created on, and
// what was deleted.
//
// Every status and body here was checked against Grafana's own documentation and
// source rather than assumed, because a stub that is wrong in the same direction
// as the driver turns a broken path into a green row:
//
//   - POST   /api/serviceaccounts/{id}/tokens      200 {"id":N,"name":...,"key":...}
//     400 ErrDuplicateToken on a repeated name (errutil.BadRequest)
//     404 ErrServiceAccountNotFound for an unknown account
//   - DELETE /api/serviceaccounts/{id}/tokens/{tid} 200 {"message":"API key deleted"}
//     404 ErrServiceAccountTokenNotFound when it is already gone
//   - GET    /api/serviceaccounts/{id}/tokens       200, a FLAT array carrying hasExpired
//   - GET    /api/serviceaccounts/{id}              200 {...,"role":...,"isDisabled":...}

// grafanaMintedFor derives the token the stub issues from the privileged token
// that authenticated the create. Deriving rather than returning a constant is
// what carries "which secret was spent" all the way to the header the gateway
// injects — a fixed value would look identical whichever token performed the call.
func grafanaMintedFor(privileged string) string {
	return "glsa_minted-for-" + privileged
}

const (
	// The accounts the stub is provisioned with, as an operator would have
	// created them in Grafana. Warden never creates one, so a row asking for an
	// account outside this set is asking for a 404.
	grafanaAccountViewer   = "42"
	grafanaAccountEditor   = "57"
	grafanaAccountDisabled = "99"
	grafanaAccountUnknown  = "12345"
)

// grafanaTokenCreate is one recorded token creation.
type grafanaTokenCreate struct {
	// Privileged is the credential that authenticated the create — the answer to
	// "which secret was spent".
	Privileged string
	// AccountID is the account the token was created on, which is the whole
	// point of the redesign: a spec names it, Warden does not invent one.
	AccountID string
	// Body is the create request verbatim, so a row can assert the mint
	// parameters an operator set actually reached Grafana.
	Body map[string]interface{}
	// MintedID is the token id the stub issued.
	MintedID string
	// TokenName is the name it was created under, which is what the sweep's
	// prefix filter reads.
	TokenName string
}

// grafanaStubToken is one token as the listing reports it.
type grafanaStubToken struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	HasExpired bool   `json:"hasExpired"`
}

// grafanaStub records what the driver asked of it. Every field is read under the
// mutex: the sweep runs on a goroutine of its own and revocation on the
// expiration manager's timer, so a row polling for their effects races the
// handler serving them.
type grafanaStub struct {
	*httptest.Server

	mu      sync.Mutex
	creates []grafanaTokenCreate
	// deleted records every token id the driver asked to remove, whether by
	// revoking a lease or by sweeping an expired one.
	deleted []string
	// accountsDeleted records any attempt to delete an ACCOUNT. It must stay
	// empty: the account is the operator's, and a driver that removed one would
	// be taking away every other token on it.
	accountsDeleted []string
	// listed is what the token listing reports, per account. Primed by a row
	// that wants the sweep to find something.
	listed map[string][]grafanaStubToken
	// issued names every token name seen, so a repeat draws Grafana's real
	// duplicate refusal rather than quietly succeeding.
	issued  map[string]bool
	nextID  int64
	accepts map[string]bool
}

func (s *grafanaStub) recordCreate(c grafanaTokenCreate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates = append(s.creates, c)
	// A real Grafana lists the token it just issued, so the sweep's listing
	// contains live Warden-named tokens as well as expired ones. Without this the
	// stub could never catch a sweep that deleted a credential still in use.
	s.listed[c.AccountID] = append(s.listed[c.AccountID], grafanaStubToken{
		ID: mustAtoi(c.MintedID), Name: c.TokenName, HasExpired: false,
	})
}

func (s *grafanaStub) createdTokens() []grafanaTokenCreate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]grafanaTokenCreate(nil), s.creates...)
}

// observed returns the privileged tokens that authenticated a create, oldest first.
func (s *grafanaStub) observed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens := make([]string, 0, len(s.creates))
	for _, c := range s.creates {
		tokens = append(tokens, c.Privileged)
	}
	return tokens
}

func (s *grafanaStub) deletedTokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deleted...)
}

func (s *grafanaStub) deletedAccounts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.accountsDeleted...)
}

// reset clears the record. Standing a source and spec up already costs Grafana a
// create and a delete — spec validation test-mints and then releases the lease —
// so a row that means to count its own traffic starts from here.
func (s *grafanaStub) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates = nil
	s.deleted = nil
	s.accountsDeleted = nil
}

// primeTokens makes the listing on an account report these tokens, as though
// earlier mints had left them there.
func (s *grafanaStub) primeTokens(accountID string, tokens ...grafanaStubToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listed[accountID] = tokens
}

func (s *grafanaStub) sawDeleted(id string) bool {
	for _, got := range s.deletedTokens() {
		if got == id {
			return true
		}
	}
	return false
}

// awaitDeleted waits for a token id to be deleted, and says what it did see when
// it is not. Both the revocation and the sweep run off this goroutine, so there
// is nothing to synchronise on but the effect itself.
func (s *grafanaStub) awaitDeleted(t *testing.T, id string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if s.sawDeleted(id) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("token %q was never deleted within %s; Grafana was asked to delete %v",
		id, within, s.deletedTokens())
}

// awaitQuiescent waits until no delete has been recorded for a settle period.
//
// The sweep walks the account's listing in order, so a row that concludes "it
// left the others alone" the instant its first expected delete lands is reading
// a half-finished sweep: a wrongly-filtered delete issued later would arrive
// after the assertions and never be seen.
func (s *grafanaStub) awaitQuiescent(t *testing.T, settle time.Duration) {
	t.Helper()
	last := len(s.deletedTokens())
	deadline := time.Now().Add(settle + 10*time.Second)
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if n := len(s.deletedTokens()); n != last {
			last, stableSince = n, time.Now()
			continue
		}
		if time.Since(stableSince) >= settle {
			return
		}
	}
	t.Fatalf("deletes never settled; Grafana was asked to delete %v", s.deletedTokens())
}

// grafanaAccountPath splits "/api/serviceaccounts/{id}[/tokens[/{tid}]]".
func grafanaAccountPath(path string) (accountID, rest string) {
	trimmed := strings.TrimPrefix(path, "/api/serviceaccounts/")
	accountID, rest, _ = strings.Cut(trimmed, "/")
	return accountID, rest
}

func startGrafanaStub(t *testing.T) *grafanaStub {
	t.Helper()

	stub := &grafanaStub{
		listed: map[string][]grafanaStubToken{},
		issued: map[string]bool{},
		accepts: map[string]bool{
			grafanaAccountViewer:   true,
			grafanaAccountEditor:   true,
			grafanaAccountDisabled: true,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/serviceaccounts/", func(w http.ResponseWriter, r *http.Request) {
		privileged, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || privileged == "" {
			grafanaErr(w, http.StatusUnauthorized, "auth.unauthorized", "Unauthorized")
			return
		}

		accountID, rest := grafanaAccountPath(r.URL.Path)

		stub.mu.Lock()
		known := stub.accepts[accountID]
		stub.mu.Unlock()
		if !known {
			// Grafana answers a call naming an account it does not have with
			// ErrServiceAccountNotFound, an errutil.NotFound.
			grafanaErr(w, http.StatusNotFound, "serviceaccounts.ErrNotFound", "service account not found")
			return
		}

		switch {
		// Nothing in the driver may create or delete an ACCOUNT. Both are
		// refused loudly rather than merely unrouted, so a regression that tried
		// shows up as a failing row and not a 404 someone reads as a stub gap.
		case rest == "" && r.Method == http.MethodDelete:
			stub.mu.Lock()
			stub.accountsDeleted = append(stub.accountsDeleted, accountID)
			stub.mu.Unlock()
			grafanaErr(w, http.StatusForbidden, "e2e.AccountDeleteForbidden",
				"this stub refuses to delete a service account: it belongs to the operator")

		case rest == "" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":         mustAtoi(accountID),
				"name":       "warden-e2e-" + accountID,
				"login":      "sa-warden-e2e-" + accountID,
				"orgId":      1,
				"isDisabled": accountID == grafanaAccountDisabled,
				"role":       grafanaRoleOf(accountID),
			})

		case rest == "tokens" && r.Method == http.MethodPost:
			var body map[string]interface{}
			if r.Body != nil {
				_ = json.NewDecoder(r.Body).Decode(&body)
			}
			name, _ := body["name"].(string)

			// Grafana reads secondsToLive 0, null or absent as "this token never
			// expires". Refusing it here means a regression that let one through
			// fails a row instead of quietly issuing a permanent credential.
			ttl, present := body["secondsToLive"].(float64)
			if !present || ttl < 1 {
				grafanaErr(w, http.StatusBadRequest, "e2e.NeverExpires",
					fmt.Sprintf("refusing to create a token that never expires (secondsToLive=%v)", body["secondsToLive"]))
				return
			}

			stub.mu.Lock()
			if stub.issued[name] {
				stub.mu.Unlock()
				// ErrDuplicateToken is an errutil.BadRequest, so 400.
				grafanaErr(w, http.StatusBadRequest, "serviceaccounts.ErrTokenAlreadyExists",
					fmt.Sprintf("service account token with name %s already exists in the organization", name))
				return
			}
			stub.issued[name] = true
			stub.nextID++
			id := stub.nextID
			stub.mu.Unlock()

			stub.recordCreate(grafanaTokenCreate{
				Privileged: privileged,
				AccountID:  accountID,
				Body:       body,
				MintedID:   strconv.FormatInt(id, 10),
				TokenName:  name,
			})

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":   id,
				"name": name,
				"key":  grafanaMintedFor(privileged),
			})

		case rest == "tokens" && r.Method == http.MethodGet:
			stub.mu.Lock()
			tokens := append([]grafanaStubToken(nil), stub.listed[accountID]...)
			stub.mu.Unlock()
			if tokens == nil {
				tokens = []grafanaStubToken{}
			}
			// A flat array, not a paginated object.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokens)

		case strings.HasPrefix(rest, "tokens/") && r.Method == http.MethodDelete:
			tokenID := strings.TrimPrefix(rest, "tokens/")

			stub.mu.Lock()
			remaining := stub.listed[accountID][:0:0]
			found := false
			for _, tok := range stub.listed[accountID] {
				if strconv.FormatInt(tok.ID, 10) == tokenID {
					found = true
					continue
				}
				remaining = append(remaining, tok)
			}
			stub.listed[accountID] = remaining
			already := stub.wasDeletedLocked(tokenID)
			stub.deleted = append(stub.deleted, tokenID)
			stub.mu.Unlock()

			// Grafana's store checks RowsAffected and returns
			// ErrServiceAccountTokenNotFound — an errutil.NotFound — which
			// ErrOrFallback re-raises as 404 rather than its 500 fallback. The
			// driver treats that as success, and this is where that is proved.
			if already && !found {
				grafanaErr(w, http.StatusNotFound, "serviceaccounts.ErrTokenNotFound",
					"service account token with id "+tokenID+" not found")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"message": "API key deleted"})

		default:
			grafanaErr(w, http.StatusNotFound, "e2e.NoRoute", "no route for "+r.Method+" "+r.URL.Path)
		}
	})

	stub.Server = httptest.NewServer(mux)
	t.Cleanup(stub.Close)
	return stub
}

// wasDeletedLocked reports whether a token id has already been deleted. Callers
// hold the mutex.
func (s *grafanaStub) wasDeletedLocked(id string) bool {
	for _, got := range s.deleted {
		if got == id {
			return true
		}
	}
	return false
}

// grafanaErr answers the way Grafana does, with a messageId beside the message.
func grafanaErr(w http.ResponseWriter, status int, messageID, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"messageId": messageID,
		"message":   message,
	})
}

func grafanaRoleOf(accountID string) string {
	if accountID == grafanaAccountEditor {
		return "Editor"
	}
	return "Viewer"
}

func mustAtoi(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
