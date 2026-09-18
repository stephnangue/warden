package anthropic

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/httpproxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// betaRequest is a request carrying an api_key credential and one anthropic-beta
// header per argument, the way a client that repeats the header sends it.
func betaRequest(betas ...string) *logical.Request {
	r, _ := http.NewRequest(http.MethodPost, "/v1/messages", nil)
	for _, b := range betas {
		r.Header.Add("anthropic-beta", b)
	}
	return &logical.Request{
		HTTPRequest: r,
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": notARealKey},
		},
	}
}

// write applies a config write the way the framework does: to a copy of the
// live state, with only the fields the write carried.
func write(state map[string]any, raw map[string]any) (map[string]any, error) {
	return onConfigWrite(&framework.FieldData{Raw: raw, Schema: extraConfigFields}, maps.Clone(state))
}

func mustWrite(t *testing.T, state map[string]any, raw map[string]any) map[string]any {
	t.Helper()
	got, err := write(state, raw)
	require.NoError(t, err)
	return got
}

// extractorFor returns the extractor the gateway would use for this state:
// ResolveUpstream's when it offers one, the spec's otherwise.
func extractorFor(t *testing.T, state map[string]any) httpproxy.CredentialExtractor {
	t.Helper()
	if d, ok := resolveUpstream(nil, "", state); ok {
		require.NotNil(t, d.ExtractCredentials)
		return d.ExtractCredentials
	}
	return Spec.ExtractCredentials
}

// betasSent runs the extractor for state and returns the anthropic-beta value it
// would send, and whether it sends one at all.
func betasSent(t *testing.T, state map[string]any, client ...string) (string, bool) {
	t.Helper()
	headers, err := extractorFor(t, state)(betaRequest(client...))
	require.NoError(t, err)
	v, ok := headers["anthropic-beta"]
	return v, ok
}

// ---- anthropic-version ----

// A mount whose persisted config predates the field, or that never wrote one,
// has no version in state. It must still send one: the upstream refuses a
// request without it, and the strip has already removed the client's.
func TestVersion_DefaultWhenStateHasNone(t *testing.T) {
	assert.Equal(t, DefaultAnthropicVersion, dynamicHeaders(map[string]any{})["anthropic-version"])

	upgraded := onInitialize(map[string]any{"anthropic_url": "https://api.anthropic.com"}, map[string]any{})
	assert.Equal(t, DefaultAnthropicVersion, dynamicHeaders(upgraded)["anthropic-version"])
}

func TestVersion_Configured(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"anthropic_version": "2024-01-01"})
	assert.Equal(t, "2024-01-01", dynamicHeaders(state)["anthropic-version"])
}

// Writing an empty version is how an operator returns to the default. It must
// not leave an empty header behind — DynamicHeaders would set it as-is.
func TestVersion_EmptyRestoresDefault(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"anthropic_version": "2024-01-01"})
	state = mustWrite(t, state, map[string]any{"anthropic_version": ""})
	assert.Equal(t, DefaultAnthropicVersion, dynamicHeaders(state)["anthropic-version"])
}

func TestVersion_InvalidRefused(t *testing.T) {
	for _, bad := range []string{"2023 06 01", "2023-06-01,2024-01-01", "v1;x"} {
		_, err := write(map[string]any{}, map[string]any{"anthropic_version": bad})
		assert.ErrorContains(t, err, "anthropic_version", "value %q", bad)
	}
}

// The version depends on DynamicHeaders running. A dispatch that skipped them
// would strip the client's version and put none back.
func TestResolveUpstream_NeverSkipsDynamicHeaders(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_required": "a-2026-01-01"})
	d, ok := resolveUpstream(nil, "", state)
	require.True(t, ok)
	assert.False(t, d.SkipDynamicHeaders)

	// Nothing else is overridden: the mount's URL, size cap and body parsing stand.
	assert.Empty(t, d.UpstreamURL)
	assert.Zero(t, d.MaxBodySize)
	assert.False(t, d.BypassBodyParsing)
}

// A mount whose config was never written has no extractor in state, and falls
// back to the spec's, which passes betas through.
func TestResolveUpstream_EmptyStateFallsBack(t *testing.T) {
	_, ok := resolveUpstream(nil, "", map[string]any{})
	assert.False(t, ok)

	got, sent := betasSent(t, map[string]any{}, "a-2026-01-01")
	assert.True(t, sent)
	assert.Equal(t, "a-2026-01-01", got)
}

// ---- anthropic-beta policy ----

// With no policy the client's single header must reach the upstream exactly as
// sent — spacing included — so that a mount nobody configured behaves as before.
func TestBetas_PassThroughIsByteIdentical(t *testing.T) {
	got, sent := betasSent(t, map[string]any{}, "a-2026-01-01, b-2026-01-01")
	assert.True(t, sent)
	assert.Equal(t, "a-2026-01-01, b-2026-01-01", got)
}

// Repeated headers are legal upstream, but the extractor returns one value per
// name, so they are joined.
func TestBetas_PassThroughJoinsRepeatedHeaders(t *testing.T) {
	got, _ := betasSent(t, map[string]any{}, "a-2026-01-01", "b-2026-01-01")
	assert.Equal(t, "a-2026-01-01,b-2026-01-01", got)
}

// No beta anywhere means no header — not an empty one.
func TestBetas_NoneSentMeansNoHeader(t *testing.T) {
	_, sent := betasSent(t, map[string]any{})
	assert.False(t, sent)
}

func TestBetas_AllowlistFilters(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_allowlist": "a-2026-01-01,c-2026-01-01"})
	got, _ := betasSent(t, state, "a-2026-01-01,b-2026-01-01", "c-2026-01-01")
	assert.Equal(t, "a-2026-01-01,c-2026-01-01", got)
}

// "" is the strictest setting: no client beta passes. Only what the operator
// requires is sent.
func TestBetas_EmptyAllowlistPassesNone(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_allowlist": ""})
	_, sent := betasSent(t, state, "a-2026-01-01")
	assert.False(t, sent)

	state = mustWrite(t, state, map[string]any{"beta_required": "r-2026-01-01"})
	got, _ := betasSent(t, state, "a-2026-01-01")
	assert.Equal(t, "r-2026-01-01", got)
}

// "*" is how an operator returns to pass-through after setting a list.
func TestBetas_StarRestoresPassThrough(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_allowlist": "a-2026-01-01"})
	state = mustWrite(t, state, map[string]any{"beta_allowlist": "*"})
	got, _ := betasSent(t, state, "b-2026-01-01")
	assert.Equal(t, "b-2026-01-01", got)
}

// Required values are added after the client's, and once only — whether the
// client already sent one or not.
func TestBetas_RequiredMergedOnce(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_required": "r-2026-01-01,a-2026-01-01"})

	got, _ := betasSent(t, state, "a-2026-01-01")
	assert.Equal(t, "a-2026-01-01,r-2026-01-01", got)

	got, _ = betasSent(t, state)
	assert.Equal(t, "r-2026-01-01,a-2026-01-01", got)
}

// A required value is sent even when the allowlist would drop it from a client.
func TestBetas_RequiredIgnoresAllowlist(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{
		"beta_allowlist": "a-2026-01-01",
		"beta_required":  "r-2026-01-01",
	})
	got, _ := betasSent(t, state, "r-2026-01-01", "x-2026-01-01")
	assert.Equal(t, "r-2026-01-01", got)
}

func TestBetas_DuplicatesCollapsed(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_allowlist": "a-2026-01-01"})
	got, _ := betasSent(t, state, "a-2026-01-01,a-2026-01-01", "a-2026-01-01")
	assert.Equal(t, "a-2026-01-01", got)
}

// A request with no HTTP request attached still authenticates.
func TestBetas_NilHTTPRequest(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_required": "r-2026-01-01"})
	headers, err := extractorFor(t, state)(&logical.Request{
		Credential: &credential.Credential{
			Type: credential.TypeAPIKey,
			Data: map[string]string{"api_key": notARealKey},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "r-2026-01-01", headers["anthropic-beta"])
	assert.Equal(t, notARealKey, headers["x-api-key"])
}

// The beta policy must not get in the way of a credential failure being
// reported as one.
func TestBetas_CredentialErrorPropagates(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_required": "r-2026-01-01"})
	_, err := extractorFor(t, state)(&logical.Request{})
	assert.ErrorContains(t, err, "no credential available")
}

// largeBetaHeader is a header about the size the server accepts, packed with
// distinct names: the input a client would send to make the merge work hardest.
func largeBetaHeader() (string, int) {
	var b strings.Builder
	n := 0
	for ; b.Len() < 1<<20-16; n++ {
		if n > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%x", n)
	}
	return b.String(), n
}

// The client controls this header, so the merge must stay linear in it. Dedup by
// scanning alone took about fifteen seconds of CPU on this input — per request.
// The bound is loose enough for a race build and a busy machine, and still an
// order of magnitude under the quadratic time.
func TestBetas_MergeIsLinearInClientInput(t *testing.T) {
	header, n := largeBetaHeader()
	for name, p := range map[string]*betaPolicy{
		"required beta set": {required: []string{"user-profiles-2026-09-04"}},
		"pass-through":      passThroughBetas,
	} {
		client := []string{header, "x"} // two lines, so pass-through leaves its fast path
		start := time.Now()
		got := p.merge(client)
		elapsed := time.Since(start)

		assert.Less(t, elapsed, 2*time.Second, "%s: %d names took %v", name, n, elapsed)
		assert.Equal(t, n+1+len(p.required), strings.Count(got, ",")+1, name)
	}
}

// Dedup must still hold once the scan has handed over to the set, including for
// a name first seen while scanning and repeated after the handover.
func TestBetas_DedupPastLinearThreshold(t *testing.T) {
	var names []string
	for i := range betaNamesLinearMax + 5 {
		names = append(names, fmt.Sprintf("n%d", i))
	}
	client := strings.Join(names, ",") + ",n0,n3," + names[len(names)-1]

	p := &betaPolicy{required: []string{"n1", "r"}}
	assert.Equal(t, strings.Join(names, ",")+",r", p.merge([]string{client}))
}

func BenchmarkBetaMerge(b *testing.B) {
	header, _ := largeBetaHeader()
	for name, client := range map[string][]string{
		"typical": {"context-management-2025-06-27,prompt-caching-2024-07-31"},
		"1 MiB":   {header},
	} {
		p := &betaPolicy{required: []string{"user-profiles-2026-09-04"}}
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				p.merge(client)
			}
		})
	}
}

// ---- validation ----

func TestConfigWrite_InvalidBetasRefused(t *testing.T) {
	cases := map[string]map[string]any{
		"space in a name":      {"beta_allowlist": "a b"},
		"separator in a name":  {"beta_required": "a;b"},
		"star in a list":       {"beta_allowlist": "a-2026-01-01,*"},
		"star as required":     {"beta_required": "*"},
		"header-breaking byte": {"beta_required": "a\nb"},
	}
	for name, raw := range cases {
		_, err := write(map[string]any{}, raw)
		assert.Error(t, err, name)
	}
}

// A list given as a JSON array is the natural mistake for these fields. On a
// config write it is refused before onConfigWrite runs: the framework checks
// every field against its declared type first. That check is what lets
// onConfigWrite read the fields with GetOk, which would panic on such a value, so
// it is pinned here against the provider's own schema.
func TestConfigWrite_FrameworkRefusesNonStringBeforeTheHook(t *testing.T) {
	for _, k := range []string{"anthropic_version", "beta_allowlist", "beta_required"} {
		fd := &framework.FieldData{Raw: map[string]any{k: []any{"a-2026-01-01"}}, Schema: extraConfigFields}
		assert.Error(t, fd.Validate(), k)
	}
}

// At enable time nothing checks types first: the config arrives as an untyped
// map. Read as absent, an allowlist given as an array would mean "*" and pass
// every client beta, so the hook refuses it itself.
func TestValidateExtraConfig_NonStringAllowlistRefused(t *testing.T) {
	err := validateExtraConfig(map[string]any{"beta_allowlist": []any{"a-2026-01-01"}})
	assert.ErrorContains(t, err, "beta_allowlist: must be a string")
}

// No write through the API can store a value of the wrong type; this guards a
// config edited in storage, or written by a release that checked differently. It
// is treated like any other unparseable value: fail closed, never open.
func TestPersistence_NonStringAllowlistFailsClosed(t *testing.T) {
	state := onInitialize(map[string]any{"beta_allowlist": []any{"a-2026-01-01"}}, map[string]any{})
	_, sent := betasSent(t, state, "a-2026-01-01")
	assert.False(t, sent)
}

// Blank entries are not errors: a trailing comma should not fail a write.
func TestConfigWrite_BlankEntriesSkipped(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_required": " r-2026-01-01 , ,"})
	got, _ := betasSent(t, state)
	assert.Equal(t, "r-2026-01-01", got)
}

// Writes are partial. A write naming one field must leave the others in force,
// which only holds if validation and the rebuilt policy see the merged state
// rather than the fields of the one write.
func TestConfigWrite_PartialWriteKeepsOtherFields(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{
		"anthropic_version": "2024-01-01",
		"beta_allowlist":    "a-2026-01-01",
	})
	state = mustWrite(t, state, map[string]any{"beta_required": "r-2026-01-01"})

	got, _ := betasSent(t, state, "a-2026-01-01", "x-2026-01-01")
	assert.Equal(t, "a-2026-01-01,r-2026-01-01", got, "the earlier allowlist still applies")
	assert.Equal(t, "2024-01-01", dynamicHeaders(state)["anthropic-version"])
}

// ValidateExtraConfig guards only the config a mount is enabled with; every
// later write goes through OnConfigWrite. Both must refuse the same values.
func TestValidateExtraConfig_SameRulesAsWrite(t *testing.T) {
	assert.NoError(t, validateExtraConfig(map[string]any{}))
	assert.NoError(t, validateExtraConfig(map[string]any{
		"anthropic_version": "2023-06-01",
		"beta_allowlist":    "",
		"beta_required":     "r-2026-01-01",
	}))
	assert.Error(t, validateExtraConfig(map[string]any{"anthropic_version": "2023 06 01"}))
	assert.Error(t, validateExtraConfig(map[string]any{"beta_allowlist": "a b"}))
	assert.Error(t, validateExtraConfig(map[string]any{"beta_required": "*"}))
}

// ---- persistence ----

// OnConfigRead's result is persisted as JSON. A derived value leaking into it —
// the extractor is a func — would make every config write fail to save.
func TestConfigRead_IsPersistable(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{
		"anthropic_version": "2024-01-01",
		"beta_allowlist":    "a-2026-01-01",
		"beta_required":     "r-2026-01-01",
	})
	read := onConfigRead(state)
	_, err := json.Marshal(read)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"anthropic_version": "2024-01-01",
		"beta_allowlist":    "a-2026-01-01",
		"beta_required":     "r-2026-01-01",
	}, read)
}

func TestConfigRead_Defaults(t *testing.T) {
	assert.Equal(t, map[string]any{
		"anthropic_version": DefaultAnthropicVersion,
		"beta_allowlist":    "*",
		"beta_required":     "",
	}, onConfigRead(map[string]any{}))
}

// persistAndReload takes a state through what a restart does to it: read out,
// stored as JSON, loaded back into a fresh state.
func persistAndReload(t *testing.T, state map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(onConfigRead(state))
	require.NoError(t, err)
	var config map[string]any
	require.NoError(t, json.Unmarshal(raw, &config))
	return onInitialize(config, map[string]any{})
}

// The strictest setting has to survive a restart. It is distinguished from the
// default only by the field being present, so a reload that read an absent key
// and an empty one alike would quietly open the mount back up.
func TestPersistence_EmptyAllowlistSurvivesRestart(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_allowlist": ""})
	reloaded := persistAndReload(t, state)

	_, sent := betasSent(t, reloaded, "a-2026-01-01")
	assert.False(t, sent)
}

func TestPersistence_RoundTrip(t *testing.T) {
	state := mustWrite(t, map[string]any{}, map[string]any{
		"anthropic_version": "2024-01-01",
		"beta_allowlist":    "a-2026-01-01",
		"beta_required":     "r-2026-01-01",
	})
	reloaded := persistAndReload(t, state)

	assert.Equal(t, onConfigRead(state), onConfigRead(reloaded))
	got, _ := betasSent(t, reloaded, "a-2026-01-01", "x-2026-01-01")
	assert.Equal(t, "a-2026-01-01,r-2026-01-01", got)
	assert.Equal(t, "2024-01-01", dynamicHeaders(reloaded)["anthropic-version"])
}

// The upgrade case. A mount persisted before these fields existed has none of
// their keys. It must keep passing client betas through: reading the missing
// allowlist as "" would mean "pass none", and silently drop every client beta
// on the first restart after upgrade.
func TestPersistence_UpgradedMountPassesBetasThrough(t *testing.T) {
	upgraded := onInitialize(map[string]any{
		"anthropic_url":  "https://api.anthropic.com",
		"auto_auth_path": "auth/jwt/",
	}, map[string]any{})

	got, sent := betasSent(t, upgraded, "a-2026-01-01")
	assert.True(t, sent)
	assert.Equal(t, "a-2026-01-01", got)
}

// A persisted value that no longer parses cannot have come from a validated
// write; this guards storage edited by hand, or a later release validating more
// strictly. With no error to return, the mount fails closed on client betas. It
// keeps its version and its required betas, which are not in doubt: dropping an
// operator's required beta because an unrelated field failed would break the
// requests that depend on it.
func TestPersistence_CorruptBetaConfigFailsClosed(t *testing.T) {
	state := onInitialize(map[string]any{
		"anthropic_version": "2024-01-01",
		"beta_allowlist":    "a b",
		"beta_required":     "r-2026-01-01",
	}, map[string]any{})

	got, sent := betasSent(t, state, "a-2026-01-01")
	assert.True(t, sent)
	assert.Equal(t, "r-2026-01-01", got, "the client's beta is dropped, the operator's kept")
	assert.Equal(t, "2024-01-01", dynamicHeaders(state)["anthropic-version"])

	// Required betas that themselves fail to parse are dropped with the rest.
	state = onInitialize(map[string]any{"beta_required": "not a beta"}, map[string]any{})
	_, sent = betasSent(t, state, "a-2026-01-01")
	assert.False(t, sent)
}

// ---- concurrency ----

// A write builds a new policy into a copy of the state and swaps it in; it never
// changes the one a request already holds. A request that captured the state
// before the write must finish with the old policy, whole.
func TestConcurrency_WriteDoesNotMutateCapturedState(t *testing.T) {
	before := mustWrite(t, map[string]any{}, map[string]any{"beta_allowlist": "a-2026-01-01"})
	captured := extractorFor(t, before)

	_ = mustWrite(t, before, map[string]any{"beta_allowlist": "b-2026-01-01"})

	headers, err := captured(betaRequest("a-2026-01-01", "b-2026-01-01"))
	require.NoError(t, err)
	assert.Equal(t, "a-2026-01-01", headers["anthropic-beta"])

	got, _ := betasSent(t, before, "a-2026-01-01", "b-2026-01-01")
	assert.Equal(t, "a-2026-01-01", got, "the pre-write state is untouched")
}

// Mirrors how the framework shares state: readers take the reference under a
// read lock and use it unlocked; a writer builds a replacement from a shallow
// copy and swaps the reference under the write lock. Run with -race.
//
// The copy is shallow, so the nested values — the version map, the extractor —
// are shared between the old state and the new. What this guards is that a write
// replaces them rather than changing them in place; the writer changes the
// version and the policy on every pass, and readers range over the version map as
// the framework does, so an in-place change would race.
func TestConcurrency_ReadersAndWriter(t *testing.T) {
	var mu sync.RWMutex
	state := mustWrite(t, map[string]any{}, map[string]any{"beta_required": "r-2026-01-01"})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				mu.RLock()
				s := state
				mu.RUnlock()

				if d, ok := resolveUpstream(nil, "", s); ok {
					if _, err := d.ExtractCredentials(betaRequest("a-2026-01-01")); err != nil {
						t.Error(err)
						return
					}
				}
				for k, v := range dynamicHeaders(s) {
					_, _ = k, v
				}
			}
		}()
	}

	for i := range 200 {
		allowlist, version := "a-2026-01-01", fmt.Sprintf("2024-01-%02d", i%28+1)
		if i%2 == 0 {
			allowlist = "*"
		}
		mu.Lock()
		next, err := onConfigWrite(
			&framework.FieldData{
				Raw:    map[string]any{"beta_allowlist": allowlist, "anthropic_version": version},
				Schema: extraConfigFields,
			},
			maps.Clone(state))
		if err == nil {
			state = next
		}
		mu.Unlock()
		require.NoError(t, err)
	}

	close(stop)
	wg.Wait()
}
