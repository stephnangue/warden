package helpers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/stephnangue/warden/api"
	"github.com/stephnangue/warden/helper/dpop"
)

// Where the proof key of a session bound to a key is kept (Session.KeyStore).
const (
	KeyStoreOS   = "keystore"
	KeyStoreFile = "file"
)

// EnvSessionKeystore set to "file" keeps proof keys in session files rather
// than the OS keystore, as when the keystore cannot be written: for CI and
// end-to-end runs, which must not write to a person's own keychain.
const EnvSessionKeystore = "WARDEN_SESSION_KEYSTORE"

// keyringService names Warden's items in the OS keystore.
const keyringService = "warden"

// sessionKeyItem names the keystore item holding the proof key of the session
// for addr and ns: the session file's own name, so a new login replaces it.
func sessionKeyItem(addr, ns string) string {
	return "session-" + sessionID(addr, ns)
}

// SetKey makes k s's proof key in memory only, so UseSession signs with it
// before StoreSessionKey keeps it.
func (s *Session) SetKey(k *dpop.Key) { s.key = k }

// StoreSessionKey records k as s's proof key and keeps it: in the OS keystore,
// or in the session file when WARDEN_SESSION_KEYSTORE is "file" or the
// keystore cannot be written, which it says on warn. The choice is made here
// only, at login: a session whose keystore item cannot be read later fails,
// and its key is never moved to the file. s's address and namespace must be
// set. The keystore item replaces the previous session's, so a login calls it
// just before SaveSession: the file and the item change together.
func StoreSessionKey(s *Session, k *dpop.Key, warn io.Writer) error {
	raw, err := k.Bytes()
	if err != nil {
		return err
	}
	enc := base64.RawURLEncoding.EncodeToString(raw)
	s.key, s.KeyStore, s.Key = k, KeyStoreFile, enc
	if strings.EqualFold(os.Getenv(EnvSessionKeystore), KeyStoreFile) {
		return nil
	}
	if err := keyring.Set(keyringService, sessionKeyItem(s.Addr, s.Namespace), enc); err != nil {
		fmt.Fprintf(warn, "Warning: the OS keystore could not be written (%v); the session's key is kept in the session file instead.\n", err)
		return nil
	}
	s.KeyStore, s.Key = KeyStoreOS, ""
	return nil
}

// DeleteSessionKey removes s's proof key from the OS keystore, if it is kept
// there; none is not an error.
func DeleteSessionKey(s *Session) error {
	if s == nil || s.KeyStore != KeyStoreOS {
		return nil
	}
	err := keyring.Delete(keyringService, sessionKeyItem(s.Addr, s.Namespace))
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("removing the session's key from the OS keystore: %w", err)
	}
	return nil
}

// loadKey loads s's proof key, if s is bound to one, from where it is kept.
func (s *Session) loadKey() error {
	if s.key != nil {
		return nil
	}
	var enc string
	switch s.KeyStore {
	case "":
		return nil
	case KeyStoreFile:
		enc = s.Key
	case KeyStoreOS:
		v, err := keyring.Get(keyringService, sessionKeyItem(s.Addr, s.Namespace))
		if err != nil {
			return fmt.Errorf("the session's key could not be read from the OS keystore: %w; run warden login", err)
		}
		enc = v
	default:
		return fmt.Errorf("the session keeps its key in %q, which this version does not know; run warden login", s.KeyStore)
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return errors.New("the session's key is malformed; run warden login")
	}
	k, err := dpop.ParseKey(raw)
	if err != nil {
		return fmt.Errorf("the session's key is malformed: %w; run warden login", err)
	}
	s.key = k
	return nil
}

// Bound reports whether s's ticket is bound to a key, so it is accepted only
// with a proof signed by that key.
func (s *Session) Bound() bool { return s.KeyStore != "" }

// UseSession makes client present s: its ticket and, when it is bound to a
// key, a proof of that key on every request carrying it. It fails when the key
// cannot be loaded, rather than send a ticket that cannot be used without it.
func UseSession(client *api.Client, s *Session) error {
	if err := s.loadKey(); err != nil {
		return err
	}
	client.SetToken(s.Token)
	client.SetRequestSigner(nil)
	if s.key != nil {
		client.SetRequestSigner(ProofSigner(client.Address(), s.key, s.Token))
	}
	return nil
}

// ProofSigner returns the signer that proves k on every request carrying
// ticket on X-Warden-Token, for a client of the Warden at addr: a fresh proof
// per attempt over the request as it is sent, its method, path, selectors,
// content type, query and body. The path is signed relative to addr's own, as
// the server sees it behind a load balancer that strips that prefix. With no
// ticket it signs the login proof of every request carrying none: method and
// path only, as the login's callback takes it.
func ProofSigner(addr string, k *dpop.Key, ticket string) api.RequestSigner {
	base := ""
	if u, err := url.Parse(addr); err == nil {
		base = strings.TrimRight((&url.URL{Path: u.Path}).EscapedPath(), "/")
	}
	var ath string
	if ticket != "" {
		ath = dpop.Hash([]byte(ticket))
	}
	return func(req *http.Request) {
		req.Header.Del(dpop.HeaderName)
		if req.Header.Get(api.TokenHeaderName) != ticket {
			return
		}
		path := req.URL.EscapedPath()
		if base != "" && (path == base || strings.HasPrefix(path, base+"/")) {
			path = path[len(base):]
		}
		c := dpop.Claims{
			Method:   req.Method,
			URL:      req.URL.Scheme + "://" + req.URL.Host + path,
			IssuedAt: time.Now(),
			ATH:      ath,
		}
		if ticket != "" {
			body, err := requestBody(req)
			if err != nil {
				return
			}
			h := req.Header
			c.Context = &dpop.Context{
				Role:        h.Get(api.RoleHeaderName),
				Namespace:   h.Get(api.NamespaceHeaderName),
				Provider:    h.Get(api.ProviderHeaderName),
				Request:     h.Get("X-Warden-Request"),
				ContentType: h.Get("Content-Type"),
				Query:       dpop.Hash([]byte(req.URL.RawQuery)),
				Body:        dpop.Hash(body),
			}
		}
		proof, err := k.Sign(c)
		if err != nil {
			return
		}
		req.Header.Set(dpop.HeaderName, proof)
	}
}

// maxClockSkew is how far the local clock may be from the server's before a
// refused proof is put down to it: within the proof window, with a margin.
const maxClockSkew = dpop.Window - 5*time.Second

// ProofRefusal says why the server refused err's proof of a session's key, and
// what to do, when it did; "" for any other error. A refused proof is never a
// reason to sign in again by itself: a clock off the server's would refuse the
// next session's proofs alike.
func ProofRefusal(err error) string {
	code := proofChallenge(err)
	if code != "" && api.ReadWardenVariable(api.EnvWardenToken) != "" {
		return "a session token bound to a key works only with the key warden login keeps with it: unset WARDEN_TOKEN to use the saved session"
	}
	switch code {
	case "invalid_token":
		return "a session token bound to a key is refused as a bearer token: only warden commands, which prove its key, can present it"
	case "invalid_dpop_proof":
		if skew, ok := ProofClockSkew(err); ok {
			return fmt.Sprintf("this machine's clock is %s off the server's; correct it", skew.Round(time.Second))
		}
		return "the session's key was not accepted; sign in again with warden login -force"
	}
	return ""
}

// ProofClockSkew returns how far this machine's clock is ahead of the server's
// when err refuses a proof and the server's Date puts the two further apart
// than a proof's window allows.
func ProofClockSkew(err error) (time.Duration, bool) {
	var re *api.ResponseError
	if proofChallenge(err) != "invalid_dpop_proof" || !errors.As(err, &re) {
		return 0, false
	}
	d, perr := http.ParseTime(re.Header.Get("Date"))
	if perr != nil {
		return 0, false
	}
	skew := time.Since(d)
	return skew, skew > maxClockSkew || skew < -maxClockSkew
}

// proofChallenge returns the error a 401's DPoP challenge names, or "".
func proofChallenge(err error) string {
	var re *api.ResponseError
	if !errors.As(err, &re) || re.StatusCode != http.StatusUnauthorized || re.Header == nil {
		return ""
	}
	challenge := re.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "DPoP ") {
		return ""
	}
	for _, code := range []string{"invalid_token", "invalid_dpop_proof"} {
		if strings.Contains(challenge, `error="`+code+`"`) {
			return code
		}
	}
	return ""
}

// requestBody returns req's body without consuming it, through GetBody.
func requestBody(req *http.Request) ([]byte, error) {
	if req.GetBody == nil {
		if req.Body == nil || req.Body == http.NoBody {
			return nil, nil
		}
		return nil, errors.New("the request body cannot be read twice")
	}
	rc, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}
