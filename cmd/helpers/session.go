package helpers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Session is what warden login keeps between commands: one Warden address and
// namespace's session ticket, the auth mount that issued it, and the role
// commands run under. One file per address and namespace, so several clusters
// and namespaces coexist.
type Session struct {
	Addr      string    `json:"addr"`
	Namespace string    `json:"namespace"`
	Mount     string    `json:"mount"`
	Token     string    `json:"token"`
	Role      string    `json:"role,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the session's ticket has expired at now.
func (s *Session) Expired(now time.Time) bool {
	return !now.Before(s.ExpiresAt)
}

// ErrSessionExpired refuses a command whose only credential is an expired
// session.
var ErrSessionExpired = errors.New("session expired; run warden login")

// sessionDirOverride replaces the session directory; tests set it.
var sessionDirOverride string

// SetSessionDir makes dir the session directory, "" restoring the default.
// Intended for tests.
func SetSessionDir(dir string) { sessionDirOverride = dir }

// SessionDir returns the directory sessions are kept in: ~/.warden/sessions.
func SessionDir() (string, error) {
	if sessionDirOverride != "" {
		return sessionDirOverride, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate the home directory for sessions: %w", err)
	}
	return filepath.Join(home, ".warden", "sessions"), nil
}

// NormalizeAddr returns addr in the one form a session is keyed by: scheme
// and host lower-cased, the default port made explicit, no trailing slash. So
// HTTPS://Host:443/ and https://host name one session.
func NormalizeAddr(addr string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(addr))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid Warden address %q", addr)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	path := strings.TrimRight(u.Path, "/")
	return scheme + "://" + net.JoinHostPort(host, port) + path, nil
}

// NormalizeNamespace returns ns without leading or trailing slashes; "" is the
// root namespace.
func NormalizeNamespace(ns string) string {
	return strings.Trim(strings.TrimSpace(ns), "/")
}

// sessionPath returns the file of the session for addr and ns, both
// normalized: the first 16 hex characters of SHA-256(addr|ns).
func sessionPath(dir, addr, ns string) string {
	sum := sha256.Sum256([]byte(addr + "|" + ns))
	return filepath.Join(dir, hex.EncodeToString(sum[:])[:16]+".json")
}

// SaveSession writes s, replacing the session for its address and namespace.
// The directory is created 0700; the file is written 0600 as a new temporary
// file (O_EXCL) in the same directory and renamed over the target, so a
// reader never sees a partial file and no existing file or link is written
// through.
func SaveSession(s *Session) error {
	dir, err := SessionDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating the session directory: %w", err)
	}
	if err := refuseSymlink(dir); err != nil {
		return err
	}
	// A directory that already existed keeps its mode through MkdirAll.
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm()&^0o700 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("restricting the session directory to its owner: %w", err)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := createExclusive(dir)
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, sessionPath(dir, s.Addr, s.Namespace))
	}
	if werr != nil {
		_ = os.Remove(name)
		return fmt.Errorf("writing the session: %w", werr)
	}
	return nil
}

// createExclusive creates a new 0600 temporary file in dir, failing rather
// than opening one that exists.
func createExclusive(dir string) (*os.File, error) {
	for range 10 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, ".session-"+hex.EncodeToString(b[:])+".tmp")
		f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("creating the session file: %w", err)
		}
	}
	return nil, errors.New("creating the session file: no free temporary name")
}

// LoadSession returns the session for addr and ns (normalized), or nil when
// there is none. It refuses a session file or directory that is a symbolic
// link, and a file whose address or namespace is not the one asked for (a
// hand-edited file, or a collision), so a ticket is never sent to another
// server.
func LoadSession(addr, ns string) (*Session, error) {
	dir, err := SessionDir()
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err := refuseSymlink(dir); err != nil {
		return nil, err
	}
	path := sessionPath(dir, addr, ns)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err := refuseSymlink(path); err != nil {
		return nil, err
	}
	data, err := readNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("reading the session: %w", err)
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("reading the session %s: %w", path, err)
	}
	if s.Addr != addr || s.Namespace != ns {
		return nil, fmt.Errorf("the session file %s is for %s (namespace %q), not %s (namespace %q); remove it",
			path, s.Addr, s.Namespace, addr, ns)
	}
	return &s, nil
}

// FindSession returns the session a command in namespace ns at addr uses:
// that namespace's, else the nearest ancestor's (team-a/dev, then team-a,
// then the root), never a sibling's or a descendant's. A parent's ticket is
// accepted in its children. It returns nil when none exists.
func FindSession(addr, ns string) (*Session, error) {
	for cur := ns; ; {
		s, err := LoadSession(addr, cur)
		if err != nil || s != nil {
			return s, err
		}
		if cur == "" {
			return nil, nil
		}
		if i := strings.LastIndex(cur, "/"); i >= 0 {
			cur = cur[:i]
		} else {
			cur = ""
		}
	}
}

// DeleteSession removes the session for addr and ns; none is not an error.
func DeleteSession(addr, ns string) error {
	dir, err := SessionDir()
	if err != nil {
		return err
	}
	err = os.Remove(sessionPath(dir, addr, ns))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing the session: %w", err)
	}
	return nil
}

func refuseSymlink(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; refusing to use it for a session", path)
	}
	return nil
}

// DisplayNamespace renders a normalized namespace for messages.
func DisplayNamespace(ns string) string {
	if ns == "" {
		return "root"
	}
	return ns
}
