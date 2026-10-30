package core

import (
	"context"
	"errors"

	"github.com/stephnangue/warden/logical"
)

// backendSealerPrefix starts the context every backend-sealed value is bound
// to. No value core seals for itself (a ticket) and no storage path starts with
// it, so nothing a backend seals can be opened as either.
const backendSealerPrefix = "backend/"

// minSealedLen is the shortest barrier ciphertext: term (4), version (1),
// nonce (12) and GCM tag (16).
const minSealedLen = 4 + 1 + 12 + 16

var (
	errSealerPurpose = errors.New("sealer purpose must be non-empty")
	errSealedFormat  = errors.New("sealed value is malformed")
)

// backendSealer implements logical.Sealer for one mount over the barrier's
// in-memory encryption. Every value is bound, as the GCM additional data, to
// "backend/<mount accessor>/<purpose>": a backend chooses only the purpose, so
// it can neither forge a value under another mount's context nor under one core
// uses for itself. A purpose may hold slashes: an accessor holds none, so the
// context still names exactly one mount.
type backendSealer struct {
	core     *Core
	accessor string
}

var _ logical.Sealer = (*backendSealer)(nil)

// newBackendSealer returns the sealer of the mount with accessor, or nil when
// the accessor is empty (a mount without one cannot be bound to).
func newBackendSealer(c *Core, accessor string) logical.Sealer {
	if c == nil || accessor == "" {
		return nil
	}
	return &backendSealer{core: c, accessor: accessor}
}

func (s *backendSealer) context(purpose string) (string, error) {
	if purpose == "" {
		return "", errSealerPurpose
	}
	return backendSealerPrefix + s.accessor + "/" + purpose, nil
}

// Seal encrypts plaintext under the active barrier key, bound to this mount and
// purpose.
func (s *backendSealer) Seal(ctx context.Context, purpose string, plaintext []byte) ([]byte, error) {
	aad, err := s.context(purpose)
	if err != nil {
		return nil, err
	}
	return s.core.barrier.Encrypt(ctx, aad, plaintext)
}

// Open returns the plaintext Seal sealed for this mount and purpose. It refuses
// a value not in the current barrier format before decrypting, since the
// earlier format ignores the context the value is bound to.
func (s *backendSealer) Open(ctx context.Context, purpose string, ciphertext []byte) ([]byte, error) {
	aad, err := s.context(purpose)
	if err != nil {
		return nil, err
	}
	if !boundCiphertext(ciphertext) {
		return nil, errSealedFormat
	}
	return s.core.barrier.Decrypt(ctx, aad, ciphertext)
}

// boundCiphertext reports whether ciphertext is long enough to be a barrier
// ciphertext and carries the format version that binds its context: the
// barrier decrypts a version-1 value with no additional data whatever context
// the caller names, so such a value must be refused before decrypting.
func boundCiphertext(ciphertext []byte) bool {
	return len(ciphertext) >= minSealedLen && ciphertext[4] == AESGCMVersion2
}
