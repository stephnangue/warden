package core

import (
	"context"
	"sync"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stephnangue/warden/core/seal"
	"github.com/stephnangue/warden/logger"
)

type TestSealOpts struct {
	Logger     *logger.GatedLogger
	StoredKeys seal.StoredKeysSupport
	Secret     []byte
	Name       wrapping.WrapperType
}

func NewTestSeal(opts *TestSealOpts) (seal.Access, *ToggleableWrapper) {
	if opts == nil {
		opts = new(TestSealOpts)
	}

	w := &ToggleableWrapper{Wrapper: wrapping.NewTestWrapper(opts.Secret)}
	if opts.Name != "" {
		w.wrapperType = &opts.Name
	}
	return seal.NewAccess(w), w
}

func NewToggleableTestSeal(opts *TestSealOpts) (seal.Access, func(error)) {
	if opts == nil {
		opts = new(TestSealOpts)
	}

	w := &ToggleableWrapper{Wrapper: wrapping.NewTestWrapper(opts.Secret)}
	return seal.NewAccess(w), w.SetError
}

type ToggleableWrapper struct {
	wrapping.Wrapper
	wrapperType *wrapping.WrapperType
	error       error
	l           sync.RWMutex
}

func (t *ToggleableWrapper) Encrypt(ctx context.Context, bytes []byte, opts ...wrapping.Option) (*wrapping.BlobInfo, error) {
	t.l.RLock()
	defer t.l.RUnlock()
	if t.error != nil {
		return nil, t.error
	}
	return t.Wrapper.Encrypt(ctx, bytes, opts...)
}

func (t *ToggleableWrapper) Decrypt(ctx context.Context, info *wrapping.BlobInfo, opts ...wrapping.Option) ([]byte, error) {
	t.l.RLock()
	defer t.l.RUnlock()
	if t.error != nil {
		return nil, t.error
	}
	return t.Wrapper.Decrypt(ctx, info, opts...)
}

func (t *ToggleableWrapper) SetError(err error) {
	t.l.Lock()
	defer t.l.Unlock()
	t.error = err
}

func (t *ToggleableWrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	if t.wrapperType != nil {
		return *t.wrapperType, nil
	}
	return t.Wrapper.Type(ctx)
}

var _ wrapping.Wrapper = &ToggleableWrapper{}
