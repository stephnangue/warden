package credential

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/logger"
)

// plainMintDriver implements SourceDriver only.
type plainMintDriver struct {
	mintCalled   bool
	revokeCalled bool
	leaseID      string
}

func (d *plainMintDriver) MintCredential(ctx context.Context, spec *CredSpec) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.mintCalled = true
	return map[string]interface{}{"k": "v"}, nil, time.Hour, d.leaseID, nil
}
func (d *plainMintDriver) Revoke(ctx context.Context, leaseID string) error { d.revokeCalled = true; return nil }
func (d *plainMintDriver) Type() string                                     { return "plain" }
func (d *plainMintDriver) Cleanup(ctx context.Context) error                { return nil }

// exchangeDriver implements SourceDriver and ExchangeMinter.
type exchangeDriver struct {
	plainMintDriver
	exchangeCalled bool
	exchangeCount  atomic.Int32
	gotInputs      *ExchangeInputs
}

func (d *exchangeDriver) MintCredentialWithExchange(ctx context.Context, spec *CredSpec, inputs *ExchangeInputs) (map[string]interface{}, map[string]interface{}, time.Duration, string, error) {
	d.exchangeCalled = true
	d.exchangeCount.Add(1)
	d.gotInputs = inputs
	// Return a value derived from the subject token so distinct inputs yield
	// distinguishable credential data.
	return map[string]interface{}{"username": inputs.SubjectToken, "password": "x"}, nil, time.Hour, "", nil
}

var _ ExchangeMinter = (*exchangeDriver)(nil)

func newTestMintingService() *MintingService {
	log, _ := logger.NewGatedLogger(logger.DefaultConfig(), logger.GatedWriterConfig{})
	return NewMintingService(log)
}

func validExchangeInputs() *ExchangeInputs {
	return &ExchangeInputs{
		SubjectToken:       "eyJ.sub",
		SubjectTokenType:   TokenTypeJWT,
		SubjectTokenOrigin: ExchangeOriginUnverified,
	}
}

func TestMintWithCleanup_NilInputs_UsesPlainMint(t *testing.T) {
	s := newTestMintingService()
	d := &exchangeDriver{} // implements ExchangeMinter, but nil inputs must skip it
	spec := &CredSpec{Name: "s", Source: "src"}

	err := s.MintWithCleanup(context.Background(), d, spec, nil, func(rawData, metadata map[string]interface{}, ttl time.Duration, leaseID string) error {
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.mintCalled {
		t.Error("expected MintCredential to be called")
	}
	if d.exchangeCalled {
		t.Error("MintCredentialWithExchange must not be called when inputs are nil")
	}
}

func TestMintWithCleanup_Inputs_UsesExchangeMint(t *testing.T) {
	s := newTestMintingService()
	d := &exchangeDriver{}
	spec := &CredSpec{Name: "s", Source: "src"}
	inputs := validExchangeInputs()

	var gotRaw map[string]interface{}
	err := s.MintWithCleanup(context.Background(), d, spec, inputs, func(rawData, metadata map[string]interface{}, ttl time.Duration, leaseID string) error {
		gotRaw = rawData
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.exchangeCalled {
		t.Error("expected MintCredentialWithExchange to be called")
	}
	if d.mintCalled {
		t.Error("plain MintCredential must not be called when inputs are present")
	}
	if d.gotInputs != inputs {
		t.Error("exchange inputs were not forwarded to the driver")
	}
	if gotRaw["username"] != inputs.SubjectToken {
		t.Errorf("onSuccess did not receive the exchange mint output: %v", gotRaw)
	}
}

func TestMintWithCleanup_Inputs_PlainDriver_FailsClosed(t *testing.T) {
	s := newTestMintingService()
	d := &plainMintDriver{leaseID: "lease-x"} // NOT an ExchangeMinter
	spec := &CredSpec{Name: "s", Source: "src"}

	onSuccessCalled := false
	err := s.MintWithCleanup(context.Background(), d, spec, validExchangeInputs(), func(rawData, metadata map[string]interface{}, ttl time.Duration, leaseID string) error {
		onSuccessCalled = true
		return nil
	})
	if err == nil {
		t.Fatal("expected fail-closed error for a non-ExchangeMinter driver")
	}
	if !strings.Contains(err.Error(), "does not accept token-exchange inputs") {
		t.Errorf("unexpected error text: %v", err)
	}
	if d.mintCalled {
		t.Error("plain mint must not run when inputs are present but unsupported")
	}
	if onSuccessCalled {
		t.Error("onSuccess must not run when the dispatch fails closed")
	}
	if d.revokeCalled {
		t.Error("no lease was minted, so no orphaned-lease revoke should occur")
	}
}
