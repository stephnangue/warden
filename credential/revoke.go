package credential

import (
	"context"
	"errors"
)

// RevokeLease revokes leaseID through driver. A lease the source reports gone
// (ErrLeaseGone) is revoked as far as anyone can tell: gone is true and err nil,
// so no caller retries it or reports it as a failure.
func RevokeLease(ctx context.Context, driver SourceDriver, leaseID string) (gone bool, err error) {
	err = driver.Revoke(ctx, leaseID)
	if errors.Is(err, ErrLeaseGone) {
		return true, nil
	}
	return false, err
}
