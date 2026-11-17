package sqlstore

import (
	"context"
	"errors"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/whatsmeow/store"
)

type contactSnapshotContextKey struct{}

// WithContactSnapshotTransaction atomically stores contact names and app-state
// progress when the device stores share this container.
func (s *SQLStore) WithContactSnapshotTransaction(ctx context.Context, contacts store.ContactStore, apply func(context.Context) error) error {
	if contactStore, ok := contacts.(*SQLStore); !ok || contactStore != s {
		return apply(ctx)
	}
	if _, nested := s.db.Execable(ctx).(dbutil.Transaction); nested {
		return errors.New("contact snapshot requires its own transaction")
	}
	err := s.db.DoTxn(context.WithValue(ctx, contactSnapshotContextKey{}, s), nil, apply)
	// A historical push-name write can populate the cache before this transaction
	// commits. Clear it after commit or rollback so subsequent reads see that state.
	s.contactCacheLock.Lock()
	clear(s.contactCache)
	s.contactCacheLock.Unlock()
	return err
}
