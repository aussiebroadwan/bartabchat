package sqlite

import (
	"context"
	"database/sql"

	"github.com/aussiebroadwan/bartab/internal/auth/store"
	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/gen"
)

type txStore struct {
	tx *sql.Tx
	q  *gen.Queries
}

func newTx(tx *sql.Tx) *txStore {
	return &txStore{
		tx: tx,
		q:  gen.New(tx),
	}
}

func (t *txStore) Commit() error   { return t.tx.Commit() }
func (t *txStore) Rollback() error { return t.tx.Rollback() }

func (t *txStore) Close() error { return nil } // nothing to close; caller will commit/rollback and outer DB stays open

// Ping is a no-op for transactions. The connection is already established
// when the transaction is created, so we just return nil.
func (t *txStore) Ping(ctx context.Context) error {
	return nil
}

func (t *txStore) Tx(ctx context.Context) (store.Tx, error) {
	// Nested tx not supported; could emulate with SAVEPOINT if needed
	return nil, sql.ErrTxDone
}

func (t *txStore) WithTx(ctx context.Context, fn func(tx store.Tx) error) error {
	// Nested tx not supported; could emulate with SAVEPOINT if needed
	return sql.ErrTxDone
}

func (t *txStore) Users() store.Users                 { return &usersRepo{q: t.q} }
func (t *txStore) Clients() store.Clients             { return &clientsRepo{q: t.q} }
func (t *txStore) RefreshTokens() store.RefreshTokens { return &refreshTokensRepo{q: t.q} }
func (t *txStore) Invites() store.Invites             { return &invitesRepo{q: t.q} }
func (t *txStore) Roles() store.Roles                 { return &rolesRepo{q: t.q} }
func (t *txStore) BackupCodes() store.BackupCodes     { return &backupCodesRepo{q: t.q} }
func (t *txStore) MFASessions() store.MFASessions     { return &mfaSessionsRepo{q: t.q} }
func (t *txStore) AuthorizationCodes() store.AuthorizationCodes {
	return &authorizationCodesRepo{q: t.q}
}
func (t *txStore) SigningKeys() store.SigningKeys { return &signingKeysRepo{q: t.q} }

func (t *txStore) ApplyMigrations() error { return nil } // no-op; migrations should be applied before starting a tx
