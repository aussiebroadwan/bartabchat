package sqlite

import (
	"errors"

	"github.com/aussiebroadwan/bartab/internal/auth/store/drivers/sqlite/migrations"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	_ "modernc.org/sqlite"
)

// ApplyMigrations applies any pending database migrations to the given Store's
// database. It uses the embedded migration files which will be compiled into
// the binary.
//
// We may want to revisit this in the future if we want to support if we want to
// support different databases so we don't have many different embeds bloating
// the binary.
//
// We may also want to make it not apply migrations directly on the store, but
// instead force it through a transaction. But for now this is simpler.
func (m *Store) ApplyMigrations() error {
	// 1. Create the SQLite migration driver
	driver, err := sqlite.WithInstance(m.db, &sqlite.Config{})
	if err != nil {
		return err
	}

	// 2. Create the iofs (embedded filesystem) source driver
	migrationsFilesystem, err := iofs.New(migrations.Migrations, ".")
	if err != nil {
		return err
	}

	// 3. Create the migrate instance to run migrations
	instance, err := migrate.NewWithInstance("iofs", migrationsFilesystem, "", driver)
	if err != nil {
		return err
	}

	// 4. Apply all up migrations
	err = instance.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	return nil
}
