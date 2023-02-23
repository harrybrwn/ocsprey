package sqlca

import (
	"embed"
	"io/fs"
	"net/url"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/sirupsen/logrus"
	"gopkg.hrry.dev/ocsprey/internal/db"
)

//go:embed migrations
var migrations embed.FS

func MigrateUp(logger *logrus.Logger, databaseURL *url.URL) (err error) {
	m, err := newMigration(logger, databaseURL)
	if err != nil {
		return err
	}
	defer func() {
		serr, derr := m.Close()
		if serr != nil && err == nil {
			err = serr
		}
		if derr != nil && err == nil {
			err = derr
		}
	}()
	err = m.Up()
	if err == migrate.ErrNoChange {
		err = nil
	}
	return
}

func MigrateDown(logger *logrus.Logger, databaseURL *url.URL) (err error) {
	m, err := newMigration(logger, databaseURL)
	if err != nil {
		return err
	}
	defer func() {
		serr, derr := m.Close()
		if serr != nil && err == nil {
			err = serr
		}
		if derr != nil && err == nil {
			err = derr
		}
	}()
	err = m.Down()
	if err == migrate.ErrNoChange {
		err = nil
	}
	return
}

func newMigration(logger *logrus.Logger, u *url.URL) (*migrate.Migrate, error) {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, err
	}
	return db.NewMigration(logger, sub, u)
}
