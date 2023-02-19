package db

import (
	"io/fs"
	"net/url"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/sirupsen/logrus"
)

func NewMigration(logger *logrus.Logger, files fs.FS, u *url.URL) (*migrate.Migrate, error) {
	source, err := iofs.New(files, ".")
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, u.String())
	if err != nil {
		return nil, err
	}
	m.Log = &migrateLogger{Logger: logger, verbose: true}
	return m, nil
}

type migrateLogger struct {
	*logrus.Logger
	verbose bool
}

func (l *migrateLogger) Verbose() bool {
	return l.verbose
}
