package db

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var ErrDBTimeout = errors.New("database ping timeout")

type DB interface {
	io.Closer
	QueryContext(context.Context, string, ...interface{}) (Rows, error)
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
}

type Scanner interface {
	Scan(...interface{}) error
}

type Rows interface {
	Scanner
	io.Closer
	Next() bool
	Err() error
}

func ScanOne(r Rows, dest ...interface{}) (err error) {
	if !r.Next() {
		if err = r.Err(); err != nil {
			r.Close()
			return err
		}
		r.Close()
		return sql.ErrNoRows
	}
	if err = r.Scan(dest...); err != nil {
		r.Close()
		return err
	}
	return r.Close()
}

type dbOptions struct {
	logger logrus.FieldLogger
	// TODO auto logging database
	autoLogging bool
	// TODO create an auto tracing database
	tracing bool
}

type Option func(*dbOptions)

func WithLogger(l logrus.FieldLogger) Option { return func(d *dbOptions) { d.logger = l } }

func New(pool *sql.DB, opts ...Option) *database {
	options := dbOptions{}
	for _, o := range opts {
		o(&options)
	}
	if options.logger == nil {
		options.logger = logrus.StandardLogger()
	}
	d := &database{
		DB:     pool,
		logger: options.logger,
	}
	return d
}

type database struct {
	*sql.DB
	logger logrus.FieldLogger
}

func (db *database) QueryContext(ctx context.Context, query string, v ...interface{}) (Rows, error) {
	return db.DB.QueryContext(ctx, query, v...)
}

type waitOpts struct {
	interval time.Duration
	timeout  time.Duration
}

type WaitOpt func(*waitOpts)

func WithInterval(d time.Duration) WaitOpt {
	return func(wo *waitOpts) { wo.interval = d }
}

func WithTimeout(d time.Duration) WaitOpt {
	return func(wo *waitOpts) { wo.timeout = d }
}

// WaitFor will block until the database is up and can be connected to.
func (db *database) WaitFor(ctx context.Context, opts ...WaitOpt) (err error) {
	wo := waitOpts{
		interval: time.Second * 2,
		timeout:  time.Minute * 5,
	}
	for _, o := range opts {
		o(&wo)
	}

	var cancel context.CancelFunc = func() {}
	if wo.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, wo.timeout)
	}
	defer cancel()

	// Don't wait to send the first ping.
	if err = db.DB.PingContext(ctx); err == nil {
		return nil
	}

	ticker := time.NewTicker(wo.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err = db.Ping()
			if err == nil {
				db.logger.Info("database connected")
				return nil
			}
			db.logger.WithError(err).Warn("failed to ping database, retrying...")
		case <-ctx.Done():
			return errors.Wrap(ErrDBTimeout, "could not reach database")
		}
	}
}

type Config struct {
	Type     string `yaml:"type" json:"type"`
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	User     string `yaml:"user" json:"user"`
	Password string `yaml:"password" json:"password"`
	Database string `yaml:"database" json:"database"`
	SSLMode  string `yaml:"sslmode" json:"sslmode"`
}

func (c *Config) URL() *url.URL {
	var (
		userinfo *url.Userinfo
		path     string
	)
	if len(c.User) > 0 && len(c.Password) > 0 {
		userinfo = url.UserPassword(c.User, c.Password)
	}
	if len(c.Database) > 0 {
		path = filepath.Join("/", c.Database)
	}
	var query = make(url.Values)
	if len(c.SSLMode) > 0 {
		query.Add("sslmode", c.SSLMode)
	}
	if c.Port == 0 {
		c.Port = 5432
	}
	return &url.URL{
		Scheme:   c.Type,
		User:     userinfo,
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     path,
		RawQuery: query.Encode(),
	}
}

func (c *Config) Validate() error {
	switch c.Type {
	case "postgres", "postgresql":
		c.Type = "postgres"
	default:
		return fmt.Errorf("unknown database type %q", c.Type)
	}
	if len(c.Host) == 0 {
		return errors.New("no database hostname")
	}
	if c.Port == 0 {
		c.Port = 5432
	}
	return nil
}

func (c *Config) InitFromEnv() (err error) {
	c.Type = strValue(c.Type, "DATABASE_TYPE")
	c.Host = strValue(c.Host, "POSTGRES_HOST")
	c.User = strValue(c.User, "POSTGRES_USER")
	c.Password = strValue(c.Password, "POSTGRES_PASSWORD")
	c.Database = strValue(c.Database, "POSTGRES_DB")
	c.SSLMode = strValue(c.SSLMode, "POSTGRES_SSLMODE")
	port := os.Getenv("POSTGRES_PORT")
	if c.Port == 0 && len(port) > 0 {
		c.Port, err = strconv.Atoi(port)
		if err != nil {
			return err
		}
	}
	return nil
}

func strValue(val, envkey string) string {
	if len(val) == 0 {
		return os.Getenv(envkey)
	}
	return val
}
