package main

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/ca/inmem"
	"gopkg.hrry.dev/ocsprey/ca/openssl"
	"gopkg.hrry.dev/ocsprey/ca/sqlca"
	"gopkg.hrry.dev/ocsprey/internal/certutil"
	"gopkg.hrry.dev/ocsprey/internal/db"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/server"
	"gopkg.in/yaml.v3"
)

//go:generate sh testdata/gen.sh --regenerate
//go:generate mockgen -package mockca -destination internal/mocks/mockca/mockca.go gopkg.hrry.dev/ocsprey/ca ResponderDB,CertStore
//go:generate mockgen -package mockdb -destination internal/mocks/mockdb/mockdb.go gopkg.hrry.dev/ocsprey/internal/db DB,Rows

func init() {
	os.Unsetenv("PGSERVICEFILE")
}

func main() {
	root := newRootCmd()
	err := root.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		logger     = logrus.New()
		logLevel   = env("LOG_LEVEL", "debug")
		logFormat  = env("LOG_FORMAT", "text")
		configFile = env("OCSP_CONFIG_FILE", "")
		config     = Config{
			hash: crypto.SHA1,
		}
	)
	c := cobra.Command{
		Use:           "ocspray",
		Short:         "OCSP responder tools",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			lvl, err := logrus.ParseLevel(logLevel)
			if err != nil {
				return err
			}
			logger.Level = lvl
			switch strings.ToLower(logFormat) {
			case "text":
				logger.Formatter = &logrus.TextFormatter{}
			case "json":
				logger.Formatter = &logrus.JSONFormatter{}
			default:
				return fmt.Errorf("unknown log format %q", logFormat)
			}
			if exists(configFile) {
				raw, err := os.ReadFile(configFile)
				if err != nil {
					return err
				}
				err = yaml.Unmarshal(raw, &config)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	c.SetContext(log.Stash(context.Background(), logger))
	c.AddCommand(
		newServerCmd(&config, logger),
		newMigrateCmd(&config, logger),
	)
	f := c.PersistentFlags()
	f.StringVar(&logLevel, "log-level", logLevel, "set the logging level (trace, debug, info, warn, error)")
	f.StringVar(&logFormat, "log-format", logFormat, "set the logging format (text, json)")
	f.StringVarP(&configFile, "config", "c", configFile, "configuration file path")
	return &c
}

func newServerCmd(conf *Config, logger *logrus.Logger) *cobra.Command {
	var (
		port       = toInt(env("SERVER_PORT", "8888"))
		certDBType = env("CERT_DB_TYPE", "openssl")
		respDBType = env("RESPONDER_DB_TYPE", "mem")
	)
	c := cobra.Command{
		Use:   "server",
		Short: "OCSP responder server",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				hash      = crypto.SHA1
				authority = inmem.NewResponderDB(hash)
				certdb    = openssl.EmptyIndex()
			)
			if err := conf.DB.InitFromEnv(); err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			ctx = log.Stash(ctx, logger)

			if len(conf.OpenSSL) > 0 {
				err := addOpenSSLConfigs(ctx, certdb, authority, conf)
				if err != nil {
					return err
				}
				if err = certdb.WatchFiles(ctx); err != nil {
					return err
				}
			}

			srv := http.Server{
				Addr:        fmt.Sprintf(":%d", port),
				Handler:     newServerHandler(certdb, authority),
				BaseContext: func(net.Listener) context.Context { return ctx },
			}
			logger.Infof("listening on [::]:%d", port)
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.WithError(err).Error("failed to start server")
					stop()
				}
			}()
			<-ctx.Done()

			logger.Info("shutting down server")
			defer logger.Info("shutdown complete")
			stop()
			downCtx, done := context.WithTimeout(context.Background(), time.Second*30)
			defer done()
			if err := srv.Shutdown(downCtx); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	f := c.Flags()
	f.IntVarP(&port, "port", "p", port, "server port")
	f.StringVarP(&certDBType, "cert-db-type", "t", certDBType, "database type to use")
	f.StringVarP(&respDBType, "responder-db-type", "r", respDBType, "type of database to use for the responder certificates")
	return &c
}

func newMigrateCmd(conf *Config, logger *logrus.Logger) *cobra.Command {
	c := cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations for the sql CA database.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sqlca.MigrateUp(logger, conf.DB.URL())
		},
	}
	return &c
}

func newServerHandler(certdb ca.CertStore, responder ca.ResponderDB) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", server.Responder(responder, certdb))
	mux.Handle("/issuer", server.ControlIssuer(responder))
	mux.Handle("/leaf", server.ControlCert(responder, certdb))
	mux.Handle("/leaf/revoke", server.ControlCertRevoke(responder, certdb))
	return log.HTTPRequests(mux)
}

func env(key, defaultVal string) string {
	v, ok := os.LookupEnv(key)
	if !ok {
		return defaultVal
	}
	return v
}

func toInt(s string) int {
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		panic(err)
	}
	return int(v)
}

func exists(s string) bool {
	_, err := os.Stat(s)
	return !os.IsNotExist(err)
}

type Config struct {
	OpenSSL []OpenSSLIndexConfig `yaml:"openssl" json:"openssl"`
	DB      db.Config            `yaml:"db" json:"db"`
	hash    crypto.Hash
}

type OpenSSLIndexConfig struct {
	BaseDir       string          `yaml:"base_dir" json:"base_dir"`
	IndexFile     string          `yaml:"index_file" json:"index_file"`
	SerialFile    string          `yaml:"serial_file" json:"serial_file"`
	NewCertsDir   string          `yaml:"new_certs_dir" json:"new_certs_dir"`
	RootCA        string          `yaml:"root_ca" json:"root_ca"`
	OCSPResponder ResponderConfig `yaml:"ocsp_responder" json:"ocsp_responder"`
}

type ResponderConfig struct {
	Cert string `yaml:"cert" json:"cert"`
	Key  string `yaml:"key" json:"key"`
}

func addOpenSSLConfigs(ctx context.Context, txt *openssl.IndexTXT, authority ca.ResponderDB, config *Config) error {
	var err error
	for _, cfg := range config.OpenSSL {
		if cfg.BaseDir == "" {
			cfg.BaseDir = "."
		}
		err = txt.AddIndex(&openssl.IndexConfig{
			Index:    filepath.Join(cfg.BaseDir, cfg.IndexFile),
			NewCerts: filepath.Join(cfg.BaseDir, cfg.NewCertsDir),
			CA:       filepath.Join(cfg.BaseDir, cfg.RootCA),
			Serial:   filepath.Join(cfg.BaseDir, cfg.SerialFile),
			Hash:     config.hash,
		})
		if err != nil {
			return err
		}
		responder, err := getResponder(&cfg)
		if err != nil {
			return err
		}
		err = authority.Put(ctx, responder)
		if err != nil {
			return err
		}
	}
	return err
}

func getResponder(cfg *OpenSSLIndexConfig) (*ca.Responder, error) {
	return openResponderKeys(
		filepath.Join(cfg.BaseDir, cfg.RootCA),
		filepath.Join(cfg.BaseDir, cfg.OCSPResponder.Cert),
		filepath.Join(cfg.BaseDir, cfg.OCSPResponder.Key),
	)
}

func openResponderKeys(root, cert, key string) (*ca.Responder, error) {
	var (
		err       error
		responder ca.Responder
	)
	responder.CA, err = certutil.OpenCertificate(root)
	if err != nil {
		return nil, err
	}
	responder.Signer.Cert, err = certutil.OpenCertificate(cert)
	if err != nil {
		return nil, err
	}
	responder.Signer.Key, err = certutil.OpenKey(key)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.After(responder.CA.NotAfter) {
		return &responder, fmt.Errorf("responder CA %q is expired", root)
	}
	if now.After(responder.Signer.Cert.NotAfter) {
		return &responder, fmt.Errorf("responder cert %q is expired", cert)
	}
	if now.Before(responder.CA.NotBefore) {
		return &responder, fmt.Errorf("responder CA %q is not yet valid", root)
	}
	if now.Before(responder.Signer.Cert.NotBefore) {
		return &responder, fmt.Errorf("responder cert %q is not yet valid", cert)
	}
	return &responder, nil
}
