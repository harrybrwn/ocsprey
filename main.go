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
	"gopkg.hrry.dev/ocsprey/internal/certutil"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/server"
	"gopkg.in/yaml.v3"
)

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
	c.AddCommand(newServerCmd(&config, logger))
	f := c.PersistentFlags()
	f.StringVar(&logLevel, "log-level", logLevel, "set the logging level (trace, debug, info, warn, error)")
	f.StringVar(&logFormat, "log-format", logFormat, "set the logging format (text, json)")
	f.StringVarP(&configFile, "config", "c", configFile, "configuration file path")
	return &c
}

func newServerCmd(conf *Config, logger *logrus.Logger) *cobra.Command {
	var port = toInt(env("SERVER_PORT", "8888"))
	c := cobra.Command{
		Use:   "server",
		Short: "OCSP responder server",
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				hash      = crypto.SHA1
				authority = inmem.NewResponderDB(hash)
				certdb    = openssl.EmptyIndex()
			)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()

			if len(conf.OpenSSL) > 0 {
				err := addOpenSSLConfigs(ctx, certdb, authority, conf)
				if err != nil {
					return err
				}
				if err = certdb.WatchFiles(ctx); err != nil {
					return err
				}
			}

			mux := http.NewServeMux()
			mux.Handle("/", server.Responder(authority, certdb))
			mux.Handle("/issuer", server.ControlIssuer(authority))
			mux.Handle("/leaf", server.ControlCert(authority, certdb))
			mux.Handle("/leaf/revoke", server.ControlCertRevoke(authority, certdb))

			srv := http.Server{
				Addr:        fmt.Sprintf(":%d", port),
				Handler:     log.HTTPRequests(mux),
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
	return &c
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
	return &responder, nil
}
