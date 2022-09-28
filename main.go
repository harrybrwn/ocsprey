package main

import (
	"context"
	"crypto"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

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
		configFile string
		config     Config
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
	c.AddCommand(
		newServerCmd(&config, logger),
	)
	f := c.PersistentFlags()
	f.StringVar(&logLevel, "log-level", logLevel, "set the logging level (trace, debug, info, warn, error)")
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
				err       error
				ctx       = log.Stash(cmd.Context(), logger)
				hash      = crypto.SHA1
				authority = inmem.NewResponderDB(hash)
				certdb    = openssl.EmptyIndex()
			)

			for _, cfg := range conf.OpenSSL {
				if cfg.BaseDir == "" {
					cfg.BaseDir = "."
				}
				err = certdb.AddIndex(&openssl.IndexConfig{
					Index:    filepath.Join(cfg.BaseDir, cfg.IndexFile),
					NewCerts: filepath.Join(cfg.BaseDir, cfg.NewCertsDir),
					CA:       filepath.Join(cfg.BaseDir, cfg.RootCA),
					Serial:   filepath.Join(cfg.BaseDir, cfg.SerialFile),
					Hash:     hash,
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
			if len(conf.OpenSSL) > 0 {
				if err = certdb.WatchFiles(ctx); err != nil {
					return err
				}
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", server.Responder(authority, certdb))
			mux.Handle("/issuer", server.ControlIssuer(authority))
			mux.Handle("/leaf", server.ControlCert(authority, certdb))
			mux.Handle("/leaf/revoke", server.ControlCertRevoke(authority, certdb))

			srv := http.Server{
				Addr:        fmt.Sprintf(":%d", port),
				Handler:     log.HTTPRequests(mux),
				BaseContext: func(net.Listener) context.Context { return ctx },
			}
			logger.Infof("listening on [::]:%d", port)
			return srv.ListenAndServe()
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
	OpenSSL []OpenSSLIndexConfig `yaml:"openssl"`
}

type OpenSSLIndexConfig struct {
	BaseDir       string          `yaml:"base_dir"`
	IndexFile     string          `yaml:"index_file"`
	SerialFile    string          `yaml:"serial_file"`
	NewCertsDir   string          `yaml:"new_certs_dir"`
	RootCA        string          `yaml:"root_ca"`
	OCSPResponder ResponderConfig `yaml:"ocsp_responder"`
}

type ResponderConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
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
