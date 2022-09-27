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
	"gopkg.hrry.dev/ocsprey/ca/openssl"
	"gopkg.hrry.dev/ocsprey/internal/certutil"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/server"
	"gopkg.in/yaml.v3"
)

//go:generate sh testdata/gen.sh
//go:generate mockgen -package mockca -destination internal/mocks/mockca/mockca.go gopkg.hrry.dev/ocsprey/ca ResponderDB,CertStore

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
	var (
		port       = toInt(env("SERVER_PORT", "8888"))
		newCertDir = env("SERVER_NEW_CERTS_DIR", ".ocsprey/certs")
	)
	c := cobra.Command{
		Use:   "server",
		Short: "OCSP responder server",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ctx = log.Stash(ctx, logger)
			authority := issuerDB{
				responders:     make(map[string]ca.Responder),
				hasher:         crypto.SHA1,
				subjectHashSet: make(map[string]string),
			}
			var (
				err    error
				certdb = openssl.EmptyIndex()
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
					Hash:     authority.hasher,
				})
				if err != nil {
					return err
				}
				var responder ca.Responder
				responder.CA, err = certutil.OpenCertificate(filepath.Join(cfg.BaseDir, cfg.RootCA))
				if err != nil {
					return err
				}
				responder.Signer.Cert, err = certutil.OpenCertificate(filepath.Join(cfg.BaseDir, cfg.OCSPResponder.Cert))
				if err != nil {
					return err
				}
				responder.Signer.Key, err = certutil.OpenKey(filepath.Join(cfg.BaseDir, cfg.OCSPResponder.Key))
				if err != nil {
					return err
				}
				err = authority.Put(ctx, &responder)
				if err != nil {
					return err
				}
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", server.Responder(&authority, certdb))
			mux.Handle("/ctrl/issuer", server.ControlIssuer(&authority))
			mux.Handle("/ctrl/leaf", server.ControlCert(&authority, certdb))

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
	f.StringVar(&newCertDir, "new-certs-dir", newCertDir, "directory to write new certificates to")
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
