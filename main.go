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
)

//go:generate sh testdata/gen.sh

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
		logger   = logrus.New()
		logLevel = env("LOG_LEVEL", "debug")
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
			return nil
		},
	}
	c.AddCommand(
		newServerCmd(logger),
	)
	f := c.PersistentFlags()
	f.StringVar(&logLevel, "log-level", logLevel, "set the logging level (trace, debug, info, warn, error)")
	return &c
}

func newServerCmd(logger *logrus.Logger) *cobra.Command {
	var (
		port         = toInt(env("SERVER_PORT", "8888"))
		responderKey []string
		responderCrt []string
		issuers      []string
		index        string
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
			// certdb := openssl.EmptyIndex(
			// 	openssl.WithNewCertsDir(filepath.Join(filepath.Dir(index), "certs")),
			// 	openssl.WithHashFunc(authority.hasher),
			// )

			certdb, err := openssl.OpenIndex(
				index,
				openssl.WithSerialFile(filepath.Join(filepath.Dir(index), "serial")),
				openssl.WithNewCertsDir(filepath.Join(filepath.Dir(index), "certs")),
				openssl.WithHashFunc(authority.hasher),
			)
			if err != nil {
				return err
			}

			key, err := certutil.OpenKey(responderKey[0])
			if err != nil {
				return err
			}
			crt, err := certutil.OpenCertificate(responderCrt[0])
			if err != nil {
				return err
			}
			iss, err := certutil.OpenCertificate(issuers[0])
			if err != nil {
				return err
			}
			authority.add(iss, crt, key)

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
	f.StringArrayVar(&responderKey, "rkey", responderKey, "OCSP responder key")
	f.StringArrayVar(&responderCrt, "rcrt", responderCrt, "OCSP responder certificate")
	f.StringArrayVar(&issuers, "issuer", issuers, "issuer certificate")
	f.StringVar(&index, "index", index, "openssl index db file")
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