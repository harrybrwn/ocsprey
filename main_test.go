package main

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	_ "github.com/golang/mock/gomock"
	"gopkg.hrry.dev/ocsprey/ca/inmem"
	"gopkg.hrry.dev/ocsprey/ca/openssl"
	"gopkg.hrry.dev/ocsprey/internal/server"
)

//go:generate sh testdata/gen.sh
//go:generate mockgen -package mockca -destination internal/mocks/mockca/mockca.go gopkg.hrry.dev/ocsprey/ca ResponderDB,CertStore

func TestServer(t *testing.T) {
	const hash = crypto.SHA1
	ctx := context.Background()
	txt := openssl.EmptyIndex()
	authority := inmem.NewResponderDB(hash)
	for i := 0; i < 3; i++ {
		base := filepath.Join("testdata", fmt.Sprintf("pki%d", i))
		err := txt.AddIndex(&openssl.IndexConfig{
			NewCerts: filepath.Join(base, "db/certs"),
			Serial:   filepath.Join(base, "db/serial"),
			Index:    filepath.Join(base, "db/index.txt"),
			CA:       filepath.Join(base, "ca.crt"),
			Hash:     hash,
		})
		if err != nil {
			t.Fatal(err)
		}
		responder, err := openResponderKeys(
			filepath.Join(base, "ca.crt"),
			filepath.Join(base, "out/ocsp-responder.crt"),
			filepath.Join(base, "out/ocsp-responder.key"),
		)
		if err != nil {
			t.Fatal(err)
		}
		err = authority.Put(ctx, responder)
		if err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.Responder(authority, txt))
	mux.Handle("/issuer", server.ControlIssuer(authority))
	mux.Handle("/leaf", server.ControlCert(authority, txt))
	mux.Handle("/leaf/revoke", server.ControlCertRevoke(authority, txt))
	srv := http.Server{Addr: ":8888", Handler: mux}
	defer func() {
		if err := srv.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// t.Error(err)
			panic(err)
		}
	}()
	// TODO do tests here
}

func TestNewRootCmd(t *testing.T) {
	root := newRootCmd()
	if root == nil {
		t.Error("wow this test wasn't meaningless... newRootCmd should not return nil")
	}
}
