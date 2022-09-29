package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	_ "github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca/inmem"
	"gopkg.hrry.dev/ocsprey/ca/openssl"
	"gopkg.hrry.dev/ocsprey/internal/certutil"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/server"
	"gopkg.hrry.dev/ocsprey/internal/testutil"
)

//go:generate sh testdata/gen.sh
//go:generate mockgen -package mockca -destination internal/mocks/mockca/mockca.go gopkg.hrry.dev/ocsprey/ca ResponderDB,CertStore

var logger = logrus.New()

func init() { logger.SetOutput(io.Discard) }

func TestServer(t *testing.T) {
	const hash = crypto.SHA1
	ctx := log.Stash(context.Background(), logger)
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
	txt.WatchFiles(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.Responder(authority, txt))
	mux.Handle("/issuer", server.ControlIssuer(authority))
	mux.Handle("/leaf", server.ControlCert(authority, txt))
	mux.Handle("/leaf/revoke", server.ControlCertRevoke(authority, txt))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.BaseContext = func(net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()
	// TODO do tests here
	resp, err := check(srv.URL, "testdata/pki1", "out/server.crt")
	if err != nil {
		t.Error(err)
	}
	if resp.Status != ocsp.Good {
		t.Error("expected status good")
	}

	cli := opensslCLI{config: "testdata/openssl.cnf", root: "testdata/pki0"}
	n := randInt()
	name := fmt.Sprintf("test%d", n)
	err = cli.new(name)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = check(srv.URL, cli.root, fmt.Sprintf("out/%s.crt", name))
	if err != nil {
		t.Error(err)
	}
	if resp.Status != ocsp.Good {
		t.Error("expected status good")
	}
	err = cli.revoke(name)
	if err != nil {
		t.Error(err)
	}
	resp, err = check(srv.URL, cli.root, fmt.Sprintf("out/%s.crt", name))
	if err != nil {
		t.Error(err)
	}
	if resp.Status != ocsp.Revoked {
		t.Error("expected status revoked")
	}
}

func check(serverURL, root, filename string) (*ocsp.Response, error) {
	rootCA, err := certutil.OpenCertificate(filepath.Join(root, "ca.crt"))
	if err != nil {
		return nil, err
	}
	cert, err := certutil.OpenCertificate(filepath.Join(root, filename))
	if err != nil {
		return nil, err
	}
	request, err := ocsp.CreateRequest(cert, rootCA, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(&http.Request{
		Method: "POST",
		Body:   io.NopCloser(bytes.NewBuffer(request)),
		URL:    u,
	})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return ocsp.ParseResponse(raw, rootCA)
}

type opensslCLI struct {
	config string
	root   string
}

func (o *opensslCLI) revoke(name string) error {
	crt := filepath.Join(o.root, "out", fmt.Sprintf("%s.crt", name))
	return o.cmd(
		"openssl", "ca", "-revoke", crt,
		"-crl_reason", "cacompromise",
	).Run()
}

func (o *opensslCLI) new(name string) error {
	key := filepath.Join(o.root, "out", fmt.Sprintf("%s.key", name))
	crt := filepath.Join(o.root, "out", fmt.Sprintf("%s.crt", name))
	csr := filepath.Join(o.root, "out", fmt.Sprintf("%s.csr", name))
	keySize := strconv.FormatInt(int64(testutil.KeySize), 10)
	subj := fmt.Sprintf("/CN=%s", name)
	err := o.cmd("openssl", "genrsa", "-out", key, keySize).Run()
	if err != nil {
		return err
	}
	err = o.cmd("openssl", "req", "-new", "-subj", subj, "-key", key, "-out", csr, "-nodes").Run()
	if err != nil {
		return err
	}
	err = o.cmd("openssl", "ca", "-batch", "-notext", "-rand_serial", "-in", csr, "-out", crt).Run()
	if err != nil {
		return err
	}
	return nil
}

func (o *opensslCLI) cmd(prod string, args ...string) *exec.Cmd {
	cmd := exec.Command(prod, args...)
	cmd.Env = append(
		cmd.Env,
		fmt.Sprintf("OPENSSL_CONF=%s", o.config),
		fmt.Sprintf("CA_ROOT=%s", o.root),
	)
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr
	return cmd
}

func TestNewRootCmd(t *testing.T) {
	root := newRootCmd()
	if root == nil {
		t.Error("wow this test wasn't meaningless... newRootCmd should not return nil")
	}
}

func randInt() int {
	var (
		buf [4]byte
		n   int
	)
	rand.Read(buf[:])
	for i := 0; i < 4; i++ {
		n = (n << 8) | int(buf[i])
	}
	return n
}
