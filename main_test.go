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
	"os"
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
var testConfig = Config{
	OpenSSL: []OpenSSLIndexConfig{
		{BaseDir: "testdata/pki0"},
		{BaseDir: "testdata/pki1"},
		{BaseDir: "testdata/pki2"},
	},
}

func init() {
	logger.SetOutput(io.Discard)
	for i := range testConfig.OpenSSL {
		testConfig.OpenSSL[i].RootCA = "ca.crt"
		testConfig.OpenSSL[i].IndexFile = "db/index.txt"
		testConfig.OpenSSL[i].SerialFile = "db/serial"
		testConfig.OpenSSL[i].NewCertsDir = "db/certs"
		testConfig.OpenSSL[i].OCSPResponder.Cert = "out/ocsp-responder.crt"
		testConfig.OpenSSL[i].OCSPResponder.Key = "out/ocsp-responder.key"
	}
}

func TestServer(t *testing.T) {
	const hash = crypto.SHA1
	logger.SetOutput(os.Stdout)
	logger.Level = logrus.TraceLevel
	defer logger.SetOutput(io.Discard)
	ctx := log.Stash(context.Background(), logger)
	txt := openssl.EmptyIndex()
	authority := inmem.NewResponderDB(hash)
	err := addOpenSSLConfigs(ctx, txt, authority, &testConfig)
	if err != nil {
		t.Fatal(err)
	}

	if err = txt.WatchFiles(ctx); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", server.Responder(authority, txt))
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
		t.Errorf("expected status good (%d), got %d", ocsp.Good, resp.Status)
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
		t.Errorf("expected status revoked (%d), got %d", ocsp.Revoked, resp.Status)
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
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}
	for i := 0; i < 4; i++ {
		n = (n << 8) | int(buf[i])
	}
	return n
}
