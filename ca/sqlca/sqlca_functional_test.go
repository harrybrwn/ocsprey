//go:build functional_test

package sqlca

import (
	"bytes"
	"context"
	"crypto"
	"database/sql"
	"io"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/db"
	"gopkg.hrry.dev/ocsprey/internal/testutil"
)

var (
	logger = logrus.New()
	config = db.Config{
		Type:     "postgres",
		Host:     "localhost",
		Port:     5432,
		User:     "ocsprey",
		Password: "testbed",
		Database: "ocsprey",
		SSLMode:  "disable",
	}
)

func init() {
	logger.SetOutput(io.Discard)
	os.Unsetenv("PGSERVICEFILE")
}

func up() {
	err := MigrateUp(logger, config.URL())
	if err != nil {
		panic(err)
	}
}

func down() {
	err := MigrateDown(logger, config.URL())
	if err != nil {
		panic(err)
	}
}

func newDB() db.DB {
	sqldb, err := sql.Open(config.Type, config.URL().String())
	if err != nil {
		panic(err)
	}
	return db.New(sqldb, db.WithLogger(logger))
}

func TestFunctional_ResponderDB(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	up()
	defer down()
	sqldb := newDB()
	defer sqldb.Close()
	rdb := NewResponder(sqldb, crypto.SHA1)

	rootCA := must(testutil.GenCA())
	ocspSigner := must(testutil.GenOCSP(rootCA))

	rootCACert := *rootCA.Cert
	rootCACert.AuthorityKeyId = nil
	err := rdb.Put(ctx, &ca.Responder{
		CA:     &rootCACert,
		Signer: *ocspSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rdb.Get(ctx, rootCA.Cert.AuthorityKeyId)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ocspSigner.Cert.Raw, resp.Signer.Cert.Raw) {
		t.Fatalf(
			"expected result of Get to has the same DER certificate:\nwant: %x\n got: %x",
			ocspSigner.Cert.Raw,
			resp.Signer.Cert.Raw,
		)
	}
	if !bytes.Equal(rootCA.Cert.RawSubject, resp.CA.RawSubject) {
		t.Fatal("expected result CA subject to equal original rootCA subject")
	}
	if !bytes.Equal(rootCA.Cert.RawSubject, resp.Signer.Cert.RawIssuer) {
		t.Fatal("expected result responder cert issuer to equal original rootCA subject")
	}
	if err = rdb.Del(ctx, rootCA.Cert.AuthorityKeyId); err != nil {
		t.Fatal(err)
	}
	_, err = rdb.Get(ctx, rootCA.Cert.AuthorityKeyId)
	if err == nil {
		t.Error("expected an error while getting a deleted responder")
	}
	// one insert without modifying AuthorityKeyId
	err = rdb.Put(ctx, &ca.Responder{
		CA:     rootCA.Cert,
		Signer: *ocspSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFunctional_CertDB(t *testing.T) {
	ctx := context.Background()
	up()
	defer down()
	sqldb := newDB()
	defer sqldb.Close()
	cdb := NewCertDB(sqldb)
	rdb := NewResponder(sqldb, crypto.SHA1)
	rootCA := must(testutil.GenCA())
	ocsp := must(testutil.GenOCSP(rootCA))
	leaf := must(testutil.GenLeaf(rootCA))

	// make sure we trigger the public key hash
	caPair := copyPair(rootCA)
	caPair.Cert.AuthorityKeyId = nil
	ocspPair := copyPair(ocsp)
	ocspPair.Cert.AuthorityKeyId = nil
	if err := rdb.Put(ctx, &ca.Responder{
		Signer: ocspPair,
		CA:     caPair.Cert,
	}); err != nil {
		t.Fatal(err)
	}

	err := cdb.Put(ctx, leaf.Cert)
	if err != nil {
		t.Error(err)
	}
	cert, status, err := cdb.Get(ctx, (*keyID)(leaf))
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Valid {
		t.Fatalf("expected %v, got %v", ca.Valid, status)
	}
	if !certificateEqual(leaf.Cert, cert) {
		t.Errorf("expected Get to return the certificate that was inserted")
	}

	err = cdb.Revoke(ctx, (*keyID)(leaf))
	if err != nil {
		t.Fatalf("failed to revoke cert: %v", err)
	}
	cert, status, err = cdb.Get(ctx, (*keyID)(leaf))
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Revoked {
		t.Fatalf("expected %v, got %v", ca.Revoked, status)
	}
	if !certificateEqual(leaf.Cert, cert) {
		t.Errorf("expected Get to return the certificate that was inserted")
	}

	err = cdb.Del(ctx, (*keyID)(leaf))
	if err != nil {
		t.Error(err)
	}
}
