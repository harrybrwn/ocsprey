package inmem

import (
	"bytes"
	"context"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/testutil"
)

func TestCertDB_Put(t *testing.T) {
	ctx := context.Background()
	db := NewCertDB()

	rootCA := must(testutil.GenCA())
	err := db.Put(ctx, rootCA.Cert)
	if err != nil {
		t.Fatal(err)
	}

	intermediate := must(testutil.GenIntermediate(rootCA))
	if err = db.Put(ctx, intermediate.Cert); err != nil {
		t.Fatal(err)
	}
	if len(db.certs) != 2 {
		t.Error("expected length of 2")
	}
	if len(db.hashes) != 1 {
		t.Error("should only have one issuer hash")
	}
	if !in(db.hashes, hex.EncodeToString(rootCA.Cert.AuthorityKeyId)) {
		t.Error("expected root ca key hash to be in hashes")
	}

	leafs := []*ca.KeyPair{
		must(testutil.GenLeaf(intermediate)),
		must(testutil.GenLeaf(intermediate)),
		must(testutil.GenLeaf(intermediate)),
	}
	for _, l := range leafs {
		if err = db.Put(ctx, l.Cert); err != nil {
			t.Fatal(err)
		}
	}
	if len(db.certs) != 5 {
		t.Error("expected 5 certs stored")
	}
	if len(db.hashes) != 2 {
		t.Error("expected 2 issuer hashes stored")
	}
	if !in(db.hashes, hex.EncodeToString(intermediate.Cert.AuthorityKeyId)) {
		t.Error("expected intermediate ca key hash to be in hashes")
	}

	leaf := must(testutil.GenLeaf(intermediate))
	leaf.Cert.AuthorityKeyId = nil
	err = db.Put(ctx, leaf.Cert)
	if err == nil {
		t.Fatal("expected error when authorityKeyID is nil")
	}

	leaf = must(testutil.GenLeaf(intermediate))
	leaf.Cert.NotAfter = time.Now()
	err = db.Put(ctx, leaf.Cert)
	if err != nil {
		t.Error(err)
	}
	_, status, err := db.Get(ctx, &keyid{
		serial: leaf.Cert.SerialNumber,
		issuer: leaf.Cert.AuthorityKeyId,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Expired {
		t.Error("expected status expired")
	}
}

func TestCertDB_Get(t *testing.T) {
	root := must(testutil.GenCA())
	intermediates := []*ca.KeyPair{
		must(testutil.GenIntermediate(root)),
		must(testutil.GenIntermediate(root)),
	}
	leafs := []*ca.KeyPair{
		must(testutil.GenLeaf(intermediates[0])),
		must(testutil.GenLeaf(intermediates[0])),
		must(testutil.GenLeaf(intermediates[1])),
		must(testutil.GenLeaf(intermediates[1])),
	}
	ctx := context.Background()
	db := NewCertDB()
	for _, kp := range append(append([]*ca.KeyPair{root}, intermediates...), leafs...) {
		err := db.Put(ctx, kp.Cert)
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < len(leafs); i++ {
		cert, status, err := db.Get(ctx, &keyid{
			serial: leafs[i].Cert.SerialNumber,
			issuer: leafs[i].Cert.AuthorityKeyId,
		})
		if err != nil {
			t.Fatal(err)
		}
		if status != ca.Valid {
			t.Error("expected valid cert")
		}
		if !bytes.Equal(leafs[i].Cert.Raw, cert.Raw) {
			t.Error("expected raw certs to be equal")
		}
	}
}

func TestCertDB_Del(t *testing.T) {
	root := must(testutil.GenCA())
	intermediates := []*ca.KeyPair{
		must(testutil.GenIntermediate(root)),
		must(testutil.GenIntermediate(root)),
	}
	leafs := []*ca.KeyPair{
		must(testutil.GenLeaf(intermediates[0])),
		must(testutil.GenLeaf(intermediates[0])),
		must(testutil.GenLeaf(intermediates[1])),
		must(testutil.GenLeaf(intermediates[1])),
	}
	ctx := context.Background()
	db := NewCertDB()
	for _, kp := range append(append([]*ca.KeyPair{root}, intermediates...), leafs...) {
		err := db.Put(ctx, kp.Cert)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < len(leafs); i++ {
		err := db.Del(ctx, &keyid{
			serial: leafs[i].Cert.SerialNumber,
			issuer: leafs[i].Cert.AuthorityKeyId,
		})
		if err != nil {
			t.Fatal(err)
		}

		_, _, err = db.Get(ctx, &keyid{
			serial: leafs[i].Cert.SerialNumber,
			issuer: leafs[i].Cert.AuthorityKeyId,
		})
		if err != ca.ErrCertNotFound {
			t.Error("expected a not found error")
		}
		err = db.Revoke(ctx, &keyid{
			serial: leafs[i].Cert.SerialNumber,
			issuer: leafs[i].Cert.AuthorityKeyId,
		})
		if err != ca.ErrCertNotFound {
			t.Error("expected a not found error")
		}

	}
}

func TestCertDB_Revoke(t *testing.T) {
	root := must(testutil.GenCA())
	intermediate := must(testutil.GenIntermediate(root))
	leafs := []*ca.KeyPair{
		must(testutil.GenLeaf(intermediate)),
		must(testutil.GenLeaf(intermediate)),
		must(testutil.GenLeaf(intermediate)),
	}
	ctx := context.Background()
	db := NewCertDB()
	for _, kp := range append([]*ca.KeyPair{root, intermediate}, leafs...) {
		err := db.Put(ctx, kp.Cert)
		if err != nil {
			t.Fatal(err)
		}
	}
	err := db.Revoke(ctx, &keyid{
		serial: leafs[0].Cert.SerialNumber,
		issuer: leafs[0].Cert.AuthorityKeyId,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, status, err := db.Get(ctx, &keyid{
		serial: leafs[0].Cert.SerialNumber,
		issuer: leafs[0].Cert.AuthorityKeyId,
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Revoked {
		t.Error("expected status revoked")
	}
}

func TestIssuerDB_PutGet(t *testing.T) {
	root := must(testutil.GenCA())
	resp := must(genOCSP(root))
	ctx := context.Background()
	db := NewResponderDB(testutil.Hash)
	err := db.Put(ctx, resp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := db.Get(ctx, root.Cert.AuthorityKeyId)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root.Cert.Raw, r.CA.Raw) {
		t.Fatal("should have the same CA")
	}
	if !bytes.Equal(resp.Signer.Cert.Raw, r.Signer.Cert.Raw) {
		t.Fatal("ocsp signer certs must be the same")
	}

	_, err = db.Get(ctx, []byte("this is not a valid id"))
	if err != ca.ErrCertNotFound {
		t.Error("expected \"cert not found\" error")
	}
}

func TestIssuerDB_Del(t *testing.T) {
	root := must(testutil.GenCA())
	resp := must(genOCSP(root))
	ctx := context.Background()
	db := NewResponderDB(testutil.Hash)
	err := db.Put(ctx, resp)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Del(ctx, root.Cert.AuthorityKeyId); err != nil {
		t.Fatal(err)
	}

	_, err = db.Get(ctx, root.Cert.AuthorityKeyId)
	if err != ca.ErrCertNotFound {
		t.Error("expected \"cert not found\" error")
	}
}

func TestIssuerDB_Find(t *testing.T) {
	root := must(testutil.GenCA())
	resp := must(genOCSP(root))
	ctx := context.Background()
	db := NewResponderDB(testutil.Hash)
	err := db.Put(ctx, resp)
	if err != nil {
		t.Fatal(err)
	}
	leafs := []*ca.KeyPair{
		must(testutil.GenLeaf(root)),
		must(testutil.GenLeaf(root)),
	}
	leafs[1].Cert.AuthorityKeyId = nil
	for _, leaf := range leafs {
		r, err := db.Find(ctx, leaf.Cert)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(root.Cert.Raw, r.CA.Raw) {
			t.Fatal("should have the same CA")
		}
		if !bytes.Equal(resp.Signer.Cert.Raw, r.Signer.Cert.Raw) {
			t.Fatal("ocsp signer certs must be the same")
		}
	}
}

func in[K comparable, V any](m map[K]V, key K) bool {
	_, ok := m[key]
	return ok
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type keyid struct {
	serial *big.Int
	issuer []byte
}

func (kid *keyid) Serial() ca.ID   { return kid.serial }
func (kid *keyid) KeyHash() []byte { return kid.issuer }

func genOCSP(issuer *ca.KeyPair) (*ca.Responder, error) {
	signer, err := testutil.GenOCSP(issuer)
	if err != nil {
		return nil, err
	}
	return &ca.Responder{CA: issuer.Cert, Signer: *signer}, nil
}
