package sqlca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lib/pq"
	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/mocks/mockdb"
	"gopkg.hrry.dev/ocsprey/internal/testutil"
)

func Test(t *testing.T) {
	ca := must(testutil.GenCA())
	leaf := must(testutil.GenLeaf(ca))
	r := must(ocsp.ParseRequest(must(ocsp.CreateRequest(
		leaf.Cert, ca.Cert,
		&ocsp.RequestOptions{Hash: crypto.SHA256},
	))))
	var _ = (*Request)(r)
}

func TestResponderDB_Put(t *testing.T) {
	testutil.Hash = crypto.SHA256
	defer func() { testutil.Hash = crypto.SHA1 }()
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sqldb := mockdb.NewMockDB(ctrl)
	rdb := NewResponder(sqldb, testutil.Hash)

	var err error
	rootCA := must(testutil.GenCA())
	ocspSigner := must(testutil.GenOCSP(rootCA))

	ocspKeyDer, err := x509.MarshalPKCS8PrivateKey(ocspSigner.Key)
	if err != nil {
		t.Fatal(err)
	}
	h := rdb.hash.New()
	h.Write(rootCA.Cert.RawSubject)
	issuerNameHash := h.Sum(nil)
	authKeyID := base64.RawStdEncoding.EncodeToString(rootCA.Cert.AuthorityKeyId)
	mock := func() *gomock.Call {
		return sqldb.EXPECT().ExecContext(
			ctx, responderPutQuery,
			authKeyID, issuerNameHash,
			ocspSigner.Cert.Raw,
			ocspKeyDer, rootCA.Cert.Raw,
		)
	}

	mock().Return(nil, nil)
	err = rdb.Put(ctx, &ca.Responder{
		CA:     withoutAuthKeyID(rootCA).Cert,
		Signer: *ocspSigner,
	})
	if err != nil {
		t.Fatal(err)
	}

	mock().Return(nil, nil)
	err = rdb.Put(ctx, &ca.Responder{
		CA:     rootCA.Cert,
		Signer: *ocspSigner,
	})
	if err != nil {
		t.Fatal(err)
	}

	mock().Return(nil, nil)
	err = rdb.Put(ctx, &ca.Responder{
		CA:     withoutAuthKeyID(rootCA).Cert,
		Signer: withoutAuthKeyID(ocspSigner),
	})
	if err != nil {
		t.Fatal(err)
	}

	mock().Return(nil, sql.ErrNoRows)
	err = rdb.Put(ctx, &ca.Responder{
		CA:     withoutAuthKeyID(rootCA).Cert,
		Signer: withoutAuthKeyID(ocspSigner),
	})
	if err != sql.ErrNoRows {
		t.Error("got wrong error")
	}
}

func TestResponderDB_Get(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sqldb := mockdb.NewMockDB(ctrl)
	rdb := NewResponder(sqldb, testutil.Hash)
	rows := mockdb.NewMockRows(ctrl)

	rootCA := must(testutil.GenCA())
	ocspSigner := must(testutil.GenOCSP(rootCA))
	ocspKeyDer, err := x509.MarshalPKCS8PrivateKey(ocspSigner.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyID := base64.RawStdEncoding.EncodeToString(ocspSigner.Cert.AuthorityKeyId)

	bytesArgs := []any{gomock.AssignableToTypeOf(&([]byte{})), gomock.AssignableToTypeOf(&([]byte{})), gomock.AssignableToTypeOf(&([]byte{}))}

	sqldb.EXPECT().QueryContext(ctx, responderGetQuery, keyID).Return(nil, sql.ErrNoRows)
	res, err := rdb.Get(ctx, ocspSigner.Cert.AuthorityKeyId)
	if err != sql.ErrNoRows {
		t.Errorf("expected error: %v, got: %v", sql.ErrNoRows, err)
	}
	if res != nil {
		t.Error("expected nil result")
	}

	sqldb.EXPECT().QueryContext(ctx, responderGetQuery, keyID).Return(rows, nil)
	rows.EXPECT().Next().Return(false)
	rows.EXPECT().Err().Return(sql.ErrNoRows)
	rows.EXPECT().Close().Return(nil)
	res, err = rdb.Get(ctx, ocspSigner.Cert.AuthorityKeyId)
	if err == nil {
		t.Error("expected an error")
	}
	if res != nil {
		t.Error("expected nil result")
	}

	sqldb.EXPECT().QueryContext(ctx, responderGetQuery, keyID).Return(rows, nil)
	rows.EXPECT().Next().Return(true)
	rows.EXPECT().Scan(bytesArgs...).Do(func(x ...any) {
		*x[0].(*[]byte) = ocspSigner.Cert.Raw
		*x[1].(*[]byte) = ocspKeyDer
		*x[2].(*[]byte) = []byte{}
	}).Return(nil)
	rows.EXPECT().Close().Return(nil)
	res, err = rdb.Get(ctx, ocspSigner.Cert.AuthorityKeyId)
	if err == nil {
		t.Error("expected error when storage has a nil cert")
	}
	if res != nil {
		t.Error("expected nil result")
	}

	sqldb.EXPECT().QueryContext(ctx, responderGetQuery, keyID).Return(rows, nil)
	rows.EXPECT().Next().Return(true)
	rows.EXPECT().Scan(bytesArgs...).Do(func(x ...any) {
		*x[0].(*[]byte) = ocspSigner.Cert.Raw
		*x[1].(*[]byte) = []byte{}
		*x[2].(*[]byte) = rootCA.Cert.Raw
	}).Return(nil)
	rows.EXPECT().Close().Return(nil)
	res, err = rdb.Get(ctx, ocspSigner.Cert.AuthorityKeyId)
	if err == nil {
		t.Error("expected error when storage has a nil cert")
	}
	if res != nil {
		t.Error("expected nil result")
	}

	sqldb.EXPECT().QueryContext(ctx, responderGetQuery, keyID).Return(rows, nil)
	rows.EXPECT().Next().Return(true)
	rows.EXPECT().Scan(bytesArgs...).Do(func(x ...any) {
		*x[0].(*[]byte) = []byte{}
		*x[1].(*[]byte) = ocspKeyDer
		*x[2].(*[]byte) = rootCA.Cert.Raw
	}).Return(nil)
	rows.EXPECT().Close().Return(nil)
	res, err = rdb.Get(ctx, ocspSigner.Cert.AuthorityKeyId)
	if err == nil {
		t.Error("expected error when storage has a nil cert")
	}
	if res != nil {
		t.Error("expected nil result")
	}

	sqldb.EXPECT().QueryContext(ctx, responderGetQuery, keyID).Return(rows, nil)
	rows.EXPECT().Next().Return(true)
	rows.EXPECT().Scan(bytesArgs...).Do(func(x ...any) {
		*x[0].(*[]byte) = ocspSigner.Cert.Raw
		*x[1].(*[]byte) = ocspKeyDer
		*x[2].(*[]byte) = rootCA.Cert.Raw
	}).Return(nil)
	rows.EXPECT().Close().Return(nil)
	res, err = rdb.Get(ctx, ocspSigner.Cert.AuthorityKeyId)
	if err != nil {
		t.Fatal(err)
	}
	h := rdb.hash.New()
	if err = hashPublicKey(res.CA, h); err != nil {
		t.Fatal(err)
	}
	res.CA.AuthorityKeyId = h.Sum(nil)
	if !certificateEqual(res.CA, rootCA.Cert) {
		t.Error("expected result CA to remain the same")
	}
	if !certificateEqual(res.Signer.Cert, ocspSigner.Cert) {
		t.Error("expected result ocsp signer to remain the same")
	}
}

func TestCertDB_Get(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sqldb := mockdb.NewMockDB(ctrl)
	rows := mockdb.NewMockRows(ctrl)
	cdb := NewCertDB(sqldb)

	root := must(testutil.GenCA())
	leaf := must(testutil.GenLeaf(root))
	id := (*keyID)(leaf)
	serial := base64.RawStdEncoding.EncodeToString(id.Serial().Bytes())
	issuerKeyHash := base64.RawStdEncoding.EncodeToString(id.KeyHash())

	sqldb.EXPECT().QueryContext(ctx, certGetQuery, serial, issuerKeyHash).Return(nil, sql.ErrNoRows)
	_, _, err := cdb.Get(ctx, id)
	if err != sql.ErrNoRows {
		t.Error("expected an error")
	}

	sqldb.EXPECT().QueryContext(ctx, certGetQuery, serial, issuerKeyHash).Return(rows, nil)
	rows.EXPECT().Next().Return(false)
	rows.EXPECT().Err().Return(sql.ErrNoRows)
	rows.EXPECT().Close().Return(nil)
	_, _, err = cdb.Get(ctx, id)
	if err != sql.ErrNoRows {
		t.Error("expected an error")
	}

	sqldb.EXPECT().QueryContext(ctx, certGetQuery, serial, issuerKeyHash).Return(rows, nil)
	rows.EXPECT().Next().Return(true)
	rows.EXPECT().Scan(
		gomock.AssignableToTypeOf((*ca.CertStatus)(nil)),
		gomock.AssignableToTypeOf((*time.Time)(nil)),
		gomock.AssignableToTypeOf((*pq.NullTime)(nil)),
		gomock.AssignableToTypeOf((*[]byte)(nil)),
	).Do(func(x ...any) {
		*x[0].(*ca.CertStatus) = ca.Valid
		*x[1].(*time.Time) = time.Now()
		*x[2].(*pq.NullTime) = pq.NullTime{Valid: false, Time: time.Now()}
		// Set invalid DER cert
		*x[3].(*[]byte) = leaf.Cert.Raw[:len(leaf.Cert.Raw)/2]
	}).Return(nil)
	rows.EXPECT().Close().Return(nil)
	_, _, err = cdb.Get(ctx, id)
	if err == nil {
		t.Fatal("expected an error when the database returns an invalid DER certificate")
	}

	sqldb.EXPECT().QueryContext(ctx, certGetQuery, serial, issuerKeyHash).Return(rows, nil)
	rows.EXPECT().Next().Return(true)
	rows.EXPECT().Scan(
		gomock.AssignableToTypeOf((*ca.CertStatus)(nil)),
		gomock.AssignableToTypeOf((*time.Time)(nil)),
		gomock.AssignableToTypeOf((*pq.NullTime)(nil)),
		gomock.AssignableToTypeOf((*[]byte)(nil)),
	).Do(func(x ...any) {
		*x[0].(*ca.CertStatus) = ca.Valid
		*x[1].(*time.Time) = time.Now()
		*x[2].(*pq.NullTime) = pq.NullTime{Valid: false, Time: time.Now()}
		*x[3].(*[]byte) = leaf.Cert.Raw
	}).Return(nil)
	rows.EXPECT().Close().Return(nil)
	_, _, err = cdb.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertDB_Del(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sqldb := mockdb.NewMockDB(ctrl)
	cdb := NewCertDB(sqldb)

	root := must(testutil.GenCA())
	leaf := must(testutil.GenLeaf(root))
	id := (*keyID)(leaf)
	serial := base64.RawStdEncoding.EncodeToString(id.Serial().Bytes())
	//issuerKeyHash := base64.RawStdEncoding.EncodeToString(id.KeyHash())

	sqldb.EXPECT().ExecContext(ctx, certDeleteQuery, serial)
	err := cdb.Del(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertDB_Put(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sqldb := mockdb.NewMockDB(ctrl)
	cdb := NewCertDB(sqldb)

	root := must(testutil.GenCA())
	leaf := must(testutil.GenLeaf(root))
	id := (*keyID)(leaf)
	serial := base64.RawStdEncoding.EncodeToString(id.Serial().Bytes())
	issuerKeyHash := base64.RawStdEncoding.EncodeToString(id.KeyHash())

	sqldb.EXPECT().ExecContext(
		ctx, certPutQuery,
		issuerKeyHash,
		ca.Valid,
		leaf.Cert.NotAfter,
		nil,
		ca.Unspecified,
		serial,
		leaf.Cert.Raw,
	).Return(nil, nil)
	err := cdb.Put(ctx, leaf.Cert)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCertDB_Revoke(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	sqldb := mockdb.NewMockDB(ctrl)
	cdb := NewCertDB(sqldb)

	root := must(testutil.GenCA())
	leaf := must(testutil.GenLeaf(root))
	id := (*keyID)(leaf)
	serial := base64.RawStdEncoding.EncodeToString(id.Serial().Bytes())
	issuerKeyHash := base64.RawStdEncoding.EncodeToString(id.KeyHash())

	sqldb.EXPECT().ExecContext(ctx, certRevokeQuery, serial, issuerKeyHash, ca.Revoked, ca.Unspecified).Return(nil, nil)
	err := cdb.Revoke(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashPublicKey(t *testing.T) {
	for _, hash := range []crypto.Hash{
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA384,
		crypto.SHA512_256,
	} {
		t.Run(hash.String(), func(t *testing.T) {
			testutil.Hash = crypto.SHA256
			defer func() { testutil.Hash = crypto.SHA1 }()
			root := must(testutil.GenCA())
			leaf := must(testutil.GenLeaf(root))
			keyID := leaf.Cert.AuthorityKeyId
			if !bytes.Equal(keyID, root.Cert.AuthorityKeyId) {
				t.Fatal("expected AuthorityKeyId to be equal for both certs")
			}
			h := testutil.Hash.New()
			err := hashPublicKey(root.Cert, h)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(keyID, h.Sum(nil)) {
				t.Fatal("expected hashPublicKey to output the AuthorityKeyId")
			}
		})
	}
}

func certificateEqual(a, b *x509.Certificate) bool {
	return bytes.Equal(a.Raw, b.Raw) //&&
	//bytes.Equal(a.AuthorityKeyId, b.AuthorityKeyId)  &&
	// bytes.Equal(a.RawIssuer, b.RawIssuer) &&
	// bytes.Equal(a.RawSubject, b.RawSubject) &&
	// bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo) &&
	// bytes.Equal(a.Signature, b.Signature)
}

type Request struct {
	HashAlgorithm  crypto.Hash
	IssuerNameHash []byte
	IssuerKeyHash  []byte
	SerialNumber   *big.Int
}

func copyPair(pair *ca.KeyPair) ca.KeyPair {
	cert, err := x509.ParseCertificate(pair.Cert.Raw)
	if err != nil {
		panic(err)
	}
	rawKey, err := x509.MarshalPKCS8PrivateKey(pair.Key)
	if err != nil {
		panic(err)
	}
	genericKey, err := x509.ParsePKCS8PrivateKey(rawKey)
	if err != nil {
		panic(err)
	}
	key, ok := genericKey.(crypto.Signer)
	if !ok {
		panic("key is not a crypto.Signer")
	}
	return ca.KeyPair{
		Key:  key,
		Cert: cert,
	}
}

func withoutAuthKeyID(pair *ca.KeyPair) ca.KeyPair {
	p := copyPair(pair)
	p.Cert.AuthorityKeyId = nil
	return p
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

type keyID ca.KeyPair

func (kid *keyID) Serial() ca.ID { return kid.Cert.SerialNumber }
func (kid *keyID) KeyHash() []byte {
	return kid.Cert.AuthorityKeyId
}
