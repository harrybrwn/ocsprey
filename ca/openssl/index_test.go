package openssl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/certutil"
	"gopkg.hrry.dev/ocsprey/internal/ocspext"
)

const testRoot = "testdata/pki0"

func Test(t *testing.T) {
}

const testIndex = "" +
	`V	230908224820Z		1000	unknown	/O=Test/CN=test_server
V	230908224820Z		1001	unknown	/O=Test/CN=test_client
V	240828224820Z		1002	unknown	/O=Test/CN=ocsp-test
R	240828224820Z	220908224820Z	1003	unknown	/O=Test/CN=revoked-test
V	230908224850Z		1004	unknown	/O=Test/CN=tester
V	230908224851Z		1005	unknown	/O=Test/CN=tester
R	230908224853Z	220908224853Z,keyCompromise	1006	unknown	/O=Test/CN=test
V	230908224854Z		2048	unknown	/O=Test/CN=tester
E	230908224854Z		2148	unknown	/O=Test/CN=tester
`

func ptr[T any](v T) *T {
	return &v
}

func TestParseIndexFile(t *testing.T) {
	entries, err := parseIndex(strings.NewReader(testIndex))
	if err != nil {
		t.Fatal(err)
	}
	expected := []indexEntry{
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 20, 0, time.UTC), serial: big.NewInt(0x1000)},
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 20, 0, time.UTC), serial: big.NewInt(0x1001)},
		{Status: ca.Valid, expiration: time.Date(2024, time.August, 28, 22, 48, 20, 0, time.UTC), serial: big.NewInt(0x1002)},
		{
			Status:           ca.Revoked,
			expiration:       time.Date(2024, time.August, 28, 22, 48, 20, 0, time.UTC),
			revocation:       ptr(time.Date(2022, time.September, 8, 22, 48, 20, 0, time.UTC)),
			revocationReason: ocsp.Unspecified,
			serial:           big.NewInt(0x1003),
		},
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 50, 0, time.UTC), serial: big.NewInt(0x1004)},
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 51, 0, time.UTC), serial: big.NewInt(0x1005)},
		{
			Status:           ca.Revoked,
			expiration:       time.Date(2023, time.September, 8, 22, 48, 53, 0, time.UTC),
			revocation:       ptr(time.Date(2022, time.September, 8, 22, 48, 53, 0, time.UTC)),
			revocationReason: ocsp.KeyCompromise,
			serial:           big.NewInt(0x1006),
		},
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 54, 0, time.UTC), serial: big.NewInt(0x2048)},
		{Status: ca.Expired, expiration: time.Date(2023, time.September, 8, 22, 48, 54, 0, time.UTC), serial: big.NewInt(0x2148)},
	}
	if len(entries) != len(expected) {
		t.Fatal("wrong number of entries parsed")
	}
	for i, exp := range expected {
		r := entries[i]
		if exp.Status != r.Status {
			t.Errorf("expected status %q, got %q", exp.Status, r.Status)
		}
		if !exp.expiration.Equal(r.expiration) {
			t.Errorf("expected expiration %q, got %q", exp.expiration, r.expiration)
		}
		if r.revocation != nil && !exp.revocation.Equal(*r.revocation) {
			t.Errorf("expected revocation date %q, got %q", exp.revocation, r.revocation)
		}
		if exp.revocationReason != r.revocationReason {
			t.Errorf("expected revocation reason %q, got %q", exp.revocationReason, r.revocationReason)
		}
		if exp.serial.Cmp(r.serial) != 0 {
			t.Errorf("expected serial %q, got %q", exp.serial.Text(10), r.serial.Text(10))
		}
		if r.filename != "" {
			t.Error("expected filename of \"\"")
		}
	}
}

func TestOpenIndex(t *testing.T) {
	txt := EmptyIndex()
	err := txt.AddIndex(&IndexConfig{
		Index:    filepath.Join(testRoot, "db/index.txt"),
		NewCerts: filepath.Join(testRoot, "db/certs"),
		Serial:   filepath.Join(testRoot, "db/serial"),
		CA:       filepath.Join(testRoot, "ca.crt"),
		Hash:     crypto.SHA1,
	})
	if err != nil {
		t.Fatal(err)
	}

	rootCA, err := certutil.OpenCertificate(filepath.Join(testRoot, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha1.New()
	if err = ocspext.PublicKeyHash(rootCA, h); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	issuerHash := h.Sum(nil)
	status, err := txt.Status(ctx, newKeyID(big.NewInt(0x1001), issuerHash))
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Revoked {
		t.Fatal("expected status revoked")
	}

	cert, _, err := txt.Get(ctx, newKeyID(big.NewInt(0x1002), issuerHash))
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber.Int64() != 0x1002 {
		t.Fatal("wrong serial number")
	}
	status, err = txt.Status(ctx, newKeyID(cert.SerialNumber, cert.AuthorityKeyId))
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Valid {
		t.Fatal("expected a valid certificate status")
	}
}

func newKeyID(s *big.Int, iss []byte) *keyID { return &keyID{SerialNumber: s, IssuerKeyHash: iss} }

type keyID ocsp.Request

func (kid *keyID) Serial() ca.ID   { return kid.SerialNumber }
func (kid *keyID) KeyHash() []byte { return kid.IssuerKeyHash }

var _ ca.KeyID = (*keyID)(nil)

func TestIndexTXT_Put(t *testing.T) {
	txt := EmptyIndex()
	err := txt.AddIndex(&IndexConfig{
		Index:    filepath.Join(testRoot, "db/index.txt"),
		NewCerts: filepath.Join(testRoot, "db/certs"),
		Serial:   filepath.Join(testRoot, "db/serial"),
		CA:       filepath.Join(testRoot, "ca.crt"),
		Hash:     crypto.SHA1,
	})
	if err != nil {
		t.Fatal(err)
	}
	rootCA, err := certutil.OpenCertificate(filepath.Join(testRoot, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := certutil.OpenKey(filepath.Join(testRoot, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha1.New()
	if err = ocspext.PublicKeyHash(rootCA, hash); err != nil {
		t.Fatal(err)
	}
	keyHash := hash.Sum(nil)
	serial := randomSerial()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-client-cert"},
		NotBefore:    time.Now(),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCA, &privateKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	defer func() {
		err := txt.Del(ctx, newKeyID(serial, keyHash))
		if err != nil {
			t.Error(err)
		}
	}()
	if err = txt.Put(ctx, cert); err != nil {
		t.Fatal(err)
	}
	k := key(serial, 0)
	entry, ok := txt.certs[k]
	if !ok {
		t.Fatal("serial number not found in certificate map")
	}
	if entry.serial.Cmp(serial) != 0 {
		t.Fatal("expected serial number to be the same")
	}
}

func TestAddIndex(t *testing.T) {
	txt := EmptyIndex()
	for i, root := range []string{
		"testdata/pki0",
		"testdata/pki1",
	} {
		err := txt.AddIndex(&IndexConfig{
			Index:    filepath.Join(root, "db/index.txt"),
			NewCerts: filepath.Join(root, "db/certs"),
			Serial:   filepath.Join(root, "db/serial"),
			CA:       filepath.Join(root, "ca.crt"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(txt.issuerIDs) != i+1 {
			t.Fatal("expected length of one")
		}
		if len(txt.cfgs) != i+1 {
			t.Fatal("expected length of one")
		}
		if len(txt.certs) == 0 {
			t.Fatal("should have certificate references")
		}
		if txt.cfgs[len(txt.cfgs)-1].Hash != crypto.SHA1 {
			t.Fatal("sha1 should be the default hash function")
		}
	}
}

func TestAddIndex_Err(t *testing.T) {
	txt := EmptyIndex()
	var err error
	for _, cfg := range []IndexConfig{
		{CA: "does not exist"},
		{CA: filepath.Join(testRoot, "ca.crt"), Index: "does not exist"},
	} {
		err = txt.AddIndex(&cfg)
		if !os.IsNotExist(err) {
			t.Error("expecting \"does not exist\" error")
		}
	}
	cfg := &IndexConfig{
		Index:    filepath.Join(testRoot, "db/index.txt"),
		NewCerts: filepath.Join(testRoot, "db/certs"),
		Serial:   filepath.Join(testRoot, "db/serial"),
		CA:       filepath.Join(testRoot, "ca.crt"),
	}
	err = txt.AddIndex(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = txt.AddIndex(cfg)
	if err == nil {
		t.Fatal("expected error for index that is already added")
	}
}

func randomSerial() *big.Int {
	var (
		buf [20]byte
		n   big.Int
	)
	_, err := rand.Reader.Read(buf[:])
	if err != nil {
		panic(err)
	}
	return n.SetBytes(buf[:])
}
