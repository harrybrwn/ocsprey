package openssl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/certutil"
)

const testIndex = "" +
	`V	230908224820Z		1000	unknown	/O=Test/CN=test_server
V	230908224820Z		1001	unknown	/O=Test/CN=test_client
V	240828224820Z		1002	unknown	/O=Test/CN=ocsp-test
R	240828224820Z	220908224820Z	1003	unknown	/O=Test/CN=revoked-test
V	230908224850Z		1004	unknown	/O=Test/CN=tester
V	230908224851Z		1005	unknown	/O=Test/CN=tester
R	230908224853Z	220908224853Z,this cert was revoked	1006	unknown	/O=Test/CN=test
V	230908224854Z		2048	unknown	/O=Test/CN=tester
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
			Status:     ca.Revoked,
			expiration: time.Date(2024, time.August, 28, 22, 48, 20, 0, time.UTC),
			revocation: ptr(time.Date(2022, time.September, 8, 22, 48, 20, 0, time.UTC)),
			serial:     big.NewInt(0x1003),
		},
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 50, 0, time.UTC), serial: big.NewInt(0x1004)},
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 51, 0, time.UTC), serial: big.NewInt(0x1005)},
		{
			Status:     ca.Revoked,
			expiration: time.Date(2023, time.September, 8, 22, 48, 53, 0, time.UTC),
			revocation: ptr(time.Date(2022, time.September, 8, 22, 48, 53, 0, time.UTC)),
			// revocationReason: "this cert was revoked",
			serial: big.NewInt(0x1006),
		},
		{Status: ca.Valid, expiration: time.Date(2023, time.September, 8, 22, 48, 54, 0, time.UTC), serial: big.NewInt(0x2048)},
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
		// if exp.revocationReason != r.revocationReason {
		// 	t.Errorf("expected revocation reason %q, got %q", exp.revocationReason, r.revocationReason)
		// }
		if exp.serial.Cmp(r.serial) != 0 {
			t.Errorf("expected serial %q, got %q", exp.serial.Text(10), r.serial.Text(10))
		}
		if r.filename != "" {
			t.Error("expected filename of \"\"")
		}
	}
}

func TestOpenIndex(t *testing.T) {
	txt, err := OpenIndex(
		"./testdata/pki/db/index.txt",
		WithHashFunc(crypto.SHA1),
		WithSerialFile("./testdata/pki/db/serial"),
		WithNewCertsDir("./testdata/pki/db/certs"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	status, err := txt.Status(ctx, big.NewInt(0x1001))
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Revoked {
		t.Fatal("expected status revoked")
	}

	cert, _, err := txt.Get(ctx, big.NewInt(0x1002))
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber.Int64() != 0x1002 {
		t.Fatal("wrong serial number")
	}
	status, err = txt.Status(ctx, cert.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	if status != ca.Valid {
		t.Fatal("expected a valid certificate status")
	}
}

func TestIndexTXT_Put(t *testing.T) {
	txt, err := OpenIndex(
		"./testdata/pki/db/index.txt",
		WithHashFunc(crypto.SHA1),
		WithSerialFile("./testdata/pki/db/serial"),
		WithNewCertsDir("./testdata/pki/db/certs"),
	)
	if err != nil {
		t.Fatal(err)
	}
	rootCA, err := certutil.OpenCertificate("./testdata/pki/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := certutil.OpenKey("./testdata/pki/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	serial := randomSerial()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-client-cert"},
		NotBefore:    time.Now(),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCA, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	defer func() {
		err := txt.Del(ctx, serial)
		if err != nil {
			t.Error(err)
		}
	}()
	if err = txt.Put(ctx, cert); err != nil {
		t.Fatal(err)
	}
	entry, ok := txt.certs[serial.Text(serialBase)]
	if !ok {
		t.Fatal("serial number not found in certificate map")
	}
	if entry.serial.Cmp(serial) != 0 {
		t.Fatal("expected serial number to be the same")
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
