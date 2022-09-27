package testutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/ocspext"
)

var (
	KeySize = 1024
	Hash    = crypto.SHA1
)

func GenCA() (*ca.KeyPair, error) {
	k, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		Version:      3,
		IsCA:         true,
		SerialNumber: randomSerial(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		Subject: pkix.Name{
			CommonName:   "testing CA",
			Organization: []string{"test org"},
		},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, k.Public(), k)
	if err != nil {
		return nil, err
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	h := Hash.New()
	if err = ocspext.PublicKeyHash(crt, h); err != nil {
		return nil, err
	}
	crt.AuthorityKeyId = h.Sum(nil) // root ca needs its own issuer key hash
	return &ca.KeyPair{Key: k, Cert: crt}, nil
}

func GenIntermediate(issuer *ca.KeyPair) (*ca.KeyPair, error) {
	return genCert(
		issuer,
		x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment,
		true,
		nil,
	)
}

func GenLeaf(issuer *ca.KeyPair) (*ca.KeyPair, error) {
	return genCert(
		issuer,
		x509.KeyUsageDataEncipherment,
		false,
		nil,
	)
}

func GenOCSP(issuer *ca.KeyPair) (*ca.KeyPair, error) {
	return genCert(
		issuer,
		x509.KeyUsageDataEncipherment,
		false,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	)
}

func genCert(issuer *ca.KeyPair, keyUsage x509.KeyUsage, pathLenZero bool, extKeyUsage []x509.ExtKeyUsage) (*ca.KeyPair, error) {
	k, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		Version:      3,
		IsCA:         true,
		SerialNumber: randomSerial(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		Subject: pkix.Name{
			CommonName:   "testing intermediate CA",
			Organization: []string{"test org"},
		},
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		MaxPathLenZero:        pathLenZero,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, issuer.Cert, k.Public(), issuer.Key)
	if err != nil {
		return nil, err
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	h := Hash.New()
	if err = ocspext.PublicKeyHash(issuer.Cert, h); err != nil {
		return nil, err
	}
	crt.AuthorityKeyId = h.Sum(nil)
	return &ca.KeyPair{Key: k, Cert: crt}, nil
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
