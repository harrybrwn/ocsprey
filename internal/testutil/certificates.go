package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"gopkg.hrry.dev/ocsprey/ca"
)

func GenCA() (*ca.KeyPair, error) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
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
	return &ca.KeyPair{Key: k, Cert: crt}, nil
}

func GenIntermediate(issuer *ca.KeyPair) (*ca.KeyPair, error) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
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
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, issuer.Cert, k.Public(), issuer.Key)
	if err != nil {
		return nil, err
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
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
