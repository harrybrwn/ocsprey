package testutil

import (
	"crypto"
	"crypto/x509"
)

type KeyPair struct {
	Key  crypto.Signer
	Cert *x509.Certificate
}

// TODO
func GenPair() (*KeyPair, error) {
	return nil, nil
}
