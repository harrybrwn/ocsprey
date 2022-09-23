package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"math/big"
)

type CertStatus uint8

const (
	Invalid CertStatus = iota
	Valid
	Revoked
	Expired
)

var (
	ErrCertNotFound = errors.New("certificate not found")
	ErrCertExpired  = errors.New("certificate is expired")
)

type KeyID interface {
	Hash() crypto.Hash
	Bytes() []byte
}

type CertStore interface {
	Get(context.Context, *big.Int) (*x509.Certificate, CertStatus, error)
	Del(context.Context, *big.Int) error
	Put(context.Context, *x509.Certificate) error
	Status(context.Context, *big.Int) (CertStatus, error)
}

type KeyPair struct {
	Key  crypto.Signer
	Cert *x509.Certificate
}

type Responder struct {
	Signer KeyPair
	CA     *x509.Certificate
}

type ResponderDB interface {
	Get(context.Context, []byte) (*Responder, error)
	Put(context.Context, *Responder) error
	Del(context.Context, []byte) error
	// Find the responder keys given a leaf certificate
	Find(context.Context, *x509.Certificate) (*Responder, error)
}

// AuthorityDB describes a structure that holds issuer certificates which
// includes CAs and intermediate CAs.
type AuthorityStore interface {
	// Issuer will take a leaf certificate and return the issuer of that
	// certificate if it exists.
	Issuer(*x509.Certificate) (*x509.Certificate, error)
	// Get will get a certificate using the keyID
	Get(keyID []byte) (*x509.Certificate, error)
	// Put will insert a new CA certificate into the store.
	Put(*x509.Certificate) error
	// Del will delete a certificate
	Del(keyID []byte) error
}
