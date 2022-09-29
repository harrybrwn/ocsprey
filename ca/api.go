package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
)

type CertStatus uint8

const (
	Invalid CertStatus = iota
	Valid
	Revoked
	Expired
)

const (
	SerialOctets = 20
	SerialBits   = 8 * SerialOctets
)

var (
	ErrCertNotFound = errors.New("certificate not found")
	ErrCertExpired  = errors.New("certificate is expired")
)

type KeyID interface {
	Serial() ID
	KeyHash() []byte
}

type ID interface{ Bytes() []byte }

// TODO Add a certificate wrapper type
// TODO Need to be able to get revocation reason
type CertStore interface {
	Get(context.Context, KeyID) (*x509.Certificate, CertStatus, error)
	Del(context.Context, KeyID) error
	Put(context.Context, *x509.Certificate) error
	Revoke(context.Context, KeyID) error
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
	// Get a responder by key hash.
	Get(context.Context, []byte) (*Responder, error)
	// Insert a new responder
	Put(context.Context, *Responder) error
	// Delete a responder
	Del(context.Context, []byte) error
	// Find the responder keys given a leaf certificate
	Find(context.Context, *x509.Certificate) (*Responder, error)
}
