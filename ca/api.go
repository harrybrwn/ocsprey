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
	ErrCertExists   = errors.New("certificate already exists")
	ErrCertRevoked  = errors.New("certificate is revoked")
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

type RevocationReason uint8

const (
	// See https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
	Unspecified RevocationReason = iota
	KeyCompromise
	CACompromise
	AffiliationChanged
	Superseded
	CessationOfOperation
	CertificateHold
	_ // 7 is reserved
	RemoveFromCRL
	PrivilegeWithdrawn
	AACompromise
)

func (rr RevocationReason) String() string {
	// See https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
	switch rr {
	case Unspecified:
		return "unspecified"
	case KeyCompromise:
		return "keyCompromise"
	case CACompromise:
		return "CACompromise"
	case AffiliationChanged:
		return "affiliationChanged"
	case Superseded:
		return "superseded"
	case CessationOfOperation:
		return "cessationOfOperation"
	case CertificateHold:
		return "certificateHold"
	case 7:
		// error
		return "unspecified"
	case RemoveFromCRL:
		return "removeFromCRL"
	case PrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case AACompromise:
		return "aACompromise"
	default:
		return "unspecified"
	}
}

func ParseRevocationReason(s string) RevocationReason {
	// See https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
	switch s {
	case "unspecified":
		return Unspecified
	case "keyCompromise":
		return KeyCompromise
	case "CACompromise":
		return CACompromise
	case "affiliationChanged":
		return AffiliationChanged
	case "superseded":
		return Superseded
	case "cessationOfOperation":
		return CessationOfOperation
	case "certificateHold":
		return CertificateHold
	case "removeFromCRL":
		return RemoveFromCRL
	case "privilegeWithdrawn":
		return PrivilegeWithdrawn
	case "aACompromise", "aacompromise":
		return AACompromise
	default:
		return Unspecified
	}
}
