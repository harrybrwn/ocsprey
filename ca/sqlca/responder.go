package sqlca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"

	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/db"
)

func NewResponder(db db.DB, hash crypto.Hash) *responder {
	return &responder{
		db:   db,
		hash: hash,
	}
}

type responder struct {
	db   db.DB
	hash crypto.Hash
}

// Get a responder given the root CA's public key hash.
func (r *responder) Get(ctx context.Context, id []byte) (*ca.Responder, error) {
	key := base64.RawStdEncoding.EncodeToString(id)
	rows, err := r.db.QueryContext(
		ctx,
		responderGetQuery,
		key,
	)
	if err != nil {
		return nil, err
	}
	var crtDer, keyDer, caDer []byte
	err = db.ScanOne(rows, &crtDer, &keyDer, &caDer)
	if err != nil {
		return nil, err
	}
	crtAuthority, err := x509.ParseCertificate(caDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse responder CA: %w", err)
	}
	var signer ca.KeyPair
	err = parseKeyPair(&signer, crtDer, keyDer)
	if err != nil {
		return nil, err
	}
	return &ca.Responder{
		Signer: signer,
		CA:     crtAuthority,
	}, nil
}

// Put a responder by storing the ocsp responder key, certificate, and issuer
// certificate using the issuer's public key hash.
func (r *responder) Put(ctx context.Context, responder *ca.Responder) error {
	keyDer, err := x509.MarshalPKCS8PrivateKey(responder.Signer.Key)
	if err != nil {
		return err
	}
	h := r.hash.New()
	var issuerKeyHash []byte
	if responder.CA.AuthorityKeyId != nil {
		issuerKeyHash = responder.CA.AuthorityKeyId
	} else if responder.Signer.Cert.AuthorityKeyId != nil {
		issuerKeyHash = responder.Signer.Cert.AuthorityKeyId
	} else {
		err = hashPublicKey(responder.CA, h)
		if err != nil {
			return err
		}
		issuerKeyHash = h.Sum(nil)
		h.Reset()
	}
	h.Write(responder.CA.RawSubject)
	nameHash := h.Sum(nil)
	key := base64.RawStdEncoding.EncodeToString(issuerKeyHash)
	_, err = r.db.ExecContext(
		ctx, responderPutQuery,
		key,
		nameHash,
		responder.Signer.Cert.Raw,
		keyDer,
		responder.CA.Raw,
	)
	return err
}

const responderDelQuery = `DELETE FROM responder WHERE issuer_hash = $1`

// Dell will delete a responder given the CA's public key hash.
func (r *responder) Del(ctx context.Context, id []byte) error {
	key := base64.RawStdEncoding.EncodeToString(id)
	_, err := r.db.ExecContext(ctx, responderDelQuery, key)
	return err
}

// Find a responder given a leaf certificate
func (r *responder) Find(ctx context.Context, leaf *x509.Certificate) (*ca.Responder, error) {
	if leaf.AuthorityKeyId == nil {
		return nil, errors.New("certificate has no authority key ID")
	}
	return r.Get(ctx, leaf.AuthorityKeyId)
}

func parseKeyPair(pair *ca.KeyPair, crtDer, keyDer []byte) (err error) {
	pair.Cert, err = x509.ParseCertificate(crtDer)
	if err != nil {
		return fmt.Errorf("failed to parse responder certificate: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDer)
	if err != nil {
		return fmt.Errorf("failed to parse responder private key: %w", err)
	}
	var ok bool
	pair.Key, ok = key.(crypto.Signer)
	if !ok {
		return errors.New("stored key not valid")
	}
	return nil
}

func hashPublicKey(crt *x509.Certificate, h hash.Hash) error {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(crt.RawSubjectPublicKeyInfo, &publicKeyInfo)
	if err != nil {
		return err
	}
	_, err = h.Write(publicKeyInfo.PublicKey.RightAlign())
	return err
}

const responderGetQuery = `
SELECT crt, key, ca FROM responder
WHERE issuer_hash = $1`

const responderPutQuery = `
INSERT INTO responder (
  issuer_hash,
  name_hash,
  crt,
  key,
  ca
)
VALUES ($1, $2, $3, $4, $5)`
