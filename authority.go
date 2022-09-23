package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sync"

	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/ocspext"
)

type issuerDB struct {
	responders map[string]ca.Responder
	mu         sync.RWMutex
	hasher     crypto.Hash

	subjectHashSet map[string]string
}

var _ ca.ResponderDB = (*issuerDB)(nil)

func (db *issuerDB) add(crt, respCert *x509.Certificate, respKey crypto.Signer) error {
	return db.Put(context.Background(), &ca.Responder{
		CA: crt,
		Signer: ca.KeyPair{
			Key:  respKey,
			Cert: respCert,
		},
	})
}

func (db *issuerDB) get(key []byte) (*ca.Responder, error) {
	k := hex.EncodeToString(key)
	db.mu.RLock()
	r, ok := db.responders[k]
	db.mu.RUnlock()
	if !ok {
		return nil, errors.New("issuer not found")
	}
	return &r, nil
}

func (db *issuerDB) Find(ctx context.Context, leaf *x509.Certificate) (*ca.Responder, error) {
	h := db.hasher.New()
	_, err := h.Write(leaf.RawIssuer)
	if err != nil {
		return nil, err
	}
	subjHash := hex.EncodeToString(h.Sum(nil))
	db.mu.RLock()
	keyid, ok := db.subjectHashSet[subjHash]
	db.mu.RUnlock()
	if !ok {
		return nil, errors.New("could not find CA using issuer DN")
	}
	db.mu.RLock()
	r, ok := db.responders[keyid]
	db.mu.RUnlock()
	if !ok {
		return nil, ca.ErrCertNotFound
	}
	return &r, nil
}

func (db *issuerDB) Get(ctx context.Context, key []byte) (*ca.Responder, error) {
	r, err := db.get(key)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (db *issuerDB) Put(ctx context.Context, r *ca.Responder) error {
	h := db.hasher.New()
	err := ocspext.PublicKeyHash(r.CA, h)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(h.Sum(nil))
	h.Reset()
	_, err = h.Write(r.CA.RawSubject)
	if err != nil {
		return err
	}
	subjHash := hex.EncodeToString(h.Sum(nil))
	db.mu.Lock()
	db.responders[key] = *r
	db.subjectHashSet[subjHash] = key
	db.mu.Unlock()
	return nil
}

func (db *issuerDB) Del(ctx context.Context, key []byte) error {
	k := hex.EncodeToString(key)
	db.mu.Lock()
	delete(db.responders, k)
	db.mu.Unlock()
	return nil
}
