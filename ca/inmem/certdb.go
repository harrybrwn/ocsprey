package inmem

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"time"
	"unsafe"

	"gopkg.hrry.dev/ocsprey/ca"
)

func NewCertDB() *certdb {
	return &certdb{
		certs:  make(map[certKey]*certificate),
		hashes: make(map[string]uint8),
	}
}

type certdb struct {
	certs  map[certKey]*certificate
	mu     sync.Mutex
	hashes map[string]uint8
}

type certificate struct {
	cert   *x509.Certificate
	status ca.CertStatus
	reason ca.RevocationReason
}

type certKey [21]byte

func newCertKey(serial ca.ID, ix uint8) certKey {
	// | serial number | issuer index |
	// | 20 bytes      | 1 byte       |
	var (
		k certKey
		n = big.NewInt(0).SetBytes(serial.Bytes())
	)
	const width = 8 * uint(unsafe.Sizeof(ix))
	n.Lsh(n, width)
	n.Or(n, big.NewInt(int64(ix)))
	copy(k[:], n.Bytes())
	return k
}

func (db *certdb) index(key []byte) uint8 {
	k := hex.EncodeToString(key)
	return db.hashes[k]
}

func (db *certdb) Get(ctx context.Context, id ca.KeyID) (*x509.Certificate, ca.CertStatus, error) {
	ix := db.index(id.KeyHash())
	key := newCertKey(id.Serial(), ix)
	db.mu.Lock()
	c, ok := db.certs[key]
	db.mu.Unlock()
	if !ok {
		return nil, ca.Invalid, ca.ErrCertNotFound
	}
	return c.cert, c.status, nil
}

func (db *certdb) Del(ctx context.Context, id ca.KeyID) error {
	ix := db.index(id.KeyHash())
	key := newCertKey(id.Serial(), ix)
	db.mu.Lock()
	delete(db.certs, key)
	db.mu.Unlock()
	return nil
}

func (db *certdb) Put(ctx context.Context, crt *x509.Certificate) error {
	entry := certificate{
		cert:   crt,
		status: ca.Valid,
	}
	now := time.Now()
	if now.After(crt.NotAfter) {
		entry.status = ca.Expired
	}
	if len(crt.AuthorityKeyId) == 0 {
		return errors.New("cannot insert certificate without authority key id")
	}

	keyHash := hex.EncodeToString(crt.AuthorityKeyId)
	db.mu.Lock()
	ix, ok := db.hashes[keyHash]
	db.mu.Unlock()
	if !ok {
		db.mu.Lock()
		ix = uint8(len(db.hashes))
		db.hashes[keyHash] = ix
		db.mu.Unlock()
	}

	key := newCertKey(crt.SerialNumber, ix)
	db.mu.Lock()
	db.certs[key] = &entry
	db.mu.Unlock()
	return nil
}

func (db *certdb) Revoke(ctx context.Context, id ca.KeyID) error {
	ix := db.index(id.KeyHash())
	key := newCertKey(id.Serial(), ix)
	db.mu.Lock()
	cert, ok := db.certs[key]
	db.mu.Unlock()
	if !ok {
		return ca.ErrCertNotFound
	}
	cert.status = ca.Revoked
	cert.reason = ca.Unspecified
	return nil
}
