package openssl

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/certutil"
	"gopkg.hrry.dev/ocsprey/internal/ocspext"
)

//go:generate sh testdata/gen.sh

type indexKey [21]byte

type IndexTXT struct {
	// Certs is a map of one index key to one certificate entry
	certs map[indexKey]indexEntry
	mu    sync.RWMutex

	cfgs      []IndexConfig
	issuerIDs map[string]uint8
	issuerMu  sync.Mutex
}

type IndexConfig struct {
	NewCerts string
	Serial   string
	Index    string
	CA       string
	Hash     crypto.Hash
}

func EmptyIndex() *IndexTXT {
	txt := IndexTXT{
		certs:     make(map[indexKey]indexEntry),
		issuerIDs: make(map[string]uint8),
	}
	return &txt
}

func (txt *IndexTXT) AddIndex(cfg *IndexConfig) error {
	if cfg.Hash == 0 {
		cfg.Hash = crypto.SHA1
	}

	txt.issuerMu.Lock() // make sure the order is serializable
	ix := uint8(len(txt.cfgs))
	txt.issuerMu.Unlock()
	ca, err := certutil.OpenCertificate(cfg.CA)
	if err != nil {
		return err
	}
	// Should contain the hash of the public key
	if ca.SubjectKeyId == nil {
		return errors.New("CA certificate has no subject key ID")
	}
	h := cfg.Hash.New()
	// This will correspond with IssuerKeyHash for OCSP requests.
	if err = ocspext.PublicKeyHash(ca, h); err != nil {
		return err
	}
	keyID := hex.EncodeToString(h.Sum(nil))
	_, found := txt.issuerIDs[keyID]
	if found {
		return errors.New("ca already loaded")
	}

	f, err := os.Open(cfg.Index)
	if err != nil {
		return err
	}
	defer f.Close()
	entries, err := parseIndex(f)
	if err != nil {
		return err
	}
	var k indexKey
	txt.mu.Lock()
	for _, entry := range entries {
		k = key(entry.serial, ix)
		txt.certs[k] = *entry
	}
	txt.mu.Unlock()

	txt.issuerMu.Lock()
	txt.issuerIDs[keyID] = ix
	txt.cfgs = append(txt.cfgs, *cfg)
	txt.issuerMu.Unlock()
	return nil
}

func key(serial ca.ID, ix uint8) indexKey {
	// Each key encodes the serial number an an index of the configuration that
	// holds metadata about the certificate issuer's openssl index database.
	//
	// | serial number | index id |
	// | 20 bytes      | 1 byte   |
	var k indexKey
	copy(k[:], append(serial.Bytes(), ix))
	return k
}

func (txt *IndexTXT) Get(ctx context.Context, id ca.KeyID) (*x509.Certificate, ca.CertStatus, error) {
	ix, err := txt.getIndex(id.KeyHash())
	if err != nil {
		return nil, ca.Invalid, err
	}
	key := key(id.Serial(), ix)
	txt.mu.RLock()
	entry, ok := txt.certs[key]
	txt.mu.RUnlock()
	if !ok {
		return nil, ca.Invalid, ca.ErrCertNotFound
	}
	file := txt.entryFile(&entry, ix)
	cert, err := certutil.OpenCertificate(file)
	if err != nil {
		return nil, entry.Status, err
	}
	return cert, entry.Status, nil
}

func (txt *IndexTXT) Status(ctx context.Context, id ca.KeyID) (ca.CertStatus, error) {
	ix, err := txt.getIndex(id.KeyHash())
	if err != nil {
		return ca.Invalid, err
	}
	key := key(id.Serial(), ix)
	txt.mu.RLock()
	entry, ok := txt.certs[key]
	txt.mu.RUnlock()
	if !ok {
		return ca.Invalid, ca.ErrCertNotFound
	}
	return entry.Status, nil
}

func (txt *IndexTXT) Del(ctx context.Context, id ca.KeyID) error {
	ix, err := txt.getIndex(id.KeyHash())
	if err != nil {
		return err
	}
	key := key(id.Serial(), ix)
	txt.mu.RLock()
	entry, ok := txt.certs[key]
	delete(txt.certs, key)
	txt.mu.RUnlock()
	if !ok {
		return ca.ErrCertNotFound
	}
	return os.Remove(txt.entryFile(&entry, ix))
}

func (txt *IndexTXT) Put(ctx context.Context, cert *x509.Certificate) error {
	var (
		err        error
		revocation *time.Time = nil
		status                = ca.Valid
	)

	now := time.Now()
	if now.After(cert.NotAfter) {
		revocation = &now
		status = ca.Expired
	}
	ix, err := txt.getIndex(cert.AuthorityKeyId)
	if err != nil {
		return err
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Int64() == 0 {
		cert.SerialNumber, err = txt.incrementSerial(ix)
		if err != nil {
			return err
		}
	}

	key := key(cert.SerialNumber, ix)
	file := txt.filename(cert.SerialNumber, ix)
	if err = certutil.WriteCertificate(file, cert.Raw); err != nil {
		return err
	}
	entry := indexEntry{
		Status:     status,
		expiration: cert.NotAfter,
		revocation: revocation,
		serial:     cert.SerialNumber,
		filename:   file,
	}
	txt.mu.Lock()
	txt.certs[key] = entry
	txt.mu.Unlock()
	return nil
}

func (txt *IndexTXT) Revoke(ctx context.Context, id ca.KeyID) error {
	ix, err := txt.getIndex(id.KeyHash())
	if err != nil {
		return err
	}
	key := key(id.Serial(), ix)
	txt.mu.RLock()
	e, found := txt.certs[key]
	txt.mu.RUnlock()
	if !found {
		return ca.ErrCertNotFound
	}
	e.Status = ca.Revoked
	txt.mu.Lock()
	txt.certs[key] = e
	txt.mu.Unlock()
	return nil
}

// Sync will take the map of entries being held in memory and write it back to disk.
func (txt *IndexTXT) Sync() error {
	panic("not implemented")
}

func (txt *IndexTXT) filename(serial *big.Int, ix uint8) string {
	h := hex.EncodeToString(serial.Bytes())
	cfg := txt.cfgs[ix]
	return filepath.Join(
		cfg.NewCerts,
		fmt.Sprintf("%s.pem", strings.ToUpper(h)),
	)
}

func (txt *IndexTXT) entryFile(entry *indexEntry, ix uint8) string {
	if len(entry.filename) > 0 {
		return entry.filename
	}
	return txt.filename(entry.serial, ix)
}

func (txt *IndexTXT) getIndex(keyHash []byte) (uint8, error) {
	k := hex.EncodeToString(keyHash)
	txt.issuerMu.Lock()
	ix, found := txt.issuerIDs[k]
	txt.issuerMu.Unlock()
	if !found {
		return 0, errors.New("failed to find issuer index")
	}
	return ix, nil
}

func (txt *IndexTXT) incrementSerial(ix uint8) (*big.Int, error) {
	cfg := txt.cfgs[ix]
	bytes, err := os.ReadFile(cfg.Serial)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseInt(string(bytes), 16, 64)
	if err != nil {
		return nil, err
	}
	// TODO update the file serial.old
	serial := big.NewInt(n)
	file, err := os.OpenFile(cfg.Serial, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return serial, err
	}
	defer file.Close()
	n++
	_, err = file.Write([]byte(strconv.FormatInt(n, 16)))
	return serial, err
}

// YYMMDDHHMMSSZ
const indexDBTimeFormat = "060102150405Z"

type indexEntry struct {
	Status           ca.CertStatus
	expiration       time.Time
	revocation       *time.Time
	revocationReason uint8
	serial           *big.Int
	filename         string
	name             string
}

func parseIndex(in io.Reader) ([]*indexEntry, error) {
	// Used <https://pki-tutorial.readthedocs.io/en/latest/cadb.html> as a guild to the file format.
	r := csv.NewReader(in)
	r.Comma = '\t'
	r.FieldsPerRecord = 6
	entries := make([]*indexEntry, 0)
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		var serial big.Int
		_, ok := serial.SetString(record[3], 16)
		if !ok {
			return nil, errors.New("invalid serial number")
		}
		e := &indexEntry{
			serial:   &serial,
			filename: record[4],
			name:     record[5],
		}
		if e.filename == "unknown" {
			e.filename = ""
		}
		switch record[0][0] {
		case 'V':
			e.Status = ca.Valid
		case 'R':
			e.Status = ca.Revoked
		case 'E':
			e.Status = ca.Expired
		}
		e.expiration, err = time.Parse(indexDBTimeFormat, record[1])
		if err != nil {
			return nil, err
		}
		// The revocation date might not be present.
		if len(record[2]) > 0 {
			parts := strings.Split(record[2], ",")
			revocation, err := time.Parse(indexDBTimeFormat, parts[0])
			if err != nil {
				return nil, err
			}
			if len(parts) > 1 {
				e.revocationReason = uint8(parseRevocationReason(parts[1]))
			}
			e.revocation = &revocation
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
func parseRevocationReason(s string) int {
	switch s {
	case "unspecified":
		return ocsp.Unspecified
	case "keyCompromise":
		return ocsp.KeyCompromise
	case "CACompromise":
		return ocsp.CACompromise
	case "affiliationChanged":
		return ocsp.AffiliationChanged
	case "superseded":
		return ocsp.Superseded
	case "cessationOfOperation":
		return ocsp.CessationOfOperation
	case "certificateHold":
		return ocsp.CertificateHold
	case "removeFromCRL":
		return ocsp.RemoveFromCRL
	case "privilegeWithdrawn":
		return ocsp.PrivilegeWithdrawn
	case "aACompromise", "aacompromise":
		return ocsp.AACompromise
	default:
		return ocsp.Unspecified
	}
}

var _ ca.CertStore = (*IndexTXT)(nil)
