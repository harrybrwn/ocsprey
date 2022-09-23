package openssl

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/csv"
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
)

//go:generate sh testdata/gen.sh

type IndexTXT struct {
	Hash        crypto.Hash
	NewCertsDir string
	SerialFile  string
	files       []string
	certs       map[string]*indexEntry
	mu          sync.RWMutex
	fileMu      sync.Mutex // protects index and serial files
}

type IndexConfig struct {
	NewCerts string
	Serial   string
	Index    string
}

type IndexDBOption func(*IndexTXT)

func WithSerialFile(filename string) IndexDBOption {
	return func(it *IndexTXT) { it.SerialFile = filename }
}

func WithNewCertsDir(dir string) IndexDBOption { return func(it *IndexTXT) { it.NewCertsDir = dir } }
func WithHashFunc(h crypto.Hash) IndexDBOption { return func(it *IndexTXT) { it.Hash = h } }

func OpenIndex(indexFile string, options ...IndexDBOption) (*IndexTXT, error) {
	f, err := os.Open(indexFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := parseIndex(f)
	if err != nil {
		return nil, err
	}
	certs := make(map[string]*indexEntry, len(entries))
	for _, entry := range entries {
		certs[entry.serial.Text(serialBase)] = entry
	}
	txt := IndexTXT{
		Hash:        crypto.SHA1,
		NewCertsDir: "./certs",
		files:       make([]string, 0),
		certs:       certs,
	}
	for _, o := range options {
		o(&txt)
	}
	txt.files = append(txt.files, indexFile)
	return &txt, nil
}

func EmptyIndex(options ...IndexDBOption) *IndexTXT {
	txt := IndexTXT{
		Hash:        crypto.SHA1,
		NewCertsDir: "./certs",
		SerialFile:  "./ca.crl",
		certs:       make(map[string]*indexEntry),
		files:       make([]string, 0),
	}
	for _, o := range options {
		o(&txt)
	}
	return &txt
}

const serialBase = 16

func (txt *IndexTXT) Get(ctx context.Context, serial *big.Int) (*x509.Certificate, ca.CertStatus, error) {
	key := serial.Text(serialBase)
	txt.mu.RLock()
	entry, ok := txt.certs[key]
	txt.mu.RUnlock()
	if !ok {
		return nil, ca.Invalid, ca.ErrCertNotFound
	}
	var file string
	if len(entry.filename) > 0 {
		file = entry.filename
	} else {
		file = filepath.Join(txt.NewCertsDir, fmt.Sprintf("%s.pem", strings.ToUpper(key)))
	}
	cert, err := certutil.OpenCertificate(file)
	if err != nil {
		return nil, entry.Status, err
	}
	return cert, entry.Status, nil
}

func (txt *IndexTXT) Status(ctx context.Context, serial *big.Int) (ca.CertStatus, error) {
	key := serial.Text(serialBase)
	txt.mu.RLock()
	entry, ok := txt.certs[key]
	txt.mu.RUnlock()
	if !ok {
		return ca.Invalid, ca.ErrCertNotFound
	}
	return entry.Status, nil
}

func (txt *IndexTXT) Del(ctx context.Context, serial *big.Int) error {
	key := serial.Text(serialBase)
	txt.mu.RLock()
	entry, ok := txt.certs[key]
	delete(txt.certs, key)
	txt.mu.RUnlock()
	var file string
	if !ok {
		return nil
	} else if len(entry.filename) > 0 {
		file = entry.filename
	} else {
		file = filepath.Join(txt.NewCertsDir, fmt.Sprintf("%s.pem", strings.ToUpper(key)))
	}
	return os.Remove(file)
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

	if cert.SerialNumber == nil || cert.SerialNumber.Int64() == 0 {
		cert.SerialNumber, err = txt.incrementSerial()
		if err != nil {
			return err
		}
	}
	key := cert.SerialNumber.Text(serialBase)
	certfile := filepath.Join(txt.NewCertsDir, fmt.Sprintf("%s.pem", strings.ToUpper(key)))
	if err = certutil.WriteCertificate(certfile, cert.Raw); err != nil {
		return err
	}
	entry := indexEntry{
		Status:     status,
		expiration: cert.NotAfter,
		revocation: revocation,
		serial:     cert.SerialNumber,
		filename:   certfile,
	}
	txt.mu.Lock()
	txt.certs[key] = &entry
	txt.mu.Unlock()
	return nil
}

func (txt *IndexTXT) Revoke(ctx context.Context, serial *big.Int) error {
	return nil
}

// Sync will take the map of entries being held in memory and write it back to disk.
func (txt *IndexTXT) Sync() error {
	panic("not implemented")
}

func (txt *IndexTXT) incrementSerial() (*big.Int, error) {
	txt.fileMu.Lock()
	defer txt.fileMu.Unlock()
	bytes, err := os.ReadFile(txt.SerialFile)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseInt(string(bytes), 16, 64)
	if err != nil {
		return nil, err
	}
	// TODO update the file serial.old
	serial := big.NewInt(n)
	file, err := os.OpenFile(txt.SerialFile, os.O_WRONLY|os.O_TRUNC, 0644)
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
