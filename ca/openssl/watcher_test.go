package openssl

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/certutil"
	"gopkg.hrry.dev/ocsprey/internal/ocspext"
)

var logger = logrus.New()

func init() {
	logger.SetOutput(io.Discard)
}

func TestWatcher_handleEvent(t *testing.T) {
	txt := &IndexTXT{}
	w := watcher{}
	setup := func(t *testing.T) func() {
		*txt = *EmptyIndex()
		var err error
		cfg := &IndexConfig{
			Index:    filepath.Join(testRoot, "db/index.txt"),
			NewCerts: filepath.Join(testRoot, "db/certs"),
			Serial:   filepath.Join(testRoot, "db/serial"),
			CA:       filepath.Join(testRoot, "ca.crt"),
			Hash:     crypto.SHA1,
		}
		if err = addConfigOnly(txt, cfg); err != nil {
			t.Fatal(err)
		}
		w = watcher{txt: txt, watcher: nil}
		w.watcher, err = fsnotify.NewWatcher()
		if err != nil {
			t.Fatal(err)
		}
		return func() {
			if err := w.watcher.Close(); err != nil {
				panic(err)
			}
		}
	}

	t.Run(fmt.Sprintf("%s_Ok", t.Name()), func(t *testing.T) {
		defer setup(t)()
		err := w.handleEvent(logger, &fsnotify.Event{Name: filepath.Join(testRoot, "db/index.txt"), Op: fsnotify.Remove})
		if err != nil {
			t.Fatal(err)
		}
		if len(txt.certs) == 0 {
			t.Error("expected certificates to be added after an event")
		}
		for key, cert := range txt.certs {
			cert.Status = ca.Expired
			txt.certs[key] = cert
		}
		err = w.handleEvent(logger, &fsnotify.Event{Name: filepath.Join(testRoot, "db/index.txt"), Op: fsnotify.Write})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range txt.certs {
			if c.Status == ca.Valid {
				t.Error("expected cert to be expired or revoked")
			}
		}
	})

	t.Run(fmt.Sprintf("%s_Err", t.Name()), func(t *testing.T) {
		defer setup(t)()
		err := w.handleEvent(logger, &fsnotify.Event{Name: filepath.Join(testRoot, ""), Op: fsnotify.Chmod})
		if err == nil {
			t.Error("expected error from bad event")
		}
	})
}

// similar to AddIndex but it doesn't populate the certificate entries.
func addConfigOnly(txt *IndexTXT, cfg *IndexConfig) error {
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

	txt.issuerMu.Lock()
	txt.issuerIDs[keyID] = ix
	txt.cfgs = append(txt.cfgs, *cfg)
	txt.issuerMu.Unlock()
	return nil
}
