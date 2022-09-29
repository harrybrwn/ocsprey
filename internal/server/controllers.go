package server

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/log"
)

func ControlIssuer(authority ca.ResponderDB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := log.ContextLogger(ctx)
		switch r.Method {
		case "POST":
			var (
				body responderBody
				rp   ca.Responder
			)
			err := json.NewDecoder(r.Body).Decode(&body)
			if err != nil {
				logger.WithError(err).Warn("failed to decode request body")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			err = body.toResponder(&rp)
			if err != nil {
				logger.WithError(err).Warn("failed to parse pem blocks")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			// TODO if we want to enforce a global root CA for all intermediates
			// then we should check that here.
			if !rp.CA.IsCA {
				logger.Info("new certificate issuer is not a CA")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !isOCSPSigner(rp.Signer.Cert) {
				logger.Info("signer is not an OCSP key pair")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			err = authority.Put(ctx, &rp)
			if err != nil {
				logger.WithError(err).Error("failed to insert new responder")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			logger.Info("ocsp responder added")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	})
}

func ControlCert(authority ca.ResponderDB, certdb ca.CertStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		logger := log.ContextLogger(ctx)
		cert, err := parseCertBody(r)
		if err != nil {
			logger.WithError(err).Error("failed to parse decode certificate in http body")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logger = logger.WithFields(logrus.Fields{
			"serial": hex.EncodeToString(cert.SerialNumber.Bytes()),
			"CN":     cert.Subject.CommonName,
			"O":      strings.Join(cert.Subject.Organization, ","),
		})

		err = verify(ctx, authority, cert)
		if err != nil {
			logger.WithError(err).Warn("failed to verify certificate")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		err = certdb.Put(ctx, cert)
		if err != nil {
			logger.WithError(err).Error("failed to add certificate to database")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		logger.Info("leaf certificate added")
		w.WriteHeader(200)
	})
}

func ControlCertRevoke(authority ca.ResponderDB, certdb ca.CertStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := log.ContextLogger(ctx)
		switch r.Method {
		case "PUT":
			cert, err := parseCertBody(r)
			if err != nil {
				logger.WithError(err).Warn("failed to parse decode certificate in http body")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			logger = logger.WithFields(logrus.Fields{
				"serial": cert.SerialNumber.Text(16),
				"CN":     cert.Subject.CommonName,
				"O":      strings.Join(cert.Subject.Organization, ","),
			})
			err = certdb.Revoke(ctx, &ocspKeyID{
				SerialNumber:  cert.SerialNumber,
				IssuerKeyHash: cert.AuthorityKeyId,
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	})
}

func parseCertBody(r *http.Request) (*x509.Certificate, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(block.Bytes)
}

func verify(ctx context.Context, au ca.ResponderDB, crt *x509.Certificate) error {
	responder, err := au.Find(ctx, crt)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(responder.CA)
	_, err = crt.Verify(x509.VerifyOptions{Roots: roots})
	return err
}

type responderBody struct {
	CA     string `json:"ca"`
	Signer struct {
		Key  string `json:"key"`
		Cert string `json:"cert"`
	} `json:"signer"`
}

func b64Pem(raw string) (*pem.Block, error) {
	dec := make([]byte, len(raw))
	_, err := base64.StdEncoding.Decode(dec, []byte(raw))
	if err != nil {
		return nil, fmt.Errorf("base64 decode failure: %w", err)
	}
	block, _ := pem.Decode(dec)
	if block == nil {
		return nil, errors.New("failed to decode pem block")
	}
	return block, nil
}

func (rb *responderBody) toResponder(r *ca.Responder) error {
	caBlock, err := b64Pem(rb.CA)
	if err != nil {
		return err
	}
	certBlock, err := b64Pem(rb.Signer.Cert)
	if err != nil {
		return err
	}
	keyBlock, err := b64Pem(rb.Signer.Key)
	if err != nil {
		return err
	}
	r.CA, err = x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA: %w", err)
	}
	r.Signer.Cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse signer cert: %w", err)
	}
	switch r.Signer.Cert.PublicKeyAlgorithm {
	case x509.RSA:
		r.Signer.Key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case x509.ECDSA:
		r.Signer.Key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return errors.New("unknown public key algorithm")
	}
	if err != nil {
		return fmt.Errorf("failed to parse signer key: %w", err)
	}
	return nil
}
