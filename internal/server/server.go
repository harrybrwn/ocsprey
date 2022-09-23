package server

import (
	"bytes"
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
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/ocspext"
)

func Responder(authority ca.ResponderDB, certdb ca.CertStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := log.ContextLogger(ctx)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.WithError(err).Warn("failed to read http request body")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}
		req, exts, err := ocspext.ParseRequest(body)
		if err != nil {
			logger.WithError(err).Warn("failed to parse ocsp request")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}

		var (
			now      = time.Now()
			template = ocsp.Response{
				Status:           ocsp.Unknown,
				IssuerHash:       req.HashAlgorithm,
				RevocationReason: ocsp.Unspecified,
				ThisUpdate:       now,
				NextUpdate:       now.Add(time.Hour), // TODO
				SerialNumber:     req.SerialNumber,
				Extensions:       exts,
			}
			cert *x509.Certificate
			stat ca.CertStatus
		)
		logger = logger.WithFields(logrus.Fields{
			"key_hash":  hex.EncodeToString(req.IssuerKeyHash),
			"name_hash": hex.EncodeToString(req.IssuerNameHash),
			"serial":    req.SerialNumber.Text(16),
		})

		responder, err := authority.Get(ctx, req.IssuerKeyHash)
		if err != nil {
			logger.WithError(err).Warn("issuer not found")
			w.WriteHeader(404)
			_, _ = w.Write(ocsp.InternalErrorErrorResponse)
			return
		}
		template.Certificate = responder.Signer.Cert
		template.SignatureAlgorithm = responder.Signer.Cert.SignatureAlgorithm

		cert, stat, err = certdb.Get(ctx, req.SerialNumber)
		if err != nil {
			logger.WithError(err).Warn("failed to get certificate")
			template.Status = ocsp.Unknown
			goto response
		}
		template.SerialNumber = cert.SerialNumber

		switch stat {
		case ca.Valid:
			template.Status = ocsp.Good
		case ca.Revoked:
			template.Status = ocsp.Revoked
			template.RevokedAt = cert.NotAfter
			logger.Info("certificate is revoked")
			goto response
		case ca.Expired:
			logger.Info("certificate status of expired")
			template.Status = ocsp.Unknown
			goto response
		default:
			logger.Info("invalid certificate status")
			template.Status = ocsp.Unknown
			goto response
		}
		if !bytes.Equal(req.IssuerKeyHash, cert.AuthorityKeyId) {
			// TODO I don't think authorityKeyId is guaranteed to be in the
			// certificate, this might be something to toggle based on
			// configuration.
			logger.Info("request issuer key hash does not match certificate authorityKeyID")
			template.Status = ocsp.Unknown
			goto response
		}
		now = time.Now()
		if now.After(cert.NotAfter) {
			template.Status = ocsp.Unknown
			logger.Info("certificate is expired")
			goto response
		}

	response:
		template.ProducedAt = now
		resp, err := ocsp.CreateResponse(
			responder.CA,
			responder.Signer.Cert,
			template,
			responder.Signer.Key,
		)
		if err != nil {
			logger.WithError(err).Error("failed to create raw response")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(ocsp.InternalErrorErrorResponse)
			return
		}
		_, _ = w.Write(resp)
	}
}

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
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		logger := log.ContextLogger(ctx)
		// var body certificateBody
		// err := json.NewDecoder(r.Body).Decode(&body)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			logger.WithError(err).Error("failed to read request body")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		block, _ := pem.Decode(raw)
		// block, err := b64Pem(body.Cert)
		if err != nil {
			logger.WithError(err).Error("failed to decode pem block")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.WithError(err).Warn("failed to parse certificate from pem")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logger = logger.WithFields(logrus.Fields{
			"serial": cert.SerialNumber.Text(16),
			"CN":     cert.Subject.CommonName,
			"O":      strings.Join(cert.Subject.Organization, ","),
		})

		responder, err := authority.Find(ctx, cert)
		if err != nil {
			logger.WithError(err).Debug("failed to find certificate issuer and responder")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		roots := x509.NewCertPool()
		roots.AddCert(responder.CA)
		_, err = cert.Verify(x509.VerifyOptions{
			Roots: roots,
		})
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

type responderBody struct {
	Signer struct {
		Key  string `json:"key"`
		Cert string `json:"cert"`
	} `json:"signer"`
	CA string `json:"ca"`
}

func b64Pem(raw string) (*pem.Block, error) {
	dec := make([]byte, len(raw))
	_, err := base64.StdEncoding.Decode(dec, []byte(raw))
	if err != nil {
		return nil, fmt.Errorf("base64 decode failure: %w", err)
	}
	block, _ := pem.Decode(dec)
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
