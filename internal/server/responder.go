package server

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/ocspext"
)

var timeNow = time.Now

func Responder(authority ca.ResponderDB, certdb ca.CertStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := log.ContextLogger(ctx).WithField("component", "http-ocsp-responder")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			logger.WithError(err).Warn("failed to read http request body")
			w.WriteHeader(http.StatusBadRequest)
			write(logger, w, ocsp.MalformedRequestErrorResponse)
			return
		}
		req, exts, err := ocspext.ParseRequest(body)
		if err != nil {
			logger.WithError(err).Warn("failed to parse ocsp request")
			w.WriteHeader(http.StatusBadRequest)
			write(logger, w, ocsp.MalformedRequestErrorResponse)
			return
		}

		var (
			now      = timeNow()
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
			"serial":    hex.EncodeToString(req.SerialNumber.Bytes()),
		})

		responder, err := authority.Get(ctx, req.IssuerKeyHash)
		if err != nil {
			logger.WithError(err).Warn("issuer not found")
			w.WriteHeader(http.StatusNotFound)
			write(logger, w, ocsp.InternalErrorErrorResponse)
			return
		}
		template.Certificate = responder.Signer.Cert
		template.SignatureAlgorithm = responder.Signer.Cert.SignatureAlgorithm

		cert, stat, err = certdb.Get(ctx, (*ocspKeyID)(req))
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
			logger.Debug("certificate is revoked")
			goto response
		case ca.Expired:
			logger.Debug("certificate status of expired")
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
		now = timeNow()
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
			write(logger, w, ocsp.InternalErrorErrorResponse)
			return
		}
		write(logger, w, resp)
	}
}
