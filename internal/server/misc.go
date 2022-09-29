package server

import (
	"crypto/x509"
	"io"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca"
)

func write(logger logrus.FieldLogger, w io.Writer, data []byte) {
	_, err := w.Write(data)
	if err != nil {
		logger.WithError(err).Error("failed to write data")
	}
}

type ocspKeyID ocsp.Request

func (okid *ocspKeyID) Serial() ca.ID   { return okid.SerialNumber }
func (okid *ocspKeyID) KeyHash() []byte { return okid.IssuerKeyHash }

func isOCSPSigner(crt *x509.Certificate) bool {
	for _, u := range crt.ExtKeyUsage {
		if u == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}
