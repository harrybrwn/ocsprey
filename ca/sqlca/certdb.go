package sqlca

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"time"

	"github.com/lib/pq"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/db"
)

func NewCertDB(db db.DB) *certDB {
	return &certDB{db}
}

type certDB struct{ db db.DB }

func (c *certDB) Get(ctx context.Context, key ca.KeyID) (*x509.Certificate, ca.CertStatus, error) {
	var (
		status ca.CertStatus
		exp    time.Time
		rev    pq.NullTime
		der    []byte
	)
	serial := base64.RawStdEncoding.EncodeToString(key.Serial().Bytes())
	issuerKeyHash := base64.RawStdEncoding.EncodeToString(key.KeyHash())
	rows, err := c.db.QueryContext(
		ctx,
		certGetQuery,
		serial,
		issuerKeyHash,
	)
	if err != nil {
		return nil, ca.Invalid, err
	}
	err = db.ScanOne(rows, &status, &exp, &rev, &der)
	if err != nil {
		return nil, ca.Invalid, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ca.Invalid, err
	}
	return cert, status, nil
}

func (c *certDB) Del(ctx context.Context, key ca.KeyID) error {
	serial := base64.RawStdEncoding.EncodeToString(key.Serial().Bytes())
	// TODO figure out how to use issuer hash to delete the correct cert and cert line
	_, err := c.db.ExecContext(ctx, certDeleteQuery, serial)
	return err
}

func (c *certDB) Put(ctx context.Context, cert *x509.Certificate) error {
	return c.putWithStatus(ctx, ca.Valid, cert)
}

func (c *certDB) putWithStatus(ctx context.Context, status ca.CertStatus, cert *x509.Certificate) error {
	serial := base64.RawStdEncoding.EncodeToString(cert.SerialNumber.Bytes())
	issuerKeyHash := base64.RawStdEncoding.EncodeToString(cert.AuthorityKeyId)
	_, err := c.db.ExecContext(
		ctx, certPutQuery,
		issuerKeyHash,
		status,         // certificate status
		cert.NotAfter,  // expiration timestamp
		nil,            // revocation timestamp
		ca.Unspecified, // revocation reason
		serial,
		cert.Raw,
	)
	return err
}

func (c *certDB) Revoke(ctx context.Context, key ca.KeyID) error {
	serial := base64.RawStdEncoding.EncodeToString(key.Serial().Bytes())
	issuerKeyHash := base64.RawStdEncoding.EncodeToString(key.KeyHash())
	_, err := c.db.ExecContext(
		ctx, certRevokeQuery,
		serial,
		issuerKeyHash,
		ca.Revoked,     // status
		ca.Unspecified, // revocation reason
	)
	return err
}

const certDeleteQuery = `
DELETE FROM "certificate"
WHERE serial = $1`

const certPutQuery = `
WITH cert AS (
  INSERT INTO "certificate" (serial, der)
  VALUES ($6, $7)
  RETURNING id, 1 as qid
),
issuer AS (
  SELECT id, 1 as qid FROM "responder"
  WHERE issuer_hash = $1
)
INSERT INTO status_line (
  status,
  expiration,
  revocation,
  reason,
  issuer_id,
  cert_id
)
SELECT
  $2, $3, $4, $5,
  i.id, c.id
FROM issuer i
JOIN cert c ON (i.qid = c.qid)`

const certGetQuery = `
SELECT
  s.status,
  s.expiration,
  s.revocation,
  c.der
FROM status_line s
  JOIN certificate c ON (s.cert_id = c.id)
  JOIN responder r   ON (s.issuer_id = r.id)
WHERE
  c.serial = $1 AND
  r.issuer_hash = $2`

const certRevokeQuery = `
WITH cert AS (
  SELECT id FROM certificate
  WHERE serial = $1
),
issuer AS (
  SELECT id FROM responder
  WHERE issuer_hash = $2
)
UPDATE status_line
SET
  status     = $3,
  revocation = CURRENT_TIMESTAMP,
  reason     = $4
WHERE
  cert_id   IN (SELECT id FROM cert) AND
  issuer_id IN (SELECT id FROM issuer)`
