CREATE TABLE IF NOT EXISTS "certificate" (
	id        SERIAL PRIMARY KEY,
	serial    VARCHAR(27) UNIQUE NOT NULL, -- base64 serial number
	der       BYTEA
);

CREATE TABLE IF NOT EXISTS "responder" (
	id          SERIAL PRIMARY KEY,
	-- Issuer public key hash
	issuer_hash VARCHAR(27) UNIQUE NOT NULL,
	-- Issuer name hash
	name_hash BYTEA,
	-- OCSP responder private key
	key BYTEA,
	-- OCSP responder certificate
	crt BYTEA,
	-- Issuer certificate.
	ca BYTEA
);

CREATE TABLE IF NOT EXISTS "status_line" (
	id         SERIAL PRIMARY KEY,
	status     SMALLINT  NOT NULL,
	expiration TIMESTAMP NOT NULL,
	revocation TIMESTAMP,
	-- Certificiate revocation reason
	reason    INT,
	issuer_id INT,
	cert_id   INT,
	FOREIGN KEY (issuer_id) REFERENCES "responder" (id),
	FOREIGN KEY (cert_id)   REFERENCES "certificate" (id)
	  ON DELETE CASCADE,
	UNIQUE (issuer_id, cert_id)
);
