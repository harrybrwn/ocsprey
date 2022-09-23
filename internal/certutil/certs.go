package certutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

func OpenCertificate(filename string) (*x509.Certificate, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	return x509.ParseCertificate(block.Bytes)
}

func OpenKey(filename string) (crypto.Signer, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errors.New("unkonwn private key type")
	}
}

func WriteCertificate(filename string, signed []byte) error {
	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()
	return pem.Encode(out, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signed,
	})
}
