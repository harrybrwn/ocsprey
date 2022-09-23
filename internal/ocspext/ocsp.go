package ocspext

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"

	"golang.org/x/crypto/ocsp"
)

func PublicKeyHash(crt *x509.Certificate, hash hash.Hash) error {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(crt.RawSubjectPublicKeyInfo, &publicKeyInfo)
	if err != nil {
		return err
	}
	_, err = hash.Write(publicKeyInfo.PublicKey.RightAlign())
	return err
}

func ParseRequest(bytes []byte) (*ocsp.Request, []pkix.Extension, error) {
	var req ocspRequest
	rest, err := asn1.Unmarshal(bytes, &req)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) > 0 {
		return nil, nil, errors.New("trailing data in OCSP request")
	}
	if len(req.TBSRequest.RequestList) == 0 {
		return nil, nil, errors.New("OCSP request contains no request body")
	}
	innerRequest := req.TBSRequest.RequestList[0]

	hashFunc := getHashAlgorithmFromOID(innerRequest.Cert.HashAlgorithm.Algorithm)
	if hashFunc == crypto.Hash(0) {
		return nil, nil, errors.New("OCSP request uses unknown hash function")
	}

	request := &ocsp.Request{
		HashAlgorithm:  hashFunc,
		IssuerNameHash: innerRequest.Cert.NameHash,
		IssuerKeyHash:  innerRequest.Cert.IssuerKeyHash,
		SerialNumber:   innerRequest.Cert.SerialNumber,
	}
	return request, req.TBSRequest.ExtensionList, nil
}

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}

func getHashAlgorithmFromOID(target asn1.ObjectIdentifier) crypto.Hash {
	for hash, oid := range hashOIDs {
		if oid.Equal(target) {
			return hash
		}
	}
	return crypto.Hash(0)
}

type ocspRequest struct {
	TBSRequest tbsRequest
}

type tbsRequest struct {
	Version       int              `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName pkix.RDNSequence `asn1:"explicit,tag:1,optional"`
	RequestList   []request
	ExtensionList []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

type request struct {
	Cert certID
}

type certID struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

//func hasNonce(exts []pkix.Extension) *pkix.Extension {
//	nonce_oid := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
//	for _, ext := range exts {
//		if ext.Id.Equal(nonce_oid) {
//			return &ext
//		}
//	}
//	return nil
//}
