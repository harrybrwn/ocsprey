package server

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ocsp"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/mocks/mockca"
	"gopkg.hrry.dev/ocsprey/internal/testutil"
)

var logger = logrus.New()

func init() { logger.SetOutput(io.Discard) }

func TestResponder(t *testing.T) {
	ctx := log.Stash(context.Background(), logger)
	testutil.Hash = crypto.SHA256
	root := must(testutil.GenCA())
	leaf := must(testutil.GenLeaf(root))
	responder := must(testutil.GenOCSP(root))
	timeNow = func() time.Time { return time.Date(1999, time.January, 1, 1, 1, 0, 0, time.UTC) }
	defer func() {
		timeNow = time.Now
		testutil.Hash = crypto.SHA1
	}()

	newResponse := func(status ocsp.ResponseStatus) []byte {
		template := ocsp.Response{
			Status:             int(status),
			IssuerHash:         testutil.Hash,
			RevocationReason:   ocsp.Unspecified,
			ThisUpdate:         timeNow(),
			NextUpdate:         timeNow().Add(time.Hour),
			ProducedAt:         timeNow(),
			SerialNumber:       leaf.Cert.SerialNumber,
			Extensions:         nil,
			Certificate:        responder.Cert,
			SignatureAlgorithm: responder.Cert.SignatureAlgorithm,
		}
		if status == ocsp.Revoked {
			template.RevokedAt = leaf.Cert.NotAfter
		}
		return must(ocsp.CreateResponse(root.Cert, responder.Cert, template, responder.Key))
	}

	type mockFunc func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte)
	type table struct {
		name string

		// Given input
		request []byte

		// Expected output
		response []byte
		code     int
		mock     mockFunc
	}

	for _, tt := range []table{
		{
			name:     "bad_input_request",
			code:     http.StatusBadRequest,
			request:  []byte("invalid request"),
			response: ocsp.MalformedRequestErrorResponse,
			mock:     func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawRequest []byte) {},
		},
		{
			name:     "responder_not_found",
			code:     http.StatusNotFound,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: ocsp.InternalErrorErrorResponse,
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().
					Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(nil, ca.ErrCertNotFound)
			},
		},
		{
			name:     "leaf_not_found",
			code:     http.StatusOK,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: newResponse(ocsp.Unknown),
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().
					Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(&ca.Responder{CA: root.Cert, Signer: *responder}, nil)
				req := must(ocsp.ParseRequest(rawReq))
				mockCertDB.EXPECT().
					Get(ctx, MatchOCSPReq(req)).
					Return(nil, ca.Invalid, ca.ErrCertNotFound)
			},
		},
		{
			name:     "expired_cert",
			code:     http.StatusOK,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: newResponse(ocsp.Unknown),
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().
					Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(&ca.Responder{CA: root.Cert, Signer: *responder}, nil)
				req := must(ocsp.ParseRequest(rawReq))
				cert := *leaf.Cert
				cert.NotAfter = time.Date(1000, time.January, 1, 1, 0, 0, 0, time.UTC)
				mockCertDB.EXPECT().
					Get(ctx, MatchOCSPReq(req)).
					Return(&cert, ca.Valid, nil)
			},
		},
		{
			name:     "status_expired",
			code:     http.StatusOK,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: newResponse(ocsp.Unknown),
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().
					Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(&ca.Responder{CA: root.Cert, Signer: *responder}, nil)
				req := must(ocsp.ParseRequest(rawReq))
				mockCertDB.EXPECT().
					Get(ctx, MatchOCSPReq(req)).
					Return(leaf.Cert, ca.Expired, nil)
			},
		},
		{
			name:     "status_revoked",
			code:     http.StatusOK,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: newResponse(ocsp.Revoked),
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().
					Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(&ca.Responder{CA: root.Cert, Signer: *responder}, nil)
				req := must(ocsp.ParseRequest(rawReq))
				mockCertDB.EXPECT().
					Get(ctx, MatchOCSPReq(req)).
					Return(leaf.Cert, ca.Revoked, nil)
			},
		},
		{
			name:     "wrong_authorityKeyId",
			code:     http.StatusOK,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: newResponse(ocsp.Unknown),
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().
					Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(&ca.Responder{CA: root.Cert, Signer: *responder}, nil)
				req := must(ocsp.ParseRequest(rawReq))
				cert := *leaf.Cert
				cert.AuthorityKeyId = []byte("wrong authority key id")
				mockCertDB.EXPECT().
					Get(ctx, MatchOCSPReq(req)).
					Return(&cert, ca.Valid, nil)
			},
		},
		{
			name:     "unknown_cert_status",
			code:     http.StatusOK,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: newResponse(ocsp.Unknown),
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(&ca.Responder{CA: root.Cert, Signer: *responder}, nil)
				req := must(ocsp.ParseRequest(rawReq))
				mockCertDB.EXPECT().Get(ctx, MatchOCSPReq(req)).
					Return(leaf.Cert, ca.CertStatus(0xff), nil)
			},
		},
		{
			name:     "status_good",
			code:     http.StatusOK,
			request:  must(ocsp.CreateRequest(leaf.Cert, root.Cert, &ocsp.RequestOptions{Hash: testutil.Hash})),
			response: newResponse(ocsp.Good),
			mock: func(mockResponderDB *mockca.MockResponderDB, mockCertDB *mockca.MockCertStore, rawReq []byte) {
				mockResponderDB.EXPECT().Get(ctx, leaf.Cert.AuthorityKeyId).
					Return(&ca.Responder{CA: root.Cert, Signer: *responder}, nil)
				req := must(ocsp.ParseRequest(rawReq))
				mockCertDB.EXPECT().Get(ctx, MatchOCSPReq(req)).
					Return(leaf.Cert, ca.Valid, nil)
			},
		},
	} {
		t.Run(fmt.Sprintf("%s_%s", t.Name(), tt.name), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockResponderDB := mockca.NewMockResponderDB(ctrl)
			mockCertDB := mockca.NewMockCertStore(ctrl)

			handler := Responder(mockResponderDB, mockCertDB)
			req := httptest.NewRequest("POST", "/", bytes.NewBuffer(tt.request)).WithContext(ctx)
			rec := httptest.NewRecorder()

			tt.mock(mockResponderDB, mockCertDB, tt.request)
			handler(rec, req)

			if rec.Code != tt.code {
				t.Fatalf("expected http response code %d, got %d", tt.code, rec.Code)
			}
			respBytes := rec.Body.Bytes()
			if !bytes.Equal(respBytes, tt.response) {
				t.Fatalf("wrong response body:\nwant %v,\ngot  %v", tt.response, respBytes)
			}
		})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func MatchOCSPReq(r *ocsp.Request) gomock.Matcher {
	return &ocspRequestMatcher{r: r}
}

type ocspRequestMatcher struct {
	r *ocsp.Request
}

func (rm *ocspRequestMatcher) Matches(x any) bool {
	var r *ocsp.Request
	switch v := x.(type) {
	case *ocsp.Request:
		r = v
	case *ocspKeyID:
		r = (*ocsp.Request)(v)
	default:
		return false
	}
	return rm.r.SerialNumber.Cmp(r.SerialNumber) == 0 &&
		bytes.Equal(rm.r.IssuerKeyHash, r.IssuerKeyHash) &&
		bytes.Equal(rm.r.IssuerNameHash, r.IssuerNameHash) &&
		rm.r.HashAlgorithm == r.HashAlgorithm
}

func (rm *ocspRequestMatcher) String() string {
	return fmt.Sprintf("%+v", rm.r)
}
