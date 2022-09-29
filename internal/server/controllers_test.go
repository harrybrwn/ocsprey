package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"gopkg.hrry.dev/ocsprey/ca"
	"gopkg.hrry.dev/ocsprey/internal/log"
	"gopkg.hrry.dev/ocsprey/internal/mocks/mockca"
	"gopkg.hrry.dev/ocsprey/internal/testutil"
)

func TestIssuer(t *testing.T) {
	type table struct {
		name string
		code int
		mock func(mockResponderDB *mockca.MockResponderDB) io.Reader
	}

	// logger.SetOutput(os.Stdout)
	// defer logger.SetOutput(io.Discard)
	ctx := log.Stash(context.Background(), logger)
	for _, tt := range []table{
		{
			name: "nil_request_body",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				return nil
			},
		},
		{
			name: "bad_ca_cert",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				return jsonBody(map[string]any{
					"ca":     b64(&x509.Certificate{Raw: []byte("invalid der encoding probably")}),
					"signer": map[string]string{"cert": "", "key": ""},
				})
			},
		},
		{
			name: "empty_responder_cert",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				responder := must(testutil.GenOCSP(root))
				return jsonBody(map[string]any{
					"ca": b64(root.Cert),
					"signer": map[string]string{
						"cert": "",
						"key":  b64Key(responder.Key),
					},
				})
			},
		},
		{
			name: "empty_responder_key",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				responder := must(testutil.GenOCSP(root))
				return jsonBody(map[string]any{
					"ca": b64(root.Cert),
					"signer": map[string]string{
						"cert": b64(responder.Cert),
						"key":  "",
					},
				})
			},
		},
		{
			name: "invalid_responder_cert",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				responder := must(testutil.GenOCSP(root))
				return jsonBody(map[string]any{
					"ca": b64(root.Cert),
					"signer": map[string]string{
						"cert": hex.EncodeToString(responder.Cert.Raw),
						"key":  b64Key(responder.Key),
					},
				})
			},
		},
		{
			name: "invalid_responder_key",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				responder := must(testutil.GenOCSP(root))
				return jsonBody(map[string]any{
					"ca": b64(root.Cert),
					"signer": map[string]string{
						"cert": b64(responder.Cert),
						"key":  hex.EncodeToString(x509.MarshalPKCS1PrivateKey(responder.Key.(*rsa.PrivateKey))),
					},
				})
			},
		},
		{
			name: "bad_ca",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				badRoot := must(testutil.GenLeaf(root))
				responder := must(testutil.GenOCSP(root))
				return jsonBody(map[string]any{
					"ca":     b64(badRoot.Cert),
					"signer": map[string]string{"cert": b64(responder.Cert), "key": b64Key(responder.Key)},
				})
			},
		},
		{
			name: "bad_responder",
			code: http.StatusBadRequest,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				responder := must(testutil.GenLeaf(root))
				return jsonBody(map[string]any{
					"ca":     b64(root.Cert),
					"signer": map[string]string{"cert": b64(responder.Cert), "key": b64Key(responder.Key)},
				})
			},
		},
		{
			name: "db_failure",
			code: http.StatusInternalServerError,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				responder := must(testutil.GenOCSP(root))
				mockResponderDB.EXPECT().Put(ctx, MatchResponder(&ca.Responder{
					CA:     root.Cert,
					Signer: *responder,
				})).Return(ca.ErrCertNotFound)
				return jsonBody(map[string]any{
					"ca":     b64(root.Cert),
					"signer": map[string]string{"cert": b64(responder.Cert), "key": b64Key(responder.Key)},
				})
			},
		},
		{
			name: "ok",
			code: http.StatusOK,
			mock: func(mockResponderDB *mockca.MockResponderDB) io.Reader {
				root := must(testutil.GenCA())
				responder := must(testutil.GenOCSP(root))
				mockResponderDB.EXPECT().Put(ctx, MatchResponder(&ca.Responder{
					CA:     root.Cert,
					Signer: *responder,
				})).Return(nil)
				return jsonBody(map[string]any{
					"ca":     b64(root.Cert),
					"signer": map[string]string{"cert": b64(responder.Cert), "key": b64Key(responder.Key)},
				})
			},
		},
	} {
		t.Run(fmt.Sprintf("%s_%s", t.Name(), tt.name), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			mockResponderDB := mockca.NewMockResponderDB(ctrl)
			handler := ControlIssuer(mockResponderDB)
			request := tt.mock(mockResponderDB)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/", request).WithContext(ctx)
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.code {
				t.Errorf("wrong status code: want %d, got %d", tt.code, rec.Code)
			}
		})
	}
}

func TestIssuer_MethodNotAllowed(t *testing.T) {
	ctx := log.Stash(context.Background(), logger)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockResponderDB := mockca.NewMockResponderDB(ctrl)
	handler := ControlIssuer(mockResponderDB)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("CONNECT", "/", nil).WithContext(ctx)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("wrong status code: want %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestResponderBodyDecoding(t *testing.T) {
	root := must(testutil.GenCA())
	ocsp := must(testutil.GenOCSP(root))
	expectedResponder := &ca.Responder{CA: root.Cert, Signer: *ocsp}
	r := newResponderBody(b64(root.Cert), b64(ocsp.Cert), b64Key(ocsp.Key))
	var rp ca.Responder
	if err := r.toResponder(&rp); err != nil {
		t.Fatal(err)
	}
	if !MatchResponder(expectedResponder).Matches(&rp) {
		t.Error("expected responders to match")
	}
}

func TestResponderBodyDecodingError(t *testing.T) {
	root := must(testutil.GenCA())
	ocsp := must(testutil.GenOCSP(root))
	for _, body := range []*responderBody{
		newResponderBody("", b64(ocsp.Cert), b64Key(ocsp.Key)),
		newResponderBody(b64(root.Cert), "", b64Key(ocsp.Key)),
		newResponderBody(b64(root.Cert), b64(ocsp.Cert), ""),

		newResponderBody(b64(&x509.Certificate{Raw: []byte("invalid cert")}), b64(ocsp.Cert), b64Key(ocsp.Key)),
		newResponderBody(b64(ocsp.Cert), b64(&x509.Certificate{Raw: []byte("invalid cert")}), b64Key(ocsp.Key)),
		newResponderBody(b64(root.Cert), b64(ocsp.Cert), base64.StdEncoding.EncodeToString(keyDer(ocsp.Key))),

		newResponderBody(base64.StdEncoding.EncodeToString(root.Cert.Raw), b64(ocsp.Cert), b64Key(ocsp.Key)),
		newResponderBody(b64(ocsp.Cert), base64.StdEncoding.EncodeToString(ocsp.Cert.Raw), b64Key(ocsp.Key)),
	} {
		var rp ca.Responder
		err := body.toResponder(&rp)
		if err == nil {
			t.Error("expected error")
		}
	}
}

func newResponderBody(root, cert, key string) *responderBody {
	r := responderBody{CA: root}
	r.Signer.Cert = cert
	r.Signer.Key = key
	return &r
}

func jsonBody[T any](m T) io.Reader {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(m)
	if err != nil {
		panic(err)
	}
	return buf
}

func b64(c *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.Raw,
	}))
}

func keyDer(key crypto.Signer) []byte {
	var bytes []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		bytes = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		var err error
		bytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			panic(err)
		}
	default:
		var err error
		bytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			panic(err)
		}
	}
	return bytes
}

func b64Key(key crypto.Signer) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDer(key),
	}))
}

func MatchResponder(r *ca.Responder) gomock.Matcher {
	return &responderMatcher{r: r}
}

type responderMatcher struct {
	r *ca.Responder
}

func (rm *responderMatcher) Matches(x any) bool {
	v, ok := x.(*ca.Responder)
	if !ok {
		return false
	}
	return bytes.Equal(rm.r.CA.Raw, v.CA.Raw) &&
		bytes.Equal(rm.r.Signer.Cert.Raw, v.Signer.Cert.Raw)
}

func (rm *responderMatcher) String() string {
	return fmt.Sprintf("%+v", rm.r)
}
