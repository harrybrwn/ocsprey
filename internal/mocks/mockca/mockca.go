// Code generated by MockGen. DO NOT EDIT.
// Source: gopkg.hrry.dev/ocsprey/ca (interfaces: ResponderDB,CertStore)

// Package mockca is a generated GoMock package.
package mockca

import (
	context "context"
	x509 "crypto/x509"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	ca "gopkg.hrry.dev/ocsprey/ca"
)

// MockResponderDB is a mock of ResponderDB interface.
type MockResponderDB struct {
	ctrl     *gomock.Controller
	recorder *MockResponderDBMockRecorder
}

// MockResponderDBMockRecorder is the mock recorder for MockResponderDB.
type MockResponderDBMockRecorder struct {
	mock *MockResponderDB
}

// NewMockResponderDB creates a new mock instance.
func NewMockResponderDB(ctrl *gomock.Controller) *MockResponderDB {
	mock := &MockResponderDB{ctrl: ctrl}
	mock.recorder = &MockResponderDBMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockResponderDB) EXPECT() *MockResponderDBMockRecorder {
	return m.recorder
}

// Del mocks base method.
func (m *MockResponderDB) Del(arg0 context.Context, arg1 []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Del", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Del indicates an expected call of Del.
func (mr *MockResponderDBMockRecorder) Del(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Del", reflect.TypeOf((*MockResponderDB)(nil).Del), arg0, arg1)
}

// Find mocks base method.
func (m *MockResponderDB) Find(arg0 context.Context, arg1 *x509.Certificate) (*ca.Responder, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Find", arg0, arg1)
	ret0, _ := ret[0].(*ca.Responder)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Find indicates an expected call of Find.
func (mr *MockResponderDBMockRecorder) Find(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Find", reflect.TypeOf((*MockResponderDB)(nil).Find), arg0, arg1)
}

// Get mocks base method.
func (m *MockResponderDB) Get(arg0 context.Context, arg1 []byte) (*ca.Responder, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*ca.Responder)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockResponderDBMockRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockResponderDB)(nil).Get), arg0, arg1)
}

// Put mocks base method.
func (m *MockResponderDB) Put(arg0 context.Context, arg1 *ca.Responder) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Put", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Put indicates an expected call of Put.
func (mr *MockResponderDBMockRecorder) Put(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockResponderDB)(nil).Put), arg0, arg1)
}

// MockCertStore is a mock of CertStore interface.
type MockCertStore struct {
	ctrl     *gomock.Controller
	recorder *MockCertStoreMockRecorder
}

// MockCertStoreMockRecorder is the mock recorder for MockCertStore.
type MockCertStoreMockRecorder struct {
	mock *MockCertStore
}

// NewMockCertStore creates a new mock instance.
func NewMockCertStore(ctrl *gomock.Controller) *MockCertStore {
	mock := &MockCertStore{ctrl: ctrl}
	mock.recorder = &MockCertStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCertStore) EXPECT() *MockCertStoreMockRecorder {
	return m.recorder
}

// Del mocks base method.
func (m *MockCertStore) Del(arg0 context.Context, arg1 ca.KeyID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Del", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Del indicates an expected call of Del.
func (mr *MockCertStoreMockRecorder) Del(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Del", reflect.TypeOf((*MockCertStore)(nil).Del), arg0, arg1)
}

// Get mocks base method.
func (m *MockCertStore) Get(arg0 context.Context, arg1 ca.KeyID) (*x509.Certificate, ca.CertStatus, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", arg0, arg1)
	ret0, _ := ret[0].(*x509.Certificate)
	ret1, _ := ret[1].(ca.CertStatus)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Get indicates an expected call of Get.
func (mr *MockCertStoreMockRecorder) Get(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockCertStore)(nil).Get), arg0, arg1)
}

// Put mocks base method.
func (m *MockCertStore) Put(arg0 context.Context, arg1 *x509.Certificate) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Put", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Put indicates an expected call of Put.
func (mr *MockCertStoreMockRecorder) Put(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Put", reflect.TypeOf((*MockCertStore)(nil).Put), arg0, arg1)
}

// Revoke mocks base method.
func (m *MockCertStore) Revoke(arg0 context.Context, arg1 ca.KeyID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Revoke", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// Revoke indicates an expected call of Revoke.
func (mr *MockCertStoreMockRecorder) Revoke(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Revoke", reflect.TypeOf((*MockCertStore)(nil).Revoke), arg0, arg1)
}
