// Code generated by MockGen. DO NOT EDIT.
// Source: hash.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "go.uber.org/mock/gomock"
)

// MockHash is a mock of Hash interface.
type MockHash struct {
	ctrl     *gomock.Controller
	recorder *MockHashMockRecorder
}

// MockHashMockRecorder is the mock recorder for MockHash.
type MockHashMockRecorder struct {
	mock *MockHash
}

// NewMockHash creates a new mock instance.
func NewMockHash(ctrl *gomock.Controller) *MockHash {
	mock := &MockHash{ctrl: ctrl}
	mock.recorder = &MockHashMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockHash) EXPECT() *MockHashMockRecorder {
	return m.recorder
}

// Calculate mocks base method.
func (m *MockHash) Calculate(filePath string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Calculate", filePath)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Calculate indicates an expected call of Calculate.
func (mr *MockHashMockRecorder) Calculate(filePath interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Calculate", reflect.TypeOf((*MockHash)(nil).Calculate), filePath)
}

// Verify mocks base method.
func (m *MockHash) Verify(filePath, expectedChecksum string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Verify", filePath, expectedChecksum)
	ret0, _ := ret[0].(error)
	return ret0
}

// Verify indicates an expected call of Verify.
func (mr *MockHashMockRecorder) Verify(filePath, expectedChecksum interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Verify", reflect.TypeOf((*MockHash)(nil).Verify), filePath, expectedChecksum)
}
