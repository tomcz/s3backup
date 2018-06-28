package mocks

import mock "github.com/stretchr/testify/mock"

// Cipher is an autogenerated mock type for the Cipher type
type Cipher struct {
	mock.Mock
}

// Decrypt provides a mock function with given fields: cipherTextFile, plainTextFile
func (_m *Cipher) Decrypt(cipherTextFile string, plainTextFile string) error {
	ret := _m.Called(cipherTextFile, plainTextFile)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(cipherTextFile, plainTextFile)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Encrypt provides a mock function with given fields: plainTextFile, cipherTextFile
func (_m *Cipher) Encrypt(plainTextFile string, cipherTextFile string) error {
	ret := _m.Called(plainTextFile, cipherTextFile)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(plainTextFile, cipherTextFile)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}