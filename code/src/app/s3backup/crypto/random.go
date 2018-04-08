package crypto

import (
	"crypto/rand"
	"io/ioutil"
)

func random(length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func createTempFile(prefix string, body []byte) (string, error) {
	file, err := ioutil.TempFile("", prefix)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = file.Write(body)
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}
