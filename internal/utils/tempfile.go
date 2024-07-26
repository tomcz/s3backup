package utils

import "os"

func CreateTempFile(prefix string, body []byte) (string, error) {
	file, err := os.CreateTemp("", prefix)
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
