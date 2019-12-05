package utils

import "io/ioutil"

func CreateTempFile(prefix string, body []byte) (string, error) {
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
