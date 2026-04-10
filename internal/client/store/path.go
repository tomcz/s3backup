package store

import (
	"fmt"
	"regexp"
)

var s3PathPattern = regexp.MustCompile(`^s3://([^/]+)/(.+)$`)

func IsRemote(path string) bool {
	return s3PathPattern.MatchString(path)
}

func splitRemotePath(remotePath string) (bucket string, objectKey string, err error) {
	md := s3PathPattern.FindStringSubmatch(remotePath)
	if md == nil {
		err = fmt.Errorf("%q is not a valid S3 path", remotePath)
		return
	}
	bucket = md[1]
	objectKey = md[2]
	return
}
