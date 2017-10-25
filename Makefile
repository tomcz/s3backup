GITCOMMIT = $(shell git rev-parse --short HEAD 2>/dev/null)
GOPATH = $(shell git rev-parse --show-toplevel 2>/dev/null)
LDFLAGS = -X s3backup/version.commit=${GITCOMMIT}

default: test install

format:
	GOPATH=${GOPATH} go fmt s3backup/...

test:
	GOPATH=${GOPATH} go test -cover -ldflags "${LDFLAGS}" s3backup/...

install:
	GOPATH=${GOPATH} go install -ldflags "${LDFLAGS}" s3backup/cmd/s3backup
	GOPATH=${GOPATH} go install -ldflags "${LDFLAGS}" s3backup/cmd/s3keygen

clean:
	rm -rf target

target:
	mkdir target

build: target
	GOOS=linux  GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/s3backup-linux64 s3backup/cmd/s3backup
	GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/s3backup-darwin  s3backup/cmd/s3backup
	GOOS=linux  GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/s3keygen-linux64 s3backup/cmd/s3keygen
	GOOS=darwin GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/s3keygen-darwin  s3backup/cmd/s3keygen

deploy:
	artifactctl store --path /security/s3backup/${GITCOMMIT}/s3backup-linux64 --filepath target/s3backup-linux64
	artifactctl store --path /security/s3backup/${GITCOMMIT}/s3backup-darwin  --filepath target/s3backup-darwin
	artifactctl store --path /security/s3backup/${GITCOMMIT}/s3keygen-linux64 --filepath target/s3keygen-linux64
	artifactctl store --path /security/s3backup/${GITCOMMIT}/s3keygen-darwin  --filepath target/s3keygen-darwin

generate-aes-key: install
	./bin/s3keygen aes

generate-rsa-keys: install
	./bin/s3keygen rsa
