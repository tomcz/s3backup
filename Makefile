GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
BASE_DIR := $(shell git rev-parse --show-toplevel 2>/dev/null)
LDFLAGS := -X app/s3backup/version.commit=${GITCOMMIT}
GO_PATH := ${BASE_DIR}/code

precommit: clean format test build

travis: clean deps test build

deps:
	cd ${GO_PATH}/src/app && GOPATH=${GO_PATH} dep ensure

clean:
	rm -rf target

target:
	mkdir target

format:
	GOPATH=${GO_PATH} go fmt app/s3backup/...

test:
	GOPATH=${GO_PATH} go test -cover -ldflags "${LDFLAGS}" app/s3backup/...

compile = GOPATH=${GO_PATH} GOOS=$2 GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/$1-$2 app/s3backup/cmd/$1

build: target
	$(call compile,s3backup,linux)
	$(call compile,s3keygen,linux)
	$(call compile,s3backup,darwin)
	$(call compile,s3keygen,darwin)
