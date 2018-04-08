GITCOMMIT = $(shell git rev-parse --short HEAD 2>/dev/null)
GOPATH = $(shell git rev-parse --show-toplevel 2>/dev/null)
LDFLAGS = -X s3backup/version.commit=${GITCOMMIT}

precommit: clean format test build

travis: clean test build

clean:
	rm -rf target

target:
	mkdir target

format:
	GOPATH=${GOPATH} go fmt s3backup/...

test:
	GOPATH=${GOPATH} go test -cover -ldflags "${LDFLAGS}" s3backup/...

compile = GOPATH=${GOPATH} GOOS=$2 GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/$1-$2 s3backup/cmd/$1

build: target
	$(call compile,s3backup,linux)
	$(call compile,s3keygen,linux)
	$(call compile,s3backup,darwin)
	$(call compile,s3keygen,darwin)
