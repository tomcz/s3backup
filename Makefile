GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
LDFLAGS := -X github.com/tomcz/s3backup/version.commit=${GITCOMMIT}

precommit: clean format test build

travis: clean test build

clean:
	rm -rf target

target:
	mkdir target

format:
	go fmt ./...

test:
	go test -cover -ldflags "${LDFLAGS}" ./...

compile = GOOS=$2 GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/$1-$2 ./cmd/$1

build: target
	$(call compile,s3backup,linux)
	$(call compile,s3keygen,linux)
	$(call compile,s3backup,darwin)
	$(call compile,s3keygen,darwin)
