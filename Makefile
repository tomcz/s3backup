BASE_DIR := $(shell git rev-parse --show-toplevel 2>/dev/null)
GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_TAG := $(shell git describe --tags 2>/dev/null)

LDFLAGS := -s -w -X github.com/tomcz/s3backup/config.commit=${GITCOMMIT}
LDFLAGS := ${LDFLAGS} -X github.com/tomcz/s3backup/config.tag=${GIT_TAG}
OUTFILE ?= s3backup

.PHONY: precommit
precommit: clean generate format lint test compile

.PHONY: build
build: clean compile

.PHONY: commit
commit: clean test cross-compile
	ls -lha target/

.PHONY: clean
clean:
	rm -rf target

target:
	mkdir target

.PHONY: format
format:
	@echo 'goimports ./...'
	@goimports -w -local github.com/tomcz/s3backup $(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test -race -cover ./...

.PHONY: generate
generate:
	go generate ./client/...

.PHONY: compile
compile: target
	go build -ldflags "${LDFLAGS}" -o target/${OUTFILE} ./cmd/s3backup/...
	gzip -c < target/${OUTFILE} > target/${OUTFILE}.gz

.PHONY: cross-compile
cross-compile:
	OUTFILE=s3backup-linux-amd64 GOOS=linux GOARCH=amd64 $(MAKE) compile
	OUTFILE=s3backup-linux-nocgo CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(MAKE) compile
	OUTFILE=s3backup-osx-amd64 GOOS=darwin GOARCH=amd64 $(MAKE) compile
	OUTFILE=s3backup-osx-arm64 GOOS=darwin GOARCH=arm64 $(MAKE) compile
	OUTFILE=s3backup-win-amd64.exe GOOS=windows GOARCH=amd64 $(MAKE) compile
	OUTFILE=s3backup-win-386.exe GOOS=windows GOARCH=386 $(MAKE) compile
	(cd target && find . -name '*.gz' -exec sha256sum {} \;) > target/verify.sha256

.PHONY: vendor
vendor:
	go mod tidy -compat=1.20
	go mod vendor
