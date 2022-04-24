GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_TAG := $(shell git describe --tags 2>/dev/null)

LDFLAGS := -s -w -X github.com/tomcz/s3backup/config.commit=${GITCOMMIT}
LDFLAGS := ${LDFLAGS} -X github.com/tomcz/s3backup/config.tag=${GIT_TAG}
OUTFILE ?= s3backup

.PHONY: precommit
precommit: clean generate format lint test compile

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
ifeq (, $(shell which goimports))
	go install golang.org/x/tools/cmd/goimports@latest
endif
	@echo "Running goimports ..."
	@goimports -w -local github.com/tomcz/s3backup $(shell find . -type f -name '*.go' | grep -v '/vendor/')

.PHONY: lint
lint:
ifeq (, $(shell which staticcheck))
	go install honnef.co/go/tools/cmd/staticcheck@latest
endif
	@echo "Running staticcheck ..."
	@staticcheck $(shell go list ./... | grep -v /vendor/)

.PHONY: test
test:
	go test -race -cover ./...

.PHONY: generate
generate:
ifeq (, $(shell which mockgen))
	go install github.com/golang/mock/mockgen@latest
endif
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
