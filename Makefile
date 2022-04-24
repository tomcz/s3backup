GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_TAG := $(shell git describe --tags 2>/dev/null)

LDFLAGS := -s -w -X github.com/tomcz/s3backup/config.commit=${GITCOMMIT}
LDFLAGS := ${LDFLAGS} -X github.com/tomcz/s3backup/config.tag=${GIT_TAG}

.PHONY: precommit
precommit: clean generate format lint test compile

.PHONY: commit
commit: clean test cross-compile
	rm target/s3backup
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
	rm -f target/s3backup
	go build -ldflags "${LDFLAGS}" -o target ./cmd/...

pack = gzip -c < target/s3backup > target/s3backup-${1}.gz

.PHONY: cross-compile
cross-compile:
	GOOS=linux GOARCH=amd64 $(MAKE) compile
	$(call pack,linux-amd64)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(MAKE) compile
	$(call pack,linux-amd64-nocgo)
	GOOS=darwin GOARCH=amd64 $(MAKE) compile
	$(call pack,osx-amd64)
	GOOS=darwin GOARCH=arm64 $(MAKE) compile
	$(call pack,osx-arm64)
	GOOS=windows GOARCH=amd64 $(MAKE) compile
	$(call pack,win-amd64.exe)
	GOOS=windows GOARCH=386 $(MAKE) compile
	$(call pack,win-386.exe)
