GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_TAG := $(shell git describe --tags 2>/dev/null)

LDFLAGS := -X github.com/tomcz/s3backup/config.commit=${GITCOMMIT}
LDFLAGS := ${LDFLAGS} -X github.com/tomcz/s3backup/config.tag=${GIT_TAG}

.PHONY: precommit
precommit: clean generate format lint test build

.PHONY: commit
commit: clean test build

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
	go test -race -cover -ldflags "${LDFLAGS}" ./...

.PHONY: generate
generate:
ifeq (, $(shell which mockgen))
	go install github.com/golang/mock/mockgen@latest
endif
	go generate ./client/...

compile = GOOS=$2 GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/$1-$2 ./cmd/$1

.PHONY: build
build: target
	$(call compile,s3backup,linux)
	$(call compile,s3backup,darwin)
