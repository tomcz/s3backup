GITCOMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_TAG := $(shell git describe --tags 2>/dev/null)

LDFLAGS := -X github.com/tomcz/s3backup/config.commit=${GITCOMMIT}
LDFLAGS := ${LDFLAGS} -X github.com/tomcz/s3backup/config.tag=${GIT_TAG}

precommit: clean format test build

travis: clean
	GO111MODULE=on GOFLAGS='-mod=vendor' $(MAKE) test build

clean:
	rm -rf target

target:
	mkdir target

format:
	@echo "Running goimports ..."
	@goimports -w -local github.com/tomcz/s3backup $(shell find . -type f -name '*.go' | grep -v '/vendor/')

test:
	go test -race -cover -ldflags "${LDFLAGS}" ./...

generate:
ifeq (, $(shell which mockgen))
	go install github.com/golang/mock/mockgen@v1.5.0
endif
	go generate ./client/...
	${MAKE} format

compile = GOOS=$2 GOARCH=amd64 go build -ldflags "${LDFLAGS}" -o target/$1-$2 ./cmd/$1

build: target
	$(call compile,s3backup,linux)
	$(call compile,s3backup,darwin)
