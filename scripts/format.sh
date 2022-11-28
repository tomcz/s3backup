#!/usr/bin/env bash
set -e

GOIMPORTS="$(go env GOPATH)/bin/goimports"

if [[ ! -x "${GOIMPORTS}" ]]; then
    echo "Installing goimports ..."
    go install golang.org/x/tools/cmd/goimports@latest
fi

 # shellcheck disable=SC2046
"${GOIMPORTS}" -w -local github.com/tomcz/s3backup $(find . -type f -name '*.go' -not -path './vendor/*')
