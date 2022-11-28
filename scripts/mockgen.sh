#!/usr/bin/env bash
set -e

MOCKGEN="$(go env GOPATH)/bin/mockgen"

if [[ ! -x "${MOCKGEN}" ]]; then
    echo "Installing mockgen ..."
    go install github.com/golang/mock/mockgen@latest
fi
