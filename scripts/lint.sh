#!/usr/bin/env bash
set -e

REVIVE="$(go env GOPATH)/bin/revive"
if [[ ! -x "${REVIVE}" ]]; then
    echo "Installing revive ..."
    go install github.com/mgechev/revive@latest
fi
echo "Running revive ..."
 # shellcheck disable=SC2046
"${REVIVE}" -set_exit_status -config scripts/revive.toml $(go list ./...)

STATICCHECK="$(go env GOPATH)/bin/staticcheck"
if [[ ! -x "${STATICCHECK}" ]]; then
    echo "Installing staticcheck ..."
    go install honnef.co/go/tools/cmd/staticcheck@latest
fi
echo "Running staticcheck ..."
 # shellcheck disable=SC2046
"${STATICCHECK}" $(go list ./...)

GOSEC="$(go env GOPATH)/bin/gosec"
if [[ ! -x "${GOSEC}" ]]; then
    echo "Installing gosec ..."
    go install github.com/securego/gosec/v2/cmd/gosec@latest
fi
echo "Running gosec ..."
"${GOSEC}" -quiet -exclude-generated -exclude-dir vendor -exclude G104,G304,G307 ./...
