#!/bin/sh

set -eu

cd `dirname $0`/..

echo "Installing lint search engine..."
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.27.0

echo "Looking for lint..."
$(go env GOPATH)/bin/golangci-lint run

echo "Double checking spelling..."
go get -u github.com/client9/misspell/cmd/misspell
$(go env GOPATH)/bin/misspell -error src *.md
