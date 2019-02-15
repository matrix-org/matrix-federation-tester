#!/bin/sh

set -exu

# Enable Go 1.11+ modules support in TravisCI.
# See https://dave.cheney.net/2018/07/16/using-go-modules-with-travis-ci
export GO111MODULE=on

# run the tests
go test

# check it builds
go build

# look for lint
./scripts/find-lint.sh
