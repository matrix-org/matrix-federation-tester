#!/bin/sh

set -exu

# run the tests
go test

# check it builds
go build

# look for lint
./scripts/find-lint.sh
