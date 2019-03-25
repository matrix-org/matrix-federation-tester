#!/bin/sh

set -exu

# run the tests
GO111MODULE=on go test

# check it builds
GO111MODULE=on go build

# look for lint
GO111MODULE=on ./scripts/find-lint.sh
