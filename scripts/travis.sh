#!/bin/sh

set -exu

# We explicitely set the GO111MODULE in this script so that Go's module support
# is enabled even though Travis CI does the checkout in the $GOPATH (in which
# case the default behaviour is to disable module support). In a normal use,
# setting this variable isn't necessary as the recommended install procedure is
# via `git clone`, which makes it unlikely that the repository ever gets checked
# out in the user's $GOPATH (in which case the default behaviour is to enable
# module support, as long as the `go.mod` file exists).

# run the tests
GO111MODULE=on go test

# check it builds
GO111MODULE=on go build

# look for lint
GO111MODULE=off ./scripts/find-lint.sh
