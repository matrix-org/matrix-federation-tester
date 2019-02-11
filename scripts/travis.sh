#!/bin/sh

set -exu

# run the tests
gb test

# check it builds
gb build

# look for lint
./scripts/find-lint.sh
