#!/bin/sh

set -eu

cd `dirname $0`/..

echo "Installing lint search engine..."
go get github.com/alecthomas/gometalinter/
gometalinter --config=linter.json --install

echo "Looking for lint..."
gometalinter --config=linter.json src/github.com/matrix-org/matrix-federation-tester

echo "Double checking spelling..."
misspell -error src *.md
