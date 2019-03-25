#!/bin/sh

set -eu

cd `dirname $0`/..

echo "Installing lint search engine..."
go get github.com/alecthomas/gometalinter/
gometalinter --config=linter.json --install

echo "Looking for lint..."
export GOPATH=$GOPATH:$PWD:$PWD/vendor
gometalinter --config=linter.json ./src/...

echo "Double checking spelling..."
misspell -error src *.md
