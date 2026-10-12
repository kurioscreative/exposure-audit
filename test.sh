#!/bin/sh
# Runs every check from HANDOFF section 6. Linux is the reference platform:
#   docker run --rm -v "$PWD":/src -w /src golang:1.26 ./test.sh
set -eu
cd "$(dirname "$0")"

unformatted=$(gofmt -l *.go)
if [ -n "$unformatted" ]; then
	echo "gofmt needed:" "$unformatted"
	exit 1
fi
go vet ./...
CGO_ENABLED=0 go build -trimpath -o /dev/null .
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o /dev/null .
CGO_ENABLED=0 go test -count=1 ./...
