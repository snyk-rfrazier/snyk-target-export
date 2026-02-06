.PHONY: build test lint fmt clean check

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o snyk-refresh .

test:
	go test ./... -v -race

lint:
	gofmt -l . | grep . && exit 1 || true
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -f snyk-refresh
	rm -rf dist/

check: fmt lint test
	@echo "All checks passed"

snapshot:
	goreleaser release --snapshot --clean

.DEFAULT_GOAL := build
