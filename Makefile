BINARY ?= bin/keyinject
VERSION ?= dev
SIGNING_IDENTITY ?=
SIGNING_IDENTIFIER ?= dev.local.keyinject

.PHONY: all build test vet fmt clean sign verify-signature

all: test build

build:
	mkdir -p $(dir $(BINARY))
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w *.go

clean:
	rm -rf bin

sign: build
	@test -n "$(SIGNING_IDENTITY)" || (echo "Set SIGNING_IDENTITY, for example SIGNING_IDENTITY=keyinject-dev" >&2; exit 2)
	codesign --force --sign "$(SIGNING_IDENTITY)" --identifier "$(SIGNING_IDENTIFIER)" $(BINARY)

verify-signature:
	codesign --verify --strict --verbose=2 $(BINARY)
	codesign -dv --verbose=2 $(BINARY) 2>&1 | grep -F "Identifier=$(SIGNING_IDENTIFIER)"
