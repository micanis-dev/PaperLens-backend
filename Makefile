GO ?= go
BINARY ?= bin/paperlens-api

.PHONY: fmt test vet build run migrate

fmt:
	$(GO)fmt -w $$(find . -name '*.go' -not -path './vendor/*')

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

build:
	mkdir -p $$(dirname $(BINARY))
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BINARY) ./cmd/api

run:
	$(GO) run ./cmd/api

migrate:
	@echo "Apply migrations/001_initial.sql with your PostgreSQL migration runner"
