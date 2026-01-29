# 0cdn build and test
.PHONY: build test clean all fmt vet

all: build

build:
	go build -o server ./cmd/server
	go build -o agent ./cmd/agent
	go build -o client ./cmd/client

test:
	go test ./internal/... -count=1

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f server agent client
