.PHONY: build test lint coverage install clean

build:
	go build -o bin/go-analyzer .

test:
	go test ./... -timeout 120s

coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

lint:
	go vet ./...
	staticcheck ./...

install:
	go install .

clean:
	rm -rf bin/ .goanalyzer/ coverage.out
