# Confidant — build/run for the two standalone binaries.
# Each lives in its own Go module (proxy/, agent/) and builds independently.
# e2e/ is a test-only module that drives both binaries end to end.

BIN := bin

.PHONY: all build build-proxy build-agent run-proxy run-agent \
        test test-proxy test-agent test-e2e cover tidy fmt vet clean

all: build

build: build-proxy build-agent

build-proxy:
	mkdir -p $(BIN)
	cd proxy && go build -o ../$(BIN)/confidant-proxy .

build-agent:
	mkdir -p $(BIN)
	cd agent && go build -o ../$(BIN)/confidant-agent .

# The proxy needs a store + dev KEK to serve. Create one first, e.g.:
#   printf 'sk-live-...' | ./bin/confidant-proxy enroll \
#       -id openai/personal -kek dev.kek -store store.json -host api.openai.com
run-proxy: build-proxy
	SECRET_STORE=store.json DEV_KEK=dev.kek AUDIT_SINK=audit.log \
		./$(BIN)/confidant-proxy serve -listen :8443 -log-level info

run-agent: build-agent
	CONFIDANT_INTERCEPT="api.openai.com,*.amazonaws.com,api.github.com" \
		./$(BIN)/confidant-agent -listen 127.0.0.1:8317 -log-level info

test: test-proxy test-agent test-e2e

test-proxy:
	cd proxy && go test ./...

test-agent:
	cd agent && go test ./...

# Builds both binaries and runs the full end-to-end flow.
test-e2e:
	cd e2e && go test ./...

cover:
	cd proxy && go test ./... -cover
	cd agent && go test ./... -cover

tidy:
	cd proxy && go mod tidy
	cd agent && go mod tidy
	cd e2e && go mod tidy

fmt:
	cd proxy && go fmt ./...
	cd agent && go fmt ./...
	cd e2e && go fmt ./...

vet:
	cd proxy && go vet ./...
	cd agent && go vet ./...
	cd e2e && go vet ./...

clean:
	rm -rf $(BIN)
