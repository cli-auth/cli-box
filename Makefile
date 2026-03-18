.PHONY: proto build test clean fmt

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/clibox.proto

fmt:
	go fmt ./...

build: fmt
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/cli-box ./cmd/cli-box
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/cli-box-server ./cmd/cli-box-server

test:
	go test ./...

clean:
	rm -rf bin/

dev-up:
	@docker compose -f docker/compose.yaml up -d --build --remove-orphans

dev-logs:
	@docker compose -f docker/compose.yaml logs -f -n 100 || true
