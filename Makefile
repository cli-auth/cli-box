.PHONY: proto build build-server ui-dist test clean fmt clients
.SILENT:

GO_BUILD := CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"

UI_REPO ?= ../cli-box-ui
ADMIN_UI_DIST := internal/adminui/dist

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/clibox.proto

fmt:
	go fmt ./...

build: fmt
	$(GO_BUILD) -o bin/cli-box ./cmd/cli-box
	$(GO_BUILD) -o bin/cli-box-server ./cmd/cli-box-server

ui-dist:
	bash scripts/build-server-with-ui.sh "$(UI_REPO)" "$(ADMIN_UI_DIST)"

test:
	go test ./...

clean:
	rm -rf bin/

clients:
	GOOS=linux   GOARCH=amd64   $(GO_BUILD) -o bin/clients/cli-box-linux-amd64   ./cmd/cli-box
	GOOS=linux   GOARCH=arm64   $(GO_BUILD) -o bin/clients/cli-box-linux-arm64   ./cmd/cli-box
	GOOS=darwin  GOARCH=amd64   $(GO_BUILD) -o bin/clients/cli-box-darwin-amd64  ./cmd/cli-box
	GOOS=darwin  GOARCH=arm64   $(GO_BUILD) -o bin/clients/cli-box-darwin-arm64  ./cmd/cli-box
	GOOS=windows GOARCH=amd64   $(GO_BUILD) -o bin/clients/cli-box-windows-amd64.exe ./cmd/cli-box

dev-up:
	@sudo docker compose -f docker/compose.yaml up -d --build --remove-orphans

dev-logs:
	@sudo docker compose -f docker/compose.yaml logs -f -n 100 || true
