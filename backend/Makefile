.PHONY: proto fmt test vet build check

PROTO_FILES := $(shell find api/proto -name '*.proto' -type f | sort)
ML_PROTO := ml-service/proto/ml/v1/traffic_classifier.proto

proto:
	mkdir -p gen/go
	PATH="$(shell go env GOPATH)/bin:$$PATH" protoc -I . \
		--go_out=paths=source_relative:gen/go \
		--go-grpc_out=paths=source_relative:gen/go \
		$(PROTO_FILES)
	PATH="$(shell go env GOPATH)/bin:$$PATH" protoc -I ml-service/proto \
		--go_out=paths=source_relative:gen/go \
		--go-grpc_out=paths=source_relative:gen/go \
		$(ML_PROTO)

fmt:
	gofmt -w $$(find src gen -name '*.go' -type f)

test:
	go test ./...

vet:
	go vet ./...

build:
	go build ./...

check: proto fmt vet test build
