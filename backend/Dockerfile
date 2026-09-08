FROM golang:1.22-alpine AS build

WORKDIR /workspace/backend
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY gen ./gen
COPY src ./src
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ipsec-core ./src/cmd/server

FROM alpine:3.20

RUN addgroup -S -g 10001 app && adduser -S -D -H -u 10001 -G app app \
    && apk add --no-cache ca-certificates tcpdump \
    && mkdir -p /var/lib/alchemist/reports \
    && chown -R app:app /var/lib/alchemist
COPY --from=build /out/ipsec-core /usr/local/bin/ipsec-core

USER app
EXPOSE 8080 50052

VOLUME ["/var/lib/alchemist/reports"]

ENTRYPOINT ["/usr/local/bin/ipsec-core"]
