FROM golang:1.22-alpine AS build

WORKDIR /workspace/backend
COPY go.mod go.sum ./
RUN go mod download
COPY api ./api
COPY gen ./gen
COPY src ./src
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ipsec-core ./src/cmd/server

FROM alpine:3.20

# Alpine reports packages as unavailable when a mirror index fetch has failed.
# Retry the network operation so a transient CDN/DNS error is not misleading.
RUN addgroup -S -g 10001 app && adduser -S -D -H -u 10001 -G app app \
    && for attempt in 1 2 3; do \
        apk add --no-cache ca-certificates tcpdump && break; \
        if [ "$attempt" = 3 ]; then exit 1; fi; \
        sleep "$attempt"; \
    done \
    && mkdir -p /var/lib/alchemist/reports \
    && chown -R app:app /var/lib/alchemist
COPY --from=build /out/ipsec-core /usr/local/bin/ipsec-core

USER app
EXPOSE 8080 50052

VOLUME ["/var/lib/alchemist/reports"]

ENTRYPOINT ["/usr/local/bin/ipsec-core"]
