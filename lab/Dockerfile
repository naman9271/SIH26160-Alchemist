FROM alpine:3.20.3

# Alpine's package index can occasionally fail to download; retry before
# treating a transient mirror outage as a missing StrongSwan dependency.
RUN for attempt in 1 2 3; do \
      apk add --no-cache strongswan iproute2 tcpdump && break; \
      if [ "$attempt" = 3 ]; then exit 1; fi; sleep "$attempt"; \
    done

ENTRYPOINT ["/usr/lib/strongswan/charon"]
