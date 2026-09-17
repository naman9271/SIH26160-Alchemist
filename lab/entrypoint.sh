#!/bin/sh
set -eu
if [ "$ROLE" = gateway ]; then
  # Private lab PSKs are generated per setup and never included in artifacts.
  exec /usr/lib/ipsec/charon
fi
if [ "$ROLE" = client ]; then
  ip route replace 172.30.162.0/24 via 172.30.161.2
  ip -6 route replace fd26:160:2::/64 via fd26:160:1::2
else
  ip route replace 172.30.161.0/24 via 172.30.162.2
  ip -6 route replace fd26:160:1::/64 via fd26:160:2::2
fi
exec sleep infinity
