FROM debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef
# A dated Debian snapshot makes package resolution repeatable. The build records
# exact installed versions in /opt/lab/versions.txt for every run manifest.
RUN printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20250601T000000Z bookworm main\n' > /etc/apt/sources.list \
 && rm /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends strongswan-charon strongswan-swanctl libcharon-extra-plugins libstrongswan-standard-plugins python3 iproute2 iptables tcpdump iputils-ping ca-certificates procps \
 && mkdir -p /opt/lab \
 && dpkg-query -W > /opt/lab/versions.txt \
 && rm -rf /var/lib/apt/lists/*
COPY traffic.py snapshot.py vici_read.py entrypoint.sh /opt/lab/
ENTRYPOINT ["/bin/sh", "/opt/lab/entrypoint.sh"]
