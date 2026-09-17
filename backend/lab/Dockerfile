FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends strongswan libstrongswan-standard-plugins libstrongswan-extra-plugins iproute2 iputils-ping curl netcat-openbsd python3 python3-aiosmtpd python3-websockets ffmpeg tcpdump procps ca-certificates && rm -rf /var/lib/apt/lists/*
COPY docker/entrypoint.sh /usr/local/bin/ipsec-lab-entrypoint
COPY configs /lab/configs
COPY generators /lab/generators
RUN chmod +x /usr/local/bin/ipsec-lab-entrypoint
ENTRYPOINT ["/usr/local/bin/ipsec-lab-entrypoint"]
CMD ["sleep", "infinity"]
