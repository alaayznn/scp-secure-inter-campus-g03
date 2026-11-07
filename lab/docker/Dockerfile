FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# Build online later; runtime networks remain isolated. Do not start package daemons.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates git curl wget openssl nginx \
       iproute2 iptables iputils-ping procps tcpdump tshark nmap \
       strongswan-charon strongswan-swanctl strongswan-pki \
       libcharon-extra-plugins libstrongswan-extra-plugins \
       python3 python3-cryptography python3-pytest \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v3.2.1 https://github.com/testssl/testssl.sh.git /opt/testssl \
    && git -C /opt/testssl rev-parse HEAD > /opt/testssl-source-commit.txt \
    && rm -rf /opt/testssl/.git \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh \
    && python3 -c "import sys,cryptography; assert sys.version_info[:2] == (3,12)" \
    && openssl version | grep -E '^OpenSSL 3\.' \
    && swanctl --version \
    && dpkg-query -W > /opt/scp-image-packages.txt
WORKDIR /work
ENTRYPOINT ["bash", "/opt/scp/roles/baseline-entrypoint.sh"]
