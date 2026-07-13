FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    python3 \
    python3-minimal \
    wget \
    ca-certificates \
    vim \
    sleepenh \
 && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3 /usr/bin/python \
  && mkdir /tmp/blobfuse /tmp/blobfusetmp

# Ubuntu 26.04 ships libfuse3.so.4; use the Debian 13 amd64 build (2.5.4+) per
# azure-storage-fuse#2274#issuecomment-4921878400. Image is amd64-only.
ARG BLOBFUSE2_VERSION=2.5.4
RUN set -eux; \
    test "$(dpkg --print-architecture)" = amd64; \
    wget -q "https://packages.microsoft.com/debian/13/prod/pool/main/b/blobfuse2/blobfuse2_${BLOBFUSE2_VERSION}_amd64.deb" -O /tmp/blobfuse2.deb; \
    apt-get update; \
    apt-get install -y --no-install-recommends /tmp/blobfuse2.deb; \
    rm -f /tmp/blobfuse2.deb; \
    rm -rf /var/lib/apt/lists/*

ADD piwik_pro_log_analytics/import_logs.py /usr/local/bin
