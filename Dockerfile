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

# Ubuntu 26.04 ships libfuse3.so.4; Ubuntu 22.04 blobfuse2 .debs need libfuse3.so.3 and fail at runtime.
# amd64: use the Debian 13 build (2.5.4+) per azure-storage-fuse#2274#issuecomment-4921878400.
# arm64: no Debian 13 .deb yet — install libfuse3.so.3 from Debian until native Ubuntu 26.04 packages ship.
ARG BLOBFUSE2_VERSION=2.5.4
ARG LIBFUSE3_3_DEB_VERSION=3.14.0-4
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) \
            bf_url="https://packages.microsoft.com/debian/13/prod/pool/main/b/blobfuse2/blobfuse2_${BLOBFUSE2_VERSION}_amd64.deb"; \
            ;; \
        arm64) \
            wget -q "http://ftp.debian.org/debian/pool/main/f/fuse3/libfuse3-3_${LIBFUSE3_3_DEB_VERSION}_arm64.deb" -O /tmp/libfuse3-3.deb; \
            apt-get update; \
            apt-get install -y --no-install-recommends /tmp/libfuse3-3.deb fuse3; \
            rm -f /tmp/libfuse3-3.deb; \
            bf_url="https://github.com/Azure/azure-storage-fuse/releases/download/blobfuse2-${BLOBFUSE2_VERSION}/blobfuse2-${BLOBFUSE2_VERSION}-Ubuntu-22.04.arm64.deb"; \
            ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    wget -q "$bf_url" -O /tmp/blobfuse2.deb; \
    apt-get update; \
    apt-get install -y --no-install-recommends /tmp/blobfuse2.deb; \
    rm -f /tmp/blobfuse2.deb; \
    rm -rf /var/lib/apt/lists/*

ADD piwik_pro_log_analytics/import_logs.py /usr/local/bin
