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

# blobfuse2 ships Ubuntu 22.04 .debs today; switch to 26.04 when Azure publishes them
# (https://github.com/Azure/azure-storage-fuse/issues/2274#issuecomment-4921878400).
# Ubuntu 22.04 .deb until blobfuse2 ships a 26.04 build (azure-storage-fuse#2274).
ARG BLOBFUSE2_VERSION=2.5.3
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) bf_arch=x86_64 ;; \
        arm64) bf_arch=arm64 ;; \
        *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    wget -q "https://github.com/Azure/azure-storage-fuse/releases/download/blobfuse2-${BLOBFUSE2_VERSION}/blobfuse2-${BLOBFUSE2_VERSION}-Ubuntu-22.04.${bf_arch}.deb" -O /tmp/blobfuse2.deb; \
    apt-get update; \
    apt-get install -y --no-install-recommends /tmp/blobfuse2.deb; \
    rm -f /tmp/blobfuse2.deb; \
    rm -rf /var/lib/apt/lists/*

ADD piwik_pro_log_analytics/import_logs.py /usr/local/bin
