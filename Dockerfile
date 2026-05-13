FROM ubuntu:focal

RUN apt-get update \
 && apt-get install -y software-properties-common \
 && add-apt-repository -y ppa:deadsnakes/ppa \
 && apt-get update \
 && apt-get install -y python3.10 wget fuse libcurl3-gnutls vim sleepenh \
 && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/bin/python3.10 /usr/bin/python \
  && mkdir /tmp/blobfuse /tmp/blobfusetmp

RUN wget https://github.com/Azure/azure-storage-fuse/releases/download/blobfuse-1.4.1/blobfuse-1.4.1-ubuntu-20.04-x86_64.deb \
  && dpkg -i blobfuse-1.4.1-ubuntu-20.04-x86_64.deb

ADD piwik_pro_log_analytics/import_logs.py /usr/local/bin
