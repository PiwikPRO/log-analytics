FROM ubuntu:focal

RUN apt-get update \
 && apt-get install -y python3.8 wget fuse libcurl3-gnutls vim sleepenh

RUN ln -s /usr/bin/python3.8 /usr/bin/python \
  && mkdir /tmp/blobfuse /tmp/blobfusetmp

RUN wget https://github.com/Azure/azure-storage-fuse/releases/download/blobfuse-1.4.1/blobfuse-1.4.1-ubuntu-20.04-x86_64.deb \
  && dpkg -i blobfuse-1.4.1-ubuntu-20.04-x86_64.deb

ADD piwik_pro_log_analytics/import_logs.py /usr/local/bin
