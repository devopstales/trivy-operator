ARG ARCH
FROM ${ARCH}python:3.8-alpine
ARG ARCH
ENV IN_CLUSTER=true

COPY entrypoint.sh /entrypoint.sh

# gcompat
RUN apk add --no-cache procps apk-tools openssl bash  && \
    apk upgrade

RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.33-r0/glibc-2.33-r0.apk && \
    apk add --force-overwrite glibc-2.33-r0.apk && \
    mkdir /etc/kube-bench

RUN pip3 install --no-cache-dir kopf kubernetes asyncio pycron prometheus_client

COPY kube-bench-scnner.py /kube-bench-scnner.py
ADD ${ARCH}cfg /etc/kube-bench/cfg
COPY ${ARCH}kube-bench /usr/local/bin/

ENV PATH=$PATH:/usr/local/mount-from-host/bin

ENTRYPOINT ["/entrypoint.sh"]
