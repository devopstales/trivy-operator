ARG ARCH
FROM ${ARCH}python:3.8-alpine
ARG ARCH
ENV TRIVY_CACHE_DIR=/home/trivy-operator/trivy-cache \
    TRIVY_QUIET=true \
    IN_CLUSTER=true

COPY entrypoint.sh /entrypoint.sh

RUN apk -U upgrade && \
    apk add --no-cache gcc musl-dev libffi-dev openssl-dev curl bash rust cargo procps apk-tools

RUN wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.33-r0/glibc-2.33-r0.apk && \
    apk add glibc-2.33-r0.apk && \
    mkdir /etc/kube-bench

RUN pip3 install --no-cache-dir kopf[dev] kubernetes asyncio pycron prometheus_client oscrypto certvalidator certbuilder validators pyOpenSSL

COPY trivy-operator.py /trivy-operator.py
COPY ${ARCH}trivy /usr/local/bin/
ADD ${ARCH}cfg /etc/kube-bench/cfg
COPY ${ARCH}kube-bench /usr/local/bin/

RUN addgroup -S -g 10001 trivy-operator && \
    adduser -S -u 10001 trivy-operator -G trivy-operator && \
    mkdir /home/trivy-operator/trivy-cache && \
    chown -R trivy-operator:trivy-operator /home/trivy-operator/trivy-cache

USER 10001:10001

ENTRYPOINT ["/entrypoint.sh"]

VOLUME [ "/data/trivy", "/data/cache" ]
