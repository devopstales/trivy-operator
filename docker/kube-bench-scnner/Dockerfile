ARG ARCH
FROM ${ARCH}python:3.8-alpine
ARG ARCH
ENV IN_CLUSTER=true

# https://github.com/opencontainers/image-spec/blob/main/annotations.md#back-compatibility-with-label-schema
LABEL org.opencontainers.image.vendor="devopstales" \
      org.opencontainers.image.authors="devopstales" \
      org.opencontainers.imeg.url="https://devopstales.github.io" \
      org.opencontainers.image.licenses="Apache 2.0" \
      org.opencontainers.image.title="kube-bench-scanner" \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.description="Container to scan hosts with kube-bench" \
      org.opencontainers.image.source="https://github.com/devopstales/trivy-operator" \
      org.opencontainers.image.documentation="https://devopstales.github.io/trivy-operator" \
      org.opencontainers.image.created=${BUILD_DATE}

WORKDIR /code
COPY entrypoint.sh /entrypoint.sh

# gcompat
RUN apk add --no-cache procps apk-tools openssl bash  && \
    apk upgrade

RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.33-r0/glibc-2.33-r0.apk && \
    apk add --force-overwrite glibc-2.33-r0.apk && \
    mkdir /etc/kube-bench

RUN pip3 install --no-cache-dir kopf kubernetes croniter prometheus_client

COPY ./kube-bench-scnner /code/kube-bench-scnner
ADD cfg /etc/kube-bench/cfg
COPY ${ARCH}kube-bench /usr/local/bin/

ENV PATH=$PATH:/usr/local/mount-from-host/bin

ENTRYPOINT ["/entrypoint.sh"]
