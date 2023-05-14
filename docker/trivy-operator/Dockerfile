ARG ARCH
FROM ${ARCH}python:3.8-alpine
ARG ARCH
ENV TRIVY_CACHE_DIR=/home/trivy-operator/trivy-cache \
    TRIVY_QUIET=true \
    IN_CLUSTER=true

# https://github.com/opencontainers/image-spec/blob/main/annotations.md#back-compatibility-with-label-schema
LABEL org.opencontainers.image.vendor="devopstales" \
      org.opencontainers.image.authors="devopstales" \
      org.opencontainers.imeg.url="https://devopstales.github.io" \
      org.opencontainers.image.licenses="Apache 2.0" \
      org.opencontainers.image.title="trivy-operator" \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.description="Operator to schedule trivy scan for namespaces" \
      org.opencontainers.image.source="https://github.com/devopstales/trivy-operator" \
      org.opencontainers.image.documentation="https://devopstales.github.io/trivy-operator" \
      org.opencontainers.image.created=${BUILD_DATE}

WORKDIR /code

COPY entrypoint.sh /entrypoint.sh

RUN apk -U upgrade && \
    apk add --no-cache gcc musl-dev libffi-dev openssl-dev curl bash rust cargo

RUN pip3 install --no-cache-dir kopf[dev] kubernetes croniter prometheus_client oscrypto certvalidator certbuilder validators pyOpenSSL

COPY ./trivy-operator /code/trivy-operator
COPY ${ARCH}trivy /usr/local/bin/

RUN addgroup -S -g 10001 trivy-operator && \
    adduser -S -u 10001 trivy-operator -G trivy-operator && \
    mkdir /home/trivy-operator/trivy-cache && \
    chown -R trivy-operator:trivy-operator /home/trivy-operator/trivy-cache && \
    chown -R trivy-operator:trivy-operator /code/trivy-operator

WORKDIR /code/kubedash

USER 10001:10001

EXPOSE 443 8000
ENTRYPOINT ["/entrypoint.sh"]

VOLUME [ "/data/trivy", "/data/cache" ]
