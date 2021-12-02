FROM python:3.8.12-slim-buster

ENV TRIVY_CACHE_DIR=/home/trivy-operator/trivy-cache \
    TRIVY_QUIET=true \
    IN_CLUSTER=true

RUN pip3 install --no-cache-dir kopf[dev] kubernetes asyncio pycron prometheus_client oscrypto certvalidator certbuilder validators

COPY trivy-operator.py /trivy-operator.py
COPY trivy /usr/local/bin

RUN addgroup --gid 10001 trivy-operator && \
    adduser --uid 10001 trivy-operator --ingroup trivy-operator && \
    mkdir /home/trivy-operator/trivy-cache && \
    chown -R trivy-operator:trivy-operator /home/trivy-operator/trivy-cache

USER 10001:10001

CMD kopf run -A /trivy-operator.py

VOLUME [ "/data/trivy", "/data/cache" ]
