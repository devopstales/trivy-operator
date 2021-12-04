FROM python:3.8.12-slim-buster

ENV TRIVY_CACHE_DIR=/home/trivy-operator/trivy-cache \
    TRIVY_QUIET=true \
    IN_CLUSTER=true

RUN apt-get -qq update \
	&& DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends curl \
	&& rm -rf /var/lib/apt/lists/*

# Download and install trivy
RUN export TRIVY_VERSION=$(curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' | cut -d v -f 2) && \
    curl -sL -o /tmp/trivy.deb \
    https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb && \
    dpkg -i /tmp/trivy.deb && \
    rm /tmp/trivy.deb

RUN pip3 install --no-cache-dir kopf[dev] kubernetes asyncio pycron prometheus_client oscrypto certvalidator certbuilder validators

COPY trivy-operator.py /trivy-operator.py

RUN addgroup --gid 10001 trivy-operator && \
    adduser --uid 10001 trivy-operator --ingroup trivy-operator && \
    mkdir /home/trivy-operator/trivy-cache && \
    chown -R trivy-operator:trivy-operator /home/trivy-operator/trivy-cache

USER 10001:10001

CMD kopf run -A /trivy-operator.py

VOLUME [ "/data/trivy", "/data/cache" ]
