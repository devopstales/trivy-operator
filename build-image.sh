#!/bin/bash
if [ ! -f /tmp/trivy ]; then
  echo "Get Trivy Version"
  VERSION=$(curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' | cut -d v -f 2)
  echo "wget Trivy"
  wget -q -O /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v$VERSION/trivy_"$VERSION"_Linux-64bit.tar.gz
  echo "Extract Trivy"
  tar -C /tmp -xf /tmp/trivy.tar.gz
fi
cp /tmp/trivy docker
cp trivy-operator.py docker/trivy-operator.py
#kim build --tag ${1}-devel docker
docker build -t ${1} docker
rm -f docker/trivy-operator.py
rm -f docker/trivy
docker push $1
