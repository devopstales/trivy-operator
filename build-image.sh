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
#############################################################
# Docker build
#############################################################
#kim build --tag ${1}-devel docker
docker build -t ${1} docker
#docker build -t ${1}-arm32v7 --build-arg ARCH=arm32v7/ docker
#docker build -t ${1}-arm64v8 --build-arg ARCH=arm64v8/ docker
#############################################################
# Docker push
#############################################################
#docker push $1
#docker push ${1}-arm32v7
#docker push ${1}-arm64v8
#docker manifest create \
#devopstales/trivy-operator:latest \
#--amend ${1} \
#--amend ${1}-arm32v7 \
#--amend ${1}-arm64v8
#docker manifest push devopstales/trivy-operator:latest
#############################################################
# Docker Cleanup
#############################################################
#rm -f docker/trivy-operator.py
#rm -f docker/trivy
