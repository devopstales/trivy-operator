#!/bin/sh
cp /tmp/trivy docker
cp trivy-operator.py docker/trivy-operator.py
kim build --tag ${1}-devel docker/
#docker build -t $1 \
#  docker
rm -f docker/trivy-operator.py
rm -f docker/trivy
#docker push $1
