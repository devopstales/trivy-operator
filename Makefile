export VERSION=2.2
export TVERSION=0.21.3

.PHONY:	all
all:	 latest version

.DEFAULT_GOAL := all

trivy:
	rm -f docker/trivy
	cp /tmp/trivy docker/trivy

devel:
	cp trivy-operator.py docker/trivy-operator.py
	kim build --tag devopstales/trivy-operator:$(VERSION)-devel docker/
	rm docker/trivy-operator.py
	rm -f docker/trivy-operator.py

devel-delete:
	kim image rm devopstales/trivy-operator:$(VERSION)-devel

version:
	cp trivy-operator.py docker/trivy-operator.py
	docker build -t devopstales/trivy-operator:$(VERSION) docker/
	docker build -t devopstales/trivy-operator:$(VERSION)-arm32v7 --build-arg ARCH=arm32v7/ docker/ -f docker/Dockerfile-arm
	docker build -t devopstales/trivy-operator:$(VERSION)-arm64v8 --build-arg ARCH=arm64v8/ docker/ -f docker/Dockerfile-arm
	rm -f docker/trivy-operator.py

push:
	docker push devopstales/trivy-operator:$(VERSION)
	docker push devopstales/trivy-operator:$(VERSION)-arm32v7
	docker push devopstales/trivy-operator:$(VERSION)-arm64v8
	docker manifest create devopstales/trivy-operator:latest \
		--amend devopstales/trivy-operator:$(VERSION) \
		--amend devopstales/trivy-operator:$(VERSION)-arm32v7 \
		--amend devopstales/trivy-operator:$(VERSION)-arm64v8
	docker manifest push devopstales/trivy-operator:latest







