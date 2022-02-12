SHELL=/bin/bash -o pipefail
export VERSION=2.3

.PHONY:	all
all:	 latest version

.DEFAULT_GOAL := all
TRIVY := $(shell curl --silent https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .name | cut -d "v" -f2)

trivy:
	@if [ ! -f /tmp/trivy ]; then \
		echo "Get Trivy Version:"; \
		echo $(TRIVY); \
		wget -q -O /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v$(TRIVY)/trivy_"$(TRIVY)"_Linux-64bit.tar.gz; \
		echo "Extract Trivy"; \
		tar -C /tmp -xf /tmp/trivy.tar.gz; \
	fi
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
	docker build -t devopstales/trivy-operator:$(VERSION)-arm32v7 --build-arg ARCH=arm32v7/ docker/ -f docker/Dockerfile
	docker build -t devopstales/trivy-operator:$(VERSION)-arm64v8 --build-arg ARCH=arm64v8/ docker/ -f docker/Dockerfile
	rm -f docker/trivy-operator.py

push-version:
	docker push devopstales/trivy-operator:$(VERSION)
	docker push devopstales/trivy-operator:$(VERSION)-arm32v7
	docker push devopstales/trivy-operator:$(VERSION)-arm64v8

push-latest:
	docker manifest create devopstales/trivy-operator:latest \
		--amend devopstales/trivy-operator:$(VERSION) \
		--amend devopstales/trivy-operator:$(VERSION)-arm32v7 \
		--amend devopstales/trivy-operator:$(VERSION)-arm64v8
	docker manifest push devopstales/trivy-operator:latest
