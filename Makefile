codeSHELL=/bin/bash -o pipefail
export VERSION=2.4

.PHONY:	all
all:	 trivy

.DEFAULT_GOAL := help

TRIVY := $(shell curl --silent https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .name | cut -d "v" -f2)

#help:	@ List available tasks on this project
help:
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#'  | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#trivy:	@ download trivy binary
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

#devel:	@ Build local devel image with kim
devel:
	cp trivy-operator.py docker/trivy-operator.py
	kim build --tag devopstales/trivy-operator:$(VERSION)-devel docker/
	rm docker/trivy-operator.py
	rm -f docker/trivy-operator.py

#devel-delete:	@ Delete local dev image with kim
devel-delete:
	kim image ls | grep devopstales | grep trivy-operator | grep $(VERSION)-devel | awk '{print "kim rmi "$$3}' | bash

version:
	cp trivy-operator.py docker/trivy-operator.py
	docker build -t devopstales/trivy-operator:$(VERSION)-amd64 --build-arg ARCH=amd64/ docker/
	docker build -t devopstales/trivy-operator:$(VERSION)-arm64v8 --build-arg ARCH=arm64v8/ docker/
	rm -f docker/trivy-operator.py
#	docker build -t devopstales/trivy-operator:$(VERSION)-arm32v7 --build-arg ARCH=arm32v7/ docker/


push-version:
	docker push devopstales/trivy-operator:$(VERSION)-amd64
	docker push devopstales/trivy-operator:$(VERSION)-arm64v8
	docker manifest create devopstales/trivy-operator:$(VERSION) \
		--amend devopstales/trivy-operator:$(VERSION)-amd64 \
		--amend devopstales/trivy-operator:$(VERSION)-arm64v8
	docker manifest push devopstales/trivy-operator:$(VERSION)

#	docker push devopstales/trivy-operator:$(VERSION)-arm32v7

push-latest:
	docker manifest create devopstales/trivy-operator:latest \
		--amend devopstales/trivy-operator:$(VERSION)-amd64 \
		--amend devopstales/trivy-operator:$(VERSION)-arm64v8
	docker manifest push devopstales/trivy-operator:latest

# 		--amend devopstales/trivy-operator:$(VERSION)-arm32v7 \
