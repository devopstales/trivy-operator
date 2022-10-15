codeSHELL=/bin/bash -o pipefail
export VERSION=2.5

.PHONY:	all
all:	 trivy

.DEFAULT_GOAL := help

TRIVY := $(shell curl --silent https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .name | cut -d "v" -f2)
BENCH := $(shell curl --silent https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | jq -r .name | cut -d "v" -f2)


#help:	@ List available tasks on this project
help:
	@grep -E '[a-zA-Z\.\-]+:.*?@ .*$$' $(MAKEFILE_LIST)| tr -d '#'  | awk 'BEGIN {FS = ":.*?@ "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#bins:	@ download binaris
bins:
	@if [ ! -f /tmp/trivy ]; then \
		echo "Get Trivy Version:"; \
		echo $(TRIVY); \
		wget -q -O /tmp/trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v$(TRIVY)/trivy_"$(TRIVY)"_Linux-64bit.tar.gz; \
		echo "Extract Trivy"; \
		tar -C /tmp -xf /tmp/trivy.tar.gz; \
	fi
	@if [ ! -f /tmp/kube-bench ]; then \
		echo "Get kube-bench Version"; \
		echo $(BENCH); \
		wget -q -O /tmp/kube-bench.tar.gz https://github.com/aquasecurity/kube-bench/releases/download/v$(BENCH)/kube-bench_"$(BENCH)"_linux_amd64.tar.gz; \
		tar -C /tmp -xf /tmp/kube-bench.tar.gz; \
	fi
	rm -f docker/trivy-operator/trivy docker/kube-bench-scnner/kube-bench
	cp /tmp/trivy docker/trivy-operator/trivy
	cp /tmp/kube-bench docker/kube-bench-scnner/kube-bench

#to-devel:	@ Build local trivy-operator devel image with nerdctl
to-devel:
	cp trivy-operator.py docker/trivy-operator/trivy-operator.py
	nerdctl --namespace k8s.io build --tag devopstales/trivy-operator:$(VERSION)-devel docker/trivy-operator
	rm -f docker/trivy-operator/trivy-operator.py

#to-devel-delete:	@ Delete local trivy-operator dev image with nerdctl
to-devel-delete:
	#nerdctl --namespace k8s.io image ls | grep devopstales | grep trivy-operator | grep $(VERSION)-devel | awk '{print "nerdctl --namespace k8s.io rmi "$$3}' | bash
	nerdctl --namespace k8s.io rmi devopstales/trivy-operator:$(VERSION)-devel

#kbs-devel:	@ Build local kube-bench-scnner devel image with nerdctl
kbs-devel:
	cp kube-bench-scnner.py docker/kube-bench-scnner/kube-bench-scnner.py
	nerdctl --namespace k8s.io build --tag devopstales/kube-bench-scnner:$(VERSION)-devel docker/kube-bench-scnner
	rm -f docker/kube-bench-scnner/kube-bench-scnner.py

#kbs-devel-delete:	@ Delete local kube-bench-scnner dev image with nerdctl
kbs-devel-delete:
	#nerdctl --namespace k8s.io image ls | grep devopstales | grep kube-bench-scnner | grep $(VERSION)-devel | awk '{print "nerdctl --namespace k8s.io rmi "$$3}' | bash
	nerdctl --namespace k8s.io rmi devopstales/kube-bench-scnner:$(VERSION)-devel

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
