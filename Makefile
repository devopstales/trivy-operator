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

devel-delete:
	kim image rm devopstales/trivy-operator:$(VERSION)-devel

latest:
	cp trivy-operator.py docker/trivy-operator.py
	docker build -t devopstales/trivy-operator:latest docker/

version:
	cp trivy-operator.py docker/trivy-operator.py
	docker build -t devopstales/trivy-operator:$(VERSION) docker/

push:
	docker push devopstales/trivy-operator:latest
	docker push devopstales/trivy-operator:$(VERSION)

