export VERSION="3.0"
export $(shell sed 's/=.*//' $(cnf))

.PHONY:	all
all:	 latest version

.DEFAULT_GOAL := all

devel:
    cp trivy-operator.py docker/trivy-operator.py
	kim build --tag devopstales/trivy-operator:$(VERSION)-devel docker/

latest:
	cp trivy-operator.py docker/trivy-operator.py
	docker build -t devopstales/trivy-operator:latest docker/

version:
	cp trivy-operator.py docker/trivy-operator.py
	docker build -t devopstales/trivy-operator:$(VERSION) docker/

push:
	docker push devopstales/trivy-operator:latest
	docker push devopstales/trivy-operator:$(VERSION)

