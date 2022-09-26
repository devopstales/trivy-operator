# Kubernetes CIS Benchmark

## What is Kubernetes CIS Benchmark?

The Kubernetes CIS Benchmark is published by the Center for Internet Security (CIS), a not-for-profit organization that publishes cybersecurity best practices. 

CIS Benchmark best practices are an important first step to securing Kubernetes in production by hardening Kubernetes environments. Several open source and commercial tools are available that automatically check Kubernetes clusters to see they are in line with the controls outlined in the benchmark, and flag any non-compliant configurations.

Trivy-operator use kube-bench to scan the kubernetes cluster and create CIS Benchmark reports. 

## Example Deploy:

To enable the CIS Benchmark scanning function you need to create a [ClusterScanner]/trivy-operator/crds/cluster-scanner/