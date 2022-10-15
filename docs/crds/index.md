# Overview

The trivy-operator uses CustomResourceDefinitions (CRDs). These are the fallowing

| NAME                          | SHORTNAMES                                              | APIGROUP               | NAMESPACED |
|-------------------------------|---------------------------------------------------------|------------------------|------------|
| [NamespaceScanner](./namespace-scanner.md)             | ns-scan                     | trivy-operator.devopstales.io | true |
| [ClusterScanner](./cluster-scanner.md) | cs-scan | trivy-operator.devopstales.io | false |
| [VulnerabilityReport](./vulnerability-report.md)            | vuln,vulns                  | trivy-operator.devopstales.io | true |     
| [ClusterVulnerabilityReport](./cluster-policy-report.md) | cpolr | wgpolicyk8s.io | false |
| [PolicyReport](./policy-report.md)               | rpolr              | wgpolicyk8s.io | true |
