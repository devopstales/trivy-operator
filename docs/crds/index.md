# Overview

The trivy-operator uses CustomResourceDefinitions (CRDs). Theas are the fallowinf

| NAME                          | SHORTNAMES                                              | APIGROUP               | NAMESPACED |
|-------------------------------|---------------------------------------------------------|------------------------|------------|
| [NamespaceScanner](./namespace-scanner.md)             | ns-scan                     | trivy-operator.devopstales.io | true |
| [VulnerabilityReport](./vulnerability-report.md)            | vuln,vulns                  | trivy-operator.devopstales.io | true |     
| [PolicyReport](./policy-report.md)               | rpolr              | wgpolicyk8s.io | true |
