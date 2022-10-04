# NamespaceScanner

The NamespaceScanner Custom Resource is the main configuration object for the trivy-operator's vulnerability scans. 

The following example object is configured to:

* run the vulnerability scan every hour (`crontab: '00 * * * *'`)
* test only the namespaces wit the the `trivy-scan: "true"`
* enable integration to defectdojo
* use the `users` fo authentication to pulling image
* use the `devopstales-dockerhub` secret to pulling image

```yaml
apiVersion: trivy-operator.devopstales.io/v1
kind: NamespaceScanner
metadata:
  name: main-config
  namespace: trivy-operator
spec:
  crontab: '00 * * * *'
  namespace_selector: trivy-scan
  clusterWide: "false"
  integrations:
    policyreport: True
    defectdojo:
      host: "https://defectdojo.rancher-desktop.intra"
      api_key: "xyz456ucdssd67sd67dsg"
  image_pull_secrets:
  - devopstales-dockerhub
  registry:
  - name: registry.rancher-desktop.intra
    user: "user"
    password: "password"
    insecure: true
```

The following list show the NamespaceScanner objects listed by the kubectl cli:

```bash
kubectl get ns-scan
NAMESPACE        NAME          NAMESPACESELECTOR   CRONTAB       MESSAGE
trivy-operator   main-config   trivy-scan          00 * * * *
```