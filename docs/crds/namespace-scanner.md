# NamespaceScanner

The NamespaceScanner object is the main configuration object for the trivy-operator's vulnerabiliti scanns. 

The following examle object is confihured to:

* run the vulnerability scan every hour (`crontab: '00 * * * *'`)
* test only the namespaces wit the the `trivy-scan: "true"`
* use the users fo authentication to pulling image

```yaml
apiVersion: trivy-operator.devopstales.io/v1
kind: NamespaceScanner
metadata:
  name: main-config
  namespace: trivy-operator
spec:
  crontab: '00 * * * *'
  namespace_selector: trivy-scan
  registry:
  - name: docker.io
    user: "user"
    password: "password"
```

The followin list show the NamespaceScanner objects listid by the kbectl cli:

```bash
kubectl get ns-scan
NAMESPACE        NAME          NAMESPACESELECTOR   CRONTAB       MESSAGE
trivy-operator   main-config   trivy-scan          00 * * * *
```