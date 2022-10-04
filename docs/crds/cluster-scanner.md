# ClusterScanner

The ClusterScanner Custom Resource is the main configuration object for the trivy-operator's Kubernetes CIS scans. 

The following example object is configured to:

* run the vulnerability scan every hour (`crontab: '00 * * * *'`)
* use the `cis-1.23` scan profile
* enable integration to defectdojo

```yaml
apiVersion: trivy-operator.devopstales.io/v1
kind: ClusterScanner
metadata:
  name: main-config
spec:
  crontab: "00 * * * *"
  scanProfileName: "cis-1.23"
  integrations:
    defectdojo:
      host: "http://defectdojo.rancher-desktop.intra"
      api_key: "3880d84590915e5c96cec075444f22285ff3659c"
      k8s-cluster-name: "eks-prod"
```

The following list show the ClusterScanner objects listed by the kubectl cli:

```bash
kubectl get cs-scan
NAME          CLUSTERSCANPROFILE   CRONTAB
main-config   cis-1.23             00 * * * *
```