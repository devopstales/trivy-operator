### Trivy Operator

![Version: 2.5.0](https://img.shields.io/badge/Version-2.5.0-informational?style=for-the-badge)
![Type: application](https://img.shields.io/badge/Type-application-informational?style=for-the-badge)
![AppVersion: 1.16.0](https://img.shields.io/badge/AppVersion-1.16.0-informational?style=for-the-badge)

## Description

This chart deploys an operator that default every 5 minutes execute a scan script. It will get image list from all namespaces with the label `trivy-scan=true`, and then scan this images with trivy, finally we will get metrics on `http://[pod-ip]:9115/metrics`

## Configuration

The following tables lists configurable parameters of the trivy-operator chart and their default values.

<fill out>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| TimeZone | string | `"UTC"` | Time Zone in container |
| admissionController.enabled | bool | `false` | enable adission controller |
| affinity | object | `{}` | Set the affinity for the pod. |
| cache.enabled | bool | `false` | enable redis cache |
| clusterScanner.crontab | string | `"*/1 * * * *"` | crontab for scheduled scan |
| clusterScanner.enabled | bool | `false` | enable clusterScanner cr creation |
| clusterScanner.integrations | object | `{}` | configure defectdojo integration |
| clusterScanner.scanProfileName | string | `"cis-1.23"` | kube-hunter scan profile |
| githubToken.enabled | bool | `false` | enable github authentiation token |
| githubToken.token | string | `""` | github authentiation token value |
| grafana.dashboards.enabled | bool | `true` | Enable the deployment of grafana dashboards |
| grafana.dashboards.label | string | `"grafana_dashboard"` | Label to find dashboards using the k8s sidecar |
| grafana.dashboards.value | string | `"1"` | Label value to find dashboards using the k8s sidecar |
| grafana.folder.annotation | string | `"grafana_folder"` | Annotation to enable folder storage using the k8s sidecar |
| grafana.folder.name | string | `"Policy Reporter"` | Grafana folder in which to store the dashboards |
| grafana.namespace | string | `nil` | namespace for configMap of grafana dashboards |
| image.pullPolicy | string | `"Always"` | The docker image pull policy |
| image.repository | string | `"devopstales/trivy-operator"` | The docker image repository to use |
| image.tag | string | `"2.5.0"` | The docker image tag to use |
| imagePullSecrets | list | `[]` | list of secrets to use for imae pull |
| kube_bench_scnner.image.pullPolicy | string | `"Always"` | The docker image pull policy |
| kube_bench_scnner.image.repository | string | `"devopstales/kube-bench-scnner"` | The docker image repository to use |
| kube_bench_scnner.image.tag | string | `"2.5"` | The docker image tag to use |
| log_level | string | `"INFO"` | Log level |
| monitoring.port | string | `"9115"` | configure prometheus monitoring port |
| namespaceScanner.clusterWide | bool | `false` |  |
| namespaceScanner.crontab | string | `"*/5 * * * *"` |  |
| namespaceScanner.integrations.policyreport | bool | `false` |  |
| namespaceScanner.namespaceSelector | string | `"trivy-scan"` |  |
| nodeSelector | object | `{}` | Set the node selector for the pod. |
| offline.db_repository | string | `"localhost:5000/trivy-db"` | repository to use for download trivy vuln db |
| offline.db_repository_insecure | bool | `false` | insecure repository |
| offline.enabled | bool | `false` | enable air-gapped mode |
| persistence.accessMode | string | `"ReadWriteOnce"` | Volumes mode |
| persistence.annotations | object | `{}` | Volumes annotations |
| persistence.enabled | bool | `true` | Volumes for the pod |
| persistence.size | string | `"1Gi"` | Volumes size |
| podSecurityContext | object | `{"fsGroup":10001,"fsGroupChangePolicy":"OnRootMismatch"}` | security options for the pod |
| registryAuth.enabled | bool | `false` | enable registry authentication |
| registryAuth.image_pull_secrets | list | `["regcred"]` | list of image pull secrets for authentication |
| serviceAccount.annotations | object | `{}` | serviceAccount annotations |
| serviceAccount.create | bool | `true` | Enable serviceAccount creation |
| serviceAccount.name | string | `"trivy-operator"` | Name of the serviceAccount |
| serviceMonitor.enabled | bool | `false` | allow to override the namespace for serviceMonitor |
| serviceMonitor.labels.release | string | `"prometheus"` | labels to match the serviceMonitorSelector of the Prometheus Resource |
| serviceMonitor.metricRelabelings | list | `[]` | metricRelabeling config for serviceMonitor |
| serviceMonitor.namespace | object | `{}` | Name of the namespace for serviceMonitor |
| serviceMonitor.relabelings | list | `[]` | relabel config for serviceMonitor |
| tolerations | list | `[]` | Set the tolerations for the pod. |

**Homepage:** <https://github.com/devopstales/trivy-operator>

## Source Code

* <https://github.com/devopstales/trivy-operator>
* <https://github.com/devopstales/helm-charts>

