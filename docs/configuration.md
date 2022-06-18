# Configuration

Create a values file for your helm deploy:

```yaml
cat <<'EOF'> values.yaml
image:
  repository: devopstales/trivy-operator
  pullPolicy: Always
  tag: "2.3"

imagePullSecrets: []
podSecurityContext:
  fsGroup: 10001
  fsGroupChangePolicy: "OnRootMismatch"

serviceAccount:
  create: true
  annotations: {}
  name: "trivy-operator"

monitoring:
  port: "9115"

serviceMonitor:
  enabled: false
  namespace: "monitoring-system"

storage:
  enabled: true
  size: 1Gi

NamespaceScanner:
  crontab: "*/5 * * * *"
  namespaceSelector: "trivy-scan"

registryAuth:
  enabled: false
  registry:
  - name: docker.io
    user: "user"
    password: "password"

githubToken:
  enabled: false
  token: ""
EOF
```

## Operator Configuration

The following tables lists configurable parameters of the trivy-operator chart and their default values.

|               Parameter             |                Description                  |                  Default                 |
| ----------------------------------- | ------------------------------------------- | -----------------------------------------|
| image.repository                    | image | devopstales/trivy-operator |
| image.pullPolicy                    | pullPolicy | Always |
| image.tag                           | image tag | 2.1 |
| imagePullSecrets                    | imagePullSecrets list | [] |
| podSecurityContext.fsGroup          | mount id | 10001 |
| serviceAccount.create               | create serviceAccount | true |
| serviceAccount.annotations          | add annotation to serviceAccount | {} |
| serviceAccount.name                 | name of the serviceAccount | trivy-operator |
| monitoring.port                     | prometheus endpoint port | 9115 |
| serviceMonitor.enabled              | enable serviceMonitor object creation | false |
| serviceMonitor.namespace            | where to create serviceMonitor object | kube-system |
| storage.enabled                     | enable pv to store trivy database | true |
| storage.size                        | pv size | 1Gi |
| NamespaceScanner.crontab            | cronjob scheduler | "*/5 * * * *" |
| NamespaceScanner.namespaceSelector  | Namespace Selector | "trivy-scan" |
| registryAuth.enabled                | enable registry authentication in operator | false |
| registryAuth.registry               | registry name for authentication |
| registryAuth.user                   | username for authentication |
| registryAuth.password               | password for authentication |
| githubToken.enabled                 | Enable githubToken usage for trivy database update | false |
| githubToken.token                   | githubToken value | "" |