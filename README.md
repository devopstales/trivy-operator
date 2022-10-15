# Trivy Operator

The goal of this project is to provide a vulnerability scanner that continuously scans containers deployed in a Kubernetes cluster. Built with [kopf](https://github.com/nolar/kopf)


It works as 
- Operator
  - Scheduled Image scans on running pods
- Admission Controller
  - protecting unsafe images from being deployed

Inspirated by [knqyf263](https://github.com/knqyf263)'s [trivy-enforcer](https://github.com/aquasecurity/trivy-enforcer) and [fleeto](https://github.com/fleeto)'s [trivy-scanner](https://github.com/fleeto/trivy-scanner).

### Scheduled Image scans
Default trivy-operator execute a scan script every 5 minutes. It will get images from all the namespaces with the label `trivy-scan=true`, and then check these images with trivy for vulnerabilities. Finally we will get metrics on `http://[pod-ip]:9115/metrics`

### Trivy Image Validator
The admission controller function can be configured as a ValidatingWebhook in a k8s cluster. Kubernetes will send requests to the admission server when a Pod creation is initiated. The admission controller checks the image using trivy if it is in a namespace with the label `trivy-operator-validation=true`.

## Install

User the [helm Chert](https://github.com/devopstales/helm-charts)

## Usage

```bash
kubectl label namespaces guestbook-demo trivy-scan=true
kubectl label namespaces guestbook-demo trivy-operator-validation=true
# or
kubectl apply -f deploy/kubernetes/10_demo.yaml

kubectl apply -f deploy/kubernetes/04_trivy-config.yaml
```

~~~text
curl -s http://10.43.179.39:9115/metrics | grep trivy_vulnerabilities
# HELP trivy_vulnerabilities_sum Container vulnerabilities
# TYPE trivy_vulnerabilities_sum gauge
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/openshift/mysql-56-centos7:latest",severity="scanning_error"} 1.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",severity="UNKNOWN"} 0.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",severity="LOW"} 83.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",severity="MEDIUM"} 5.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",severity="HIGH"} 7.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",severity="CRITICAL"} 4.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="UNKNOWN"} 0.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="LOW"} 126.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="MEDIUM"} 25.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="HIGH"} 43.0
trivy_vulnerabilities_sum{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="CRITICAL"} 21.0
# HELP trivy_vulnerabilities Container vulnerabilities
# TYPE trivy_vulnerabilities gauge
trivy_vulnerabilities{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",installedVersion="2.2.4",pkgName="pkgName",severity="LOW",vulnerabilityId="CVE-2011-3374"} 1.0
trivy_vulnerabilities{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",installedVersion="8.32-4",pkgName="pkgName",severity="LOW",vulnerabilityId="CVE-2016-2781"} 1.0
trivy_vulnerabilities{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",installedVersion="8.32-4",pkgName="pkgName",severity="LOW",vulnerabilityId="CVE-2017-18018"} 1.0
trivy_vulnerabilities{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",installedVersion="7.74.0-1.3",pkgName="pkgName",severity="CRITICAL",vulnerabilityId="CVE-2021-22945"} 1.0
trivy_vulnerabilities{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",installedVersion="7.74.0-1.3",pkgName="pkgName",severity="HIGH",vulnerabilityId="CVE-2021-22946"} 1.0
trivy_vulnerabilities{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",installedVersion="7.74.0-1.3",pkgName="pkgName",severity="MEDIUM",vulnerabilityId="CVE-2021-22947"} 1.0
trivy_vulnerabilities{exported_namespace="trivytest",image="docker.io/nginxinc/nginx-unprivileged:latest",installedVersion="7.74.0-1.3",pkgName="pkgName",severity="LOW",vulnerabilityId="CVE-2021-22898"} 1.0
~~~

~~~text
curl -s http://10.43.179.39:9115/metrics | grep ac_vulnerabilities

# HELP ac_vulnerabilities Admission Controller vulnerabilities
# TYPE ac_vulnerabilities gauge
ac_vulnerabilities{exported_namespace="trivytest",image="nginxinc/nginx-unprivileged:latest",severity="UNKNOWN"} 0.0
ac_vulnerabilities{exported_namespace="trivytest",image="nginxinc/nginx-unprivileged:latest",severity="LOW"} 83.0
ac_vulnerabilities{exported_namespace="trivytest",image="nginxinc/nginx-unprivileged:latest",severity="MEDIUM"} 6.0
ac_vulnerabilities{exported_namespace="trivytest",image="nginxinc/nginx-unprivileged:latest",severity="HIGH"} 6.0
ac_vulnerabilities{exported_namespace="trivytest",image="nginxinc/nginx-unprivileged:latest",severity="CRITICAL"} 4.0
~~~


~~~text
kubectl logs 

[2021-10-02 09:38:38,598] kopf.activities.star [INFO    ] Activity 'startup_fn_crd' succeeded.
[2021-10-02 09:38:38,687] kopf.activities.star [INFO    ] trivy cache created...
[2021-10-02 09:38:38,687] kopf.activities.star [INFO    ] Activity 'startup_fn_trivy_cache' succeeded.
[2021-10-02 09:38:38,689] kopf._core.engines.a [INFO    ] Initial authentication has been initiated.
[2021-10-02 09:38:38,696] kopf.activities.auth [INFO    ] Activity 'login_via_client' succeeded.
[2021-10-02 09:38:38,697] kopf._core.engines.a [INFO    ] Initial authentication has finished.
[2021-10-02 09:38:46,726] kopf.objects         [INFO    ] [trivytest/main-config] Prometheus Exporter started...
[2021-10-02 09:40:01,831] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:1.18
[2021-10-02 09:40:05,245] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:latest
[2021-10-02 09:40:23,817] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:1.18
[2021-10-02 09:40:26,947] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:latest
[2021-10-02 09:40:45,428] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:1.18
[2021-10-02 09:40:48,949] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:latest

[2021-10-02 09:45:08,229] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:1.18
[2021-10-02 09:45:11,922] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:latest
[2021-10-02 09:45:30,381] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:1.18
[2021-10-02 09:45:33,881] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:latest
[2021-10-02 09:45:52,227] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:1.18
[2021-10-02 09:45:55,556] kopf.objects         [INFO    ] [trivytest/main-config] Scanning Image: docker.io/library/nginx:latest

[2021-10-02 18:33:32,742] kopf.objects         [INFO    ] [trivytest/app-85ddd4585b-sdt4t] Admission Controller is working
[2021-10-02 18:33:32,755] kopf.objects         [INFO    ] [trivytest/app-85ddd4585b-sdt4t] Scanning Image: nginxinc/nginx-unprivileged:latest
[2021-10-02 18:33:34,967] kopf.objects         [INFO    ] [trivytest/app-85ddd4585b-sdt4t] severity: {'UNKNOWN': 0, 'LOW': 83, 'MEDIUM': 6, 'HIGH':6, 'CRITICAL': 4}
[2021-10-02 18:33:34,969] kopf.objects         [ERROR   ] [trivytest/app-85ddd4585b-sdt4t] Webhook 'validate1' failed permanently: Too muchvulnerability in the image: nginxinc/nginx-unprivileged:latest
[2021-10-02 18:33:34,971] aiohttp.access       [INFO    ] 10.244.0.1 [17/Dec/2021:18:33:32 +0000] "POST /validate1?timeout=30s HTTP/1.1" 200 417"-" "kube-apiserver-admission"
~~~

### Example Deploy:
You can define policy to the Admission Controller, by adding annotation to the pod through the deployment:

```yaml
spec:
  ...
  template:
    metadata:
      annotations:
        trivy.security.devopstales.io/medium: "5"
        trivy.security.devopstales.io/low: "10"
        trivy.security.devopstales.io/critical: "2"
...
```

### Development

Install trivy:

```bash
nano /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=0
enabled=1

sudo yum -y install trivy
```

To run kopf development you need to install the fallowing packages to the k3s host:

```bash
yum install -y python3.8
pip3 install --no-cache-dir kopf[dev] kubernetes asyncio pycron prometheus_client oscrypto certvalidator certbuilder validators pyOpenSSL
```

The admission webhook try to call the host with the domain name `host.k3d.internal` so I added to the host's `/etc/host` file.

```bash
echo "172.17.12.10 host.k3d.internal" >> /etc/host
```

```bash
kopf run -A ./trivy-operator.py
```

