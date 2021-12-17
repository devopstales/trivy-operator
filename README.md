# Trivy Operator

Built with [kopf](https://github.com/nolar/kopf)

Main functions:

* Scheduled Image scans on running pods
* Trivy Image Validator Admission controller

Inspirated by [knqyf263](https://github.com/knqyf263)'s [trivy-enforcer](https://github.com/aquasecurity/trivy-enforcer) and [fleeto](https://github.com/fleeto)'s [trivy-scanner](https://github.com/fleeto/trivy-scanner).

### Schefuled Image scans
Default every 5 minutes execute a scan script. It will get image list from all namespaces with the label `trivy-scan=true`, and then scan this images with trivy, finally we will get metrics on `http://[pod-ip]:9115/metrics`

### Trivy Image Validator
The admission controller function can be configured as a ValidatingWebhook in a k8s cluster. Kubernetes will send requests to the admission server when a Pod creation is initiated. The admission controller checks the image using trivy if it is in a namespace with the lable `trivy-operator-validation=true`.


## Usage

```bash
kubectl label namespaces guestbook-demo trivy-scan=true
kubectl label namespaces guestbook-demo trivy-operator-validation=true
# or
kubectl apply -f deploy/10_demo.yaml

kubectl apply -f deploy/04_trivy-config.yaml
```

~~~text
curl -s http://10.43.179.39:9115/metrics | grep so_vulnerabilities

so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="UNKNOWN"} 0
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="LOW"} 23
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="MEDIUM"} 93
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="HIGH"} 76
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:1.18",severity="CRITICAL"} 25
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:latest",severity="UNKNOWN"} 0
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:latest",severity="LOW"} 23
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:latest",severity="MEDIUM"} 88
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:latest",severity="HIGH"} 60
so_vulnerabilities{exported_namespace="trivytest",image="docker.io/library/nginx:latest",severity="CRITICAL"} 8
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
~~~

### Example Deploy:
You can define policy to the Admission Controller, by adding annotation to the pod trough the deployment:

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
