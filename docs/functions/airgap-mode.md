# Air-Gapped Environment

Trivy-operator can be used in air-gapped environments.

## Air-Gapped Environment for vulnerabilities

### Download the vulnerability database

=== "wget"

    ```
    $ wget https://github.com/aquasecurity/trivy-db/releases/latest/download/trivy-offline.db.tgz
    $ mv trivy-offline.db.tgz db.tar.gz
    ```

=== "Trivy"

    ```
    TRIVY_TEMP_DIR=$(mktemp -d)
    trivy --cache-dir $TRIVY_TEMP_DIR image --download-db-only
    tar -cf ./db.tar.gz -C $TRIVY_TEMP_DIR/db metadata.json trivy.db
    rm -rf $TRIVY_TEMP_DIR
    ```

=== "oras >= v0.13.0"
    At first, you need to download the vulnerability database for use in air-gapped environments.
    Please follow [oras installation instruction][oras].

    Download `db.tar.gz`:

    ```
    $ oras pull ghcr.io/aquasecurity/trivy-db:2
    ```

=== "oras < v0.13.0"
    At first, you need to download the vulnerability database for use in air-gapped environments.
    Please follow [oras installation instruction][oras].

    Download `db.tar.gz`:

    ```
    $ oras pull -a ghcr.io/aquasecurity/trivy-db:2
    ```

### Put the DB file in Trivy's cache directory

```
$ kubectl cp db.tar.gz trivy-operator:/home/trivy-operator/trivy-cache/
```

Put the DB file in the cache directory

```
$ kubectl exec -it trivy-operator bash

$ mkdir -p /home/trivy-operator/trivy-cache/db
$ cd /home/trivy-operator/trivy-cache
$ tar xvf db.tar.gz /home/trivy-operator/trivy-cache/db
x trivy.db
x metadata.json
$ rm db.tar.gz
```

In an air-gapped environment it is your responsibility to update the Trivy database on a regular basis, so that the scanner can detect recently-identified vulnerabilities. 

### Run Trivy with offline option
In an air-gapped environment, specify `offline.enabled: true` helm option at install, so that Trivy doesn't attempt to download the latest database file.

```
# Don't try to download trivy db, run in air-gapped env:
offline:
  enabled: true
```

### Use your own OCI registry to store the vulnerability database

With `oras` cli you can upload the downloaded database to your own OCI (Docker) registry:

```
oras push localhost:5000/trivy-db:2 \
db.tar.gz:application/vnd.aquasec.trivy.db.layer.v1.tar+gzip

curl -X GET http://localhost:5000/v2/_catalog
{"repositories":["nginx","trivy-db"]}

curl -X GET http://localhost:5000/v2/trivy-db/tags/list
{"name":"trivy-db","tags":["2"]}
```

You can test the mechanism with your local trivy:

```
trivy image --db-repository localhost:5000/trivy-db alpine:latest
2022-09-15T09:45:44.928+0200	INFO	Need to update DB
2022-09-15T09:45:44.929+0200	INFO	DB Repository: localhost:5000/trivy-db
2022-09-15T09:45:44.929+0200	INFO	Downloading DB...
33.89 MiB / 33.89 MiB [-------------------------------------------------------------------------------------------------] 100.00% 21.70 MiB p/s 1.8s
2022-09-15T09:45:46.834+0200	INFO	Vulnerability scanning is enabled
2022-09-15T09:45:46.834+0200	INFO	Secret scanning is enabled
2022-09-15T09:45:46.834+0200	INFO	If your scanning is slow, please try '--security-checks vuln' to disable secret scanning
2022-09-15T09:45:46.834+0200	INFO	Please see also https://aquasecurity.github.io/trivy/v0.31.3/docs/secret/scanning/#recommendation for faster secret detection
2022-09-15T09:45:49.099+0200	INFO	Detected OS: alpine
2022-09-15T09:45:49.099+0200	INFO	Detecting Alpine vulnerabilities...
2022-09-15T09:45:49.100+0200	INFO	Number of language-specific files: 0

alpine:latest (alpine 3.16.2)

Total: 0 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0)
```

In the helm chart you need to specify the url of your OCI registry with the `db_repository` option.

```
# Don't try to download trivy db, run in air-gapped env:
offline:
  enabled: true
  db_repository: localhost:5000/trivy-db
```