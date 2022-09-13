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