#!/bin/bash

export LOG_LEVEL=DEBUG
#export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# Fix getpwuid(): uid not found: 1001 by setting the USER env var to prevent python from looking for a matching uid/gid in the password database.
# See https://github.com/python/cpython/blob/v3.6.0/Lib/getpass.py#L155-L170.
USER=$(id -u)
echo "Setting USER environment variable to ${USER}"
export USER=$USER

if [[ $LOG_LEVEL == "DEBUG" ]];
then
        kopf run -A main.py --log-format=full
else
        kopf run -A main.py --log-format=full
fi
