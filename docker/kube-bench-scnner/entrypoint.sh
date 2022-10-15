#!/bin/bash

if [[ $LOG_LEVEL == "DEBUG" ]];
then
	kopf run -v -A /kube-bench-scnner.py --log-format=full
else
	kopf run -A /kube-bench-scnner.py --log-format=full
fi
