#!/bin/bash

if [[ $LOG_LEVEL == "DEBUG" ]];
then
	kopf run -v -A /trivy-operator.py --log-format=full
else
	kopf run -A /trivy-operator.py --log-format=full
fi
