#!/usr/bin/env python3

import kopf

from modules.helper_functions import get_logger,get_logger_level
from modules.prometheus import startup_prometheus_client
from modules.cluster_scanner import start_cluster_scanner

#############################################################################
# Logging
#############################################################################

logger = get_logger(__name__)

"""Set Log Level"""
@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.posting.level = get_logger_level(logger)

"""Start Prometheus Exporter"""
@kopf.on.startup()
async def startup_fn_prometheus_client(logger, **kwargs):
    startup_prometheus_client(logger)

"""Start ClustereScanner"""
@kopf.on.resume('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
async def startup_sc(logger, spec, **kwargs):
    start_cluster_scanner(logger, spec)