#!/usr/bin/env python3

import kopf, prometheus_client

from modules.helper_functions import *
from modules.namespace_scanner import (
    trivy_cache_download,
    namespace_scanner,
)
from modules.get_variables import AC_ENABLED
from modules.admission_controller import (
    create_admission_server, 
    start_admission_controller,
)
from modules.cluster_scanner import (
    create_cluster_scanner,
    delete_cluster_scanner,
)


#############################################################################
# Logging
#############################################################################

logger = get_logger(__name__)

"""Set Log Level"""
@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.posting.level = get_logger_level(logger)


#############################################################################
# Initialization
#############################################################################

"""Start Prometheus Exporter"""
@kopf.on.startup()
async def startup_fn_prometheus_client(logger, **kwargs):
    prometheus_client.start_http_server(9115)
    logger.info("Prometheus Exporter started...")

"""Download trivy cache """
@kopf.on.startup()
async def startup_fn_trivy_cache(logger, **kwargs):
    trivy_cache_download(logger)

@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'namespace-scanners')
async def create_fn( logger, spec, **kwargs):
    namespace_scanner(logger, spec)

    if AC_ENABLED:
        """Admission Server Creation"""
        @kopf.on.startup()
        def configure(settings: kopf.OperatorSettings, logger, **_):
            create_admission_server(logger, settings)

        """Admission Controller"""
        @kopf.on.validate('pod', operation='CREATE')
        def validate1(logger, namespace, name, annotations, spec, **_):
            start_admission_controller(logger, spec, annotations)

@kopf.on.resume('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
async def startup_sc_deployer(logger, spec, **kwargs):
    create_cluster_scanner(logger, spec)

@kopf.on.delete('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
async def startup_sc_deleter( logger, spec, **kwargs):
    delete_cluster_scanner(logger, spec)