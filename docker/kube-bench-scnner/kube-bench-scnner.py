import kopf
import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException
import logging
import asyncio
import pycron
import os
import subprocess
import json
# import prometheus_client

#############################################################################
# ToDo
#############################################################################
## Add prometheus endpoint for kube-bench scanner
## Integration with OWASP Defectdojo
#############################################################################
# Logging
#############################################################################

VERBOSE_LOG = os.getenv("VERBOSE_LOG", False) in ('true', '1', 'True', 't', 'yes', 'Yes')
IN_CLUSTER = os.getenv("IN_CLUSTER", False) in ('true', '1', 'True', 't', 'yes', 'Yes')

FORMAT = '[%(asctime)s] %(name)s         [VERBOSE_LOG] %(message)s'

logging.basicConfig(format=FORMAT)
MyLogger = logging.getLogger("trivy-operator")
MyLogger.setLevel(logging.WARNING)

if VERBOSE_LOG:
    MyLogger.setLevel(logging.INFO)


level = os.getenv('LOG_LEVEL', 'INFO').upper()
LOG_LEVEL = logging.getLevelName(level)

"""Set Log Level"""
@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.posting.level = LOG_LEVEL

#############################################################################
# ClustereScanner Scanner
#############################################################################

#@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
@kopf.on.resume('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
async def startup_sc( logger, spec, **kwargs):
    logger.info("ClustereScanner Created")

    try:
        NODE_NAME = os.environ.get("NODE_NAME")
        report_name = ("kube-bench-cis-" + NODE_NAME )
    except:
            logger.error("NODE_NAME variable mast configure !!!")
            raise kopf.PermanentError("NODE_NAME variable not set")

    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    try:
        crontab = spec['crontab']
        logger.debug("cluster-scanners - crontab:") # debuglog
        logger.debug(format(crontab)) # debuglog
    except:
        logger.error("cluster-scanner: crontab must be set !!!")
        raise kopf.PermanentError("cluster-scanner: crontab must be set")

    try:
        scan_profile = spec['scanProfileName']
        logger.info("ClustereScannerProfile is set to %s" % scan_profile)
    except:
        scan_profile = None
        logger.info("ClustereScannerProfile is not configured")

    if scan_profile is not None:
        KUBE_BENCH_COMMAND = [ "kube-bench", "--benchmark", scan_profile, "--json" ]
    else:
        KUBE_BENCH_COMMAND = [ "kube-bench", "--json" ]

# -s [master node controlplane etcd policies]
# --benchmark [ack-1.0 aks-1.0 cis-1.20 cis-1.23 cis-1.5 cis-1.6 eks-1.0.1 gke-1.0 gke-1.2.0 rh-0.7 rh-1.0]

    """Test policyReport"""
    def get_clusterpolicyreports(name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'wgpolicyk8s.io'
            version = 'v1alpha2'
            plural = 'clusterpolicyreports'
        try:
            api_response = api_instance.get_cluster_custom_object(
                group, version, plural, name
            )
            MyLogger.info("api_response: %s" % api_response) # WARNING
            return True
        except ApiException as e:
            if e.status != 404:
                print("Exception when testing clusterpolicyreport - %s : %s\n" % (name, e))
                return False
            else:
                return False

    """Generate policyReport"""
    def create_clusterpolicyreports(body, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'wgpolicyk8s.io'
            version = 'v1alpha2'
            plural = 'clusterpolicyreports'
            pretty = 'true'
            field_manager = 'trivy-operator'
            body = body
        try:
            api_response = api_instance.create_cluster_custom_object(
                group, version, plural, body, pretty=pretty, field_manager=field_manager)
            logger.info("New policyReport created") # WARNING
        except ApiException as e:
            if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
                logger.info("policyReport %s already exists!!!" % name)
            else:
                print("Exception when creating clusterpolicyreport - %s : %s\n" % (name, e))

    """Delete policyReport"""
    def delete_clusterpolicyreports(name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'wgpolicyk8s.io'
            version = 'v1alpha2'
            plural = 'clusterpolicyreports'
        try:
            api_response = api_instance.delete_cluster_custom_object(
                group, version, plural, name)
        except ApiException as e:
            print("Exception when deleting clusterpolicyreport - %s : %s\n" % (name, e))

    ############################################
    # start crontab
    ############################################

    while True:
        if pycron.is_now(crontab):
            res = subprocess.Popen(
                KUBE_BENCH_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = res.communicate()

            if error:
                logger.error("kube-bench run failed: %s" % error)
                raise kopf.PermanentError("kube-bench run failed !!!")
            elif output:
                bench_result = json.loads(output.decode("UTF-8"))

            ClusterPolicyReport = {
                "apiVersion": "wgpolicyk8s.io/v1alpha2",
                "kind": "ClusterPolicyReport",
                "metadata": {
                    "name": report_name
                },
                "results": [],
                "summary": {
                    "error": 0,
                    "fail": 0,
                    "pass": 0,
                    "skip": 0,
                    "warn": 0,
                },
            }

            for item in bench_result["Controls"]:
                for test in item["tests"]:
                  #  ClusterPolicyReport["summary"]["error"] += 
                    ClusterPolicyReport["summary"]["fail"] += test["fail"]
                    ClusterPolicyReport["summary"]["pass"] += test["pass"]
                    ClusterPolicyReport["summary"]["warn"] += test["warn"]
                    for result in test["results"]:
                        try:
                            reason = result["reason"]
                        except:
                            reason = ""
                        report = {
                            "category": test["desc"],
                            "message": result["test_desc"],
                            "policy": item["text"],
                            "rule": test["desc"],
                            "properties": {
                                "AuditConfig": result["AuditConfig"],
                                "AuditEnv": result["AuditEnv"],
                                "IsMultiple": str(result["IsMultiple"]),
                                "actual_value": result["actual_value"],
                                "audit": result["audit"],
                                "expected_result": result["expected_result"],
                                "index": result["test_number"],
                                "reason": reason,
                                "remediation": result["remediation"],
                                "test_info": result["test_info"][0],
                                "type": result["type"],
                            },
                            "result": result["status"].lower(),
                      #      "severity": "",
                            "source": "CIS Vulnerability"
                        }
                        ClusterPolicyReport["results"] += [report]

            is_pClusterPolicyReport_exists = get_clusterpolicyreports(report_name)
            MyLogger.info("DEBUG - is_pClusterPolicyReport_exists: %s" % is_pClusterPolicyReport_exists) # WARNING

            if is_pClusterPolicyReport_exists:
                logger.info("policyReport need deletion") # WARNING
                delete_clusterpolicyreports(report_name)
                create_clusterpolicyreports(ClusterPolicyReport, report_name)
            else:
                create_clusterpolicyreports(ClusterPolicyReport, report_name)

            await asyncio.sleep(15)
        else:
            await asyncio.sleep(15)