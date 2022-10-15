from genericpath import exists
import kopf, prometheus_client
import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException
import logging
#import asyncio, pycron
from croniter import croniter
from datetime import datetime, timedelta, timezone
import os, subprocess, json, requests, time

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
MyLogger = logging.getLogger("kube-bench-scnner")
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
# Pretasks
#############################################################################

CIS_VULN = prometheus_client.Gauge(
    'cis_results',
    'Details of CIS benchmarks for cluster',
    ['hostname', 'scored', 'status', 'test_number', 'type']
)

# Round time down to the top of the previous minute
def roundDownTime(dt=None, dateDelta=timedelta(minutes=1)):
    roundTo = dateDelta.total_seconds()
    if dt == None : dt = datetime.now()
    seconds = (dt - dt.min).seconds
    rounding = (seconds+roundTo/2) // roundTo * roundTo
    return dt + timedelta(0,rounding-seconds,-dt.microsecond)

# Get next run time from now, based on schedule specified by cron string
def getNextCronRunTime(schedule):
    return croniter(schedule, datetime.now()).get_next(datetime)

# Sleep till the top of the next minute
def sleepTillTopOfNextMinute():
    t = datetime.utcnow()
    sleeptime = 60 - (t.second + t.microsecond/1000000.0)
    time.sleep(sleeptime)

def getCurretnTime():
  now = datetime.now().time() # time object
  return now

"""Start Prometheus Exporter"""
@kopf.on.startup()
async def startup_fn_prometheus_client(logger, **kwargs):
    prometheus_client.start_http_server(9115)
    logger.info("Prometheus Exporter started...")

#############################################################################
# ClustereScanner Scanner
#############################################################################

@kopf.on.resume('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
async def startup_sc( logger, spec, **kwargs):
    logger.info("ClustereScanner Created")
    defectdojo_host = None
    defectdojo_api_key = None
    k8s_cluster = None

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
        defectdojo_host = spec['integrations']['defectdojo']['host']
        defectdojo_api_key = spec['integrations']['defectdojo']['api_key']
        k8s_cluster = spec['integrations']['defectdojo']['k8s-cluster-name']
        logger.info("defectdojo integration is configured")
        logger.debug("namespace-scanners integrations - defectdojo:") # debuglog
        logger.debug("host: %s" % format(defectdojo_host)) # debuglog
        logger.debug("api_key: %s" % format(defectdojo_api_key)) # debuglog
        logger.debug("k8s_cluster: %s" % format(k8s_cluster)) # debuglog
    except:
        logger.info("defectdojo integration is not set")

    try:
        scan_profile = spec['scanProfileName']
        logger.info("ClustereScannerProfile is set to %s" % scan_profile)
    except:
        scan_profile = None
        logger.info("ClustereScannerProfile is not configured")

    if scan_profile is not None:
        KUBE_BENCH_COMMAND = [ "kube-bench", "--nosummary", "--nototals", "--noremediations", "--benchmark", scan_profile, "--json" ]
    else:
        KUBE_BENCH_COMMAND = [ "kube-bench", "--nosummary", "--nototals", "--noremediations", "--json" ]

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
            logger.info("New clusterPolicyReport created") # WARNING
        except ApiException as e:
            if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
                logger.info("clusterPolicyReport %s already exists!!!" % name)
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

    nextRunTime = getNextCronRunTime(crontab)
    while True:
#        if pycron.is_now(crontab):
        roundedDownTime = roundDownTime()
        if (roundedDownTime == nextRunTime):

            res = subprocess.Popen(
                KUBE_BENCH_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = res.communicate()

            if error:
                logger.error("kube-bench run failed: %s" % error)
                raise kopf.PermanentError("kube-bench run failed !!!")
            elif output:
                bench_result = json.loads(output.decode("UTF-8"))
                """DefectDojo Integration"""
                logging.captureWarnings(True)
                if defectdojo_host is not None and defectdojo_api_key is not None and k8s_cluster is not None:
                    DEFECTDOJO_AUTH_TOKEN = "Token " + defectdojo_api_key

                    headers = dict()
                    headers['Authorization'] = DEFECTDOJO_AUTH_TOKEN
                    files = {
                        'file': output.decode("UTF-8")
                    }
                    data = {
                        'scan_date': datetime.now().strftime("%Y-%m-%d"),
                        'active': True,
                        'verified': False,
                        'scan_type': "kube-bench Scan",
                        'product_type_name': "Kubernetes Cluster",
                        'product_name': k8s_cluster,
                        'engagement_name': NODE_NAME,
                        'version': scan_profile,
                        'auto_create_context': True,
                        'close_old_findings': True,
                    }
                    response = requests.post(defectdojo_host+"/api/v2/import-scan/", headers=headers, files=files, data=data, verify=False)
                    if response.status_code == 201 :
                        logger.info("Successfully uploaded the results to Defect Dojo")
                    else:
                        logger.info("Something went wrong, please debug " + str(response.text))
                    """Add kubernetes node to Defect Dojo"""
                    response = requests.get(defectdojo_host+"/api/v2/products/?name="+k8s_cluster, headers=headers, verify=False)
                    response_body = json.loads(response.text)
                    for item in response_body['results']:
                        product = item['id']
                    data = {
                        "tags": [
                            "Kubernetes"
                        ],
                        "host": NODE_NAME,
                        "product": product,
                    }
                    response = requests.post(defectdojo_host+"/api/v2/endpoints/", headers=headers, data=data, verify=False)
                    if response.status_code == 201 :
                        logger.info("Successfully added host to Defect Dojo")
                    else:
                        if "already exists" in response.text:
                            print()
                        else:
                            logger.info("Something went wrong, please debug " + str(response.text))

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

            for item in bench_result:
                MyLogger.info("Node Type: %s" % item["node_type"]) # warning
                for test in item["tests"]:
                    MyLogger.info("Tets: %s" % test["desc"]) # warning
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

                        """Generate Metricfile"""
                        MyLogger.info("id: %s" % result["test_number"]) # warning
                        if "manual" in result["type"]:
                            result_type = result["type"]
                        else:
                            result_type = "automated"

                        if "PASS" in result["status"]:
                            CIS_VULN.labels(
                                NODE_NAME,
                                result["scored"],
                                result["status"],
                                result["test_number"],
                                result_type,
                            ).set(0)
                        else:
                            CIS_VULN.labels(
                                NODE_NAME,
                                result["scored"],
                                result["status"],
                                result["test_number"],
                                result_type,
                            ).set(1)

            is_pClusterPolicyReport_exists = get_clusterpolicyreports(report_name)
            MyLogger.info("DEBUG - is_pClusterPolicyReport_exists: %s" % is_pClusterPolicyReport_exists) # WARNING

            if is_pClusterPolicyReport_exists:
                logger.info("clusterPolicyReport need deletion") # WARNING
                delete_clusterpolicyreports(report_name)
                create_clusterpolicyreports(ClusterPolicyReport, report_name)
            else:
                create_clusterpolicyreports(ClusterPolicyReport, report_name)

        elif (roundedDownTime > nextRunTime):
            # We missed an execution. Error. Re initialize.
            now = getCurretnTime()
            MyLogger.info("MISSED RUN: %s" % now) # WARNING
            nextRunTime = getNextCronRunTime(crontab)
        sleepTillTopOfNextMinute()
#            await asyncio.sleep(15)
#        else:
#            await asyncio.sleep(15)