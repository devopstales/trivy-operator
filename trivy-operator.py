import kopf, prometheus_client
import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException
#import asyncio, pycron
from croniter import croniter
from datetime import datetime, timedelta, timezone
import time
import os, six, json, subprocess, validators, base64
from typing import AsyncIterator, Optional, Tuple, Collection
from OpenSSL import crypto
import logging, uuid, requests

def var_test(var):
    if isinstance(var, bool):
        resp = var
    elif isinstance(var, six.string_types):
        if var.lower() in ['true']:
            resp = True
        else:
            resp = False
    else:
        resp = False
    return resp

#############################################################################
# Logging
#############################################################################

VERBOSE_LOG = var_test(os.getenv("VERBOSE_LOG", False))
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
# Global Variables
#############################################################################
CONTAINER_VULN_SUM = prometheus_client.Gauge(
    'so_vulnerabilities',
    'Container vulnerabilities',
    ['exported_namespace', 'image', 'severity']
)
CONTAINER_VULN = prometheus_client.Gauge(
    'trivy_vulnerabilities',
    'Container vulnerabilities',
    ['exported_namespace', 'pod', 'image', 'installedVersion',
        'pkgName', 'severity', 'vulnerabilityId']
)
AC_VULN = prometheus_client.Gauge(
    'ac_vulnerabilities',
    'Admission Controller vulnerabilities',
    ['exported_namespace', 'image', 'severity']
)
IN_CLUSTER = var_test(os.getenv("IN_CLUSTER", False))
IS_GLOBAL = var_test(os.getenv("IS_GLOBAL", False))
AC_ENABLED = var_test(os.getenv("ADMISSION_CONTROLLER", False))
REDIS_ENABLED = var_test(os.getenv("REDIS_ENABLED", False))
OFFLINE_ENABLED = var_test(os.getenv("SKIP_DB_UPDATE", False))
DB_REPOSITORY_INSECURE = var_test(os.getenv("DB_REPOSITORY_INSECURE", False))

if REDIS_ENABLED:
    REDIS_BACKEND = os.getenv("REDIS_BACKEND")
    if not REDIS_BACKEND:
        REDIS_ENABLED = False

        MyLogger.warning("Redis Cache Disabled: %s" % (REDIS_BACKEND))
    else:
        MyLogger.warning("Redis Cache Enabled: %s" % (REDIS_BACKEND))
    TRIVY_REDIS = ["--cache-backend", REDIS_BACKEND]

if OFFLINE_ENABLED:
    DB_REPOSITORY = os.getenv("DB_REPOSITORY")
    if not DB_REPOSITORY:
        TRIVY_OFFLINE = ["--skip-db-update", "--offline-scan"]
    else:
        TRIVY_OFFLINE = ["--db-repository", DB_REPOSITORY]
        if DB_REPOSITORY_INSECURE:
            os.environ['TRIVY_INSECURE'] = "true"

#############################################################################
# Pretasks
#############################################################################
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

"""Download trivy cache """
@kopf.on.startup()
async def startup_fn_trivy_cache(logger, **kwargs):
    if OFFLINE_ENABLED:
        if DB_REPOSITORY:
            TRIVY_CACHE = ["trivy", "-q", "image", "--download-db-only"]
            TRIVY_CACHE = TRIVY_CACHE + ["--db-repository", DB_REPOSITORY]
            trivy_cache_result = (
                subprocess.check_output(TRIVY_CACHE).decode("UTF-8")
            )
            logger.info("Offline mode enabled, trivy cache created...")
        else:
            logger.info("Offline mode enabled, skipping cache update")
    else:
        TRIVY_CACHE = ["trivy", "-q", "image", "--download-db-only"]
        if REDIS_ENABLED:
            TRIVY_CACHE = TRIVY_CACHE + TRIVY_REDIS
        trivy_cache_result = (
            subprocess.check_output(TRIVY_CACHE).decode("UTF-8")
        )
        logger.info("trivy cache created...")

"""Start Prometheus Exporter"""
@kopf.on.startup()
async def startup_fn_prometheus_client(logger, **kwargs):
    prometheus_client.start_http_server(9115)
    logger.info("Prometheus Exporter started...")

#############################################################################
# Operator
#############################################################################
# Namespace Scanner
#############################################################################

@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'namespace-scanners')
async def create_fn( logger, spec, **kwargs):
    logger.info("NamespaceScanner Created")

    registry_list = []
    secret_names = None
    current_namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")
    clusterWide = None
    namespaceSelector = None
    policyreport = None
    defectdojo_host = None
    defectdojo_api_key = None


    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    v1 = k8s_client.CoreV1Api()

    try:
        crontab = spec['crontab']
        logger.debug("namespace-scanners - crontab:") # debuglog
        logger.debug(format(crontab)) # debuglog
    except:
        logger.error("namespace-scanner: crontab must be set !!!")
        raise kopf.PermanentError("namespace-scanner: crontab must be set")

    try:
        clusterWide = var_test(spec['clusterWide'])
        logger.debug("namespace-scanners - clusterWide:") # debuglog
        logger.debug(format(clusterWide)) # debuglog
    except:
        logger.warning("clusterWide is not set, checking namespaceSelector")
        clusterWide = False

    try:
        policyreport = var_test(spec['integrations']['policyreport'])
        logger.info("policyreport integration is configured")
        logger.debug("namespace-scanners integrations - policyreport:") # debuglog
        logger.debug(format(policyreport)) # debuglog
    except:
        logger.info("policyreport integration is not set")
        policyreport = False

    try:
        defectdojo_host = spec['integrations']['defectdojo']['host']
        defectdojo_api_key = spec['integrations']['defectdojo']['api_key']
        logger.info("defectdojo integration is configured")
        logger.debug("namespace-scanners integrations - defectdojo:") # debuglog
        logger.debug("host: " % format(defectdojo_host)) # debuglog
        logger.debug("api_key: " % format(defectdojo_api_key)) # debuglog
    except:
        logger.info("defectdojo integration is not set")

    try:
        namespaceSelector = spec['namespace_selector']
        logger.debug("namespace-scanners - namespace_selector:") # debuglog
        logger.debug(format(namespaceSelector)) # debuglog
    except:
        logger.warning("namespace_selector is not set")

    try:
        secret_names = spec['image_pull_secrets']
        secret_names_present = True
        logger.debug("image_pull_secrets:") # debuglog
    except:
        secret_names_present = False
        logger.warning("image_pull_secrets is not set")

    if clusterWide == False and namespaceSelector is None:
        logger.error("Either clusterWide need to be set to 'true' or namespace_selector should be set")
        raise kopf.PermanentError("Either clusterWide need to be set to 'true' or namespace_selector should be set")

    """Get auth data from pull secret"""
    def pull_secret_decoder(secret_names, secret_namespace):
        try:
            registry_list = spec['registry']
        except:
            registry_list = list()
            logger.debug("Can't get registry auth config.") # debug

        for secret_name in secret_names:
            try:
                secret = v1.read_namespaced_secret(secret_name, secret_namespace)
                if '.dockerconfigjson' in secret.data:
                    secret_data = secret.data['.dockerconfigjson']
                    data = json.loads(base64.b64decode(secret_data).decode("utf-8"))
                    registry_list.append(data['auths'])
                    logger.debug(format(data['auths'])) # debuglog
                elif '.dockercfg' in secret.data:
                    secret_data = secret.data['.dockercfg']
                    data = json.loads(base64.b64decode(secret_data).decode("utf-8"))
                    registry_list.append(data)
                    logger.debug(format(data)) # debuglog
                else:
                    logger.error("Unknown pull secret format")
                    logger.debug(format(secret.data)) # debuglog
            except ApiException as e:
                logger.error("%s secret dose not exist in namespace %s" % (secret_name, secret_namespace))
                logger.debug("Exception when calling CoreV1Api->read_namespaced_secret: %s\n" % e) # debuglog

    if secret_names_present:
        pull_secret_decoder(secret_names, current_namespace)

    """Generate VulnerabilityReport"""
    def create_vulnerabilityreports(body, namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'trivy-operator.devopstales.io'
            version = 'v1'
            plural = 'vulnerabilityreports'
            pretty = 'true'
            field_manager = 'trivy-operator'
            body = body
            namespace = namespace
        try:
            api_response = api_instance.create_namespaced_custom_object(
                group, version, namespace, plural, body, pretty=pretty, field_manager=field_manager)
            MyLogger.info("New vulnerabilityReport created") # WARNING
        except ApiException as e:
            if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
                logger.info("VulnerabilityReport %s already exists!!!" % name)
            else:
                logger.error("Exception when creating VulnerabilityReport - %s : %s\n" % (name, e))

    """Test VulnerabilityReport"""
    def get_vulnerabilityreports(namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'trivy-operator.devopstales.io'
            version = 'v1'
            plural = 'vulnerabilityreports'
        try:
            api_response = api_instance.get_namespaced_custom_object(
                group, version, namespace, plural, name
            )
            return True
        except ApiException as e:
            if e.status != 404:
                logger.error("Exception when testing VulnerabilityReport - %s : %s\n" % (name, e))
                return False
            else:
                return False

    """Delete VulnerabilityReport"""
    def delete_vulnerabilityreports(namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'trivy-operator.devopstales.io'
            version = 'v1'
            plural = 'vulnerabilityreports'
        try:
            api_response = api_instance.delete_namespaced_custom_object(
                group, version, namespace, plural, name)
        except ApiException as e:
            logger.error("Exception when deleting VulnerabilityReport - %s : %s\n" % (name, e))

    """Test policyReport"""
    def get_policyreports(namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'wgpolicyk8s.io'
            version = 'v1alpha2'
            plural = 'policyreports'
        try:
            api_response = api_instance.get_namespaced_custom_object(
                group, version, namespace, plural, name
            )
            return True
        except ApiException as e:
            if e.status != 404:
                logger.error("Exception when testing policyReport - %s : %s\n" % (name, e))
                return False
            else:
                return False

    """Generate policyReport"""
    def create_policyreports(body, namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'wgpolicyk8s.io'
            version = 'v1alpha2'
            plural = 'policyreports'
            pretty = 'true'
            field_manager = 'trivy-operator'
            body = body
            namespace = namespace
        try:
            api_response = api_instance.create_namespaced_custom_object(
                group, version, namespace, plural, body, pretty=pretty, field_manager=field_manager)
            MyLogger.info("New policyReport created") # WARNING
        except ApiException as e:
            if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
                logger.info("policyReport %s already exists!!!" % name)
            else:
                logger.error("Exception when creating policyReport - %s : %s\n" % (name, e))

    """Delete policyReport"""
    def delete_policyreports(namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.CustomObjectsApi(api_client)
            group = 'wgpolicyk8s.io'
            version = 'v1alpha2'
            plural = 'policyreports'
        try:
            api_response = api_instance.delete_namespaced_custom_object(
                group, version, namespace, plural, name)
        except ApiException as e:
            logger.error("Exception when deleting policyReport - %s : %s\n" % (name, e))

    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    ############################################
    # start crontab
    ############################################

    nextRunTime = getNextCronRunTime(crontab)
    while True:
        #if pycron.is_now(crontab):
        roundedDownTime = roundDownTime()
        if (roundedDownTime == nextRunTime):

            """Find Namespaces"""
            unique_image_list = {}
            pod_list = {}
            trivy_result_list = {}
            vul_list = {}
            vul_report = {}
            tagged_ns_list = []
            policy_report = {}

            """Find Namespaces"""
            namespace_list = k8s_client.CoreV1Api().list_namespace()
            logger.debug("namespace list begin:") # debuglog
            logger.debug(format(namespace_list)) # debuglog
            logger.debug("namespace list end:") # debuglog

            for ns in namespace_list.items:
                try:
                    ns_label_list = ns.metadata.labels.items()
                    ns_name = ns.metadata.name
                except Exception as e:
                    logger.error(str(e))

                """Find Namespaces with selector tag"""
                logger.debug("labels and namespace begin") # debuglog
                logger.debug(format(ns_label_list)) # debuglog
                logger.debug(format(ns_name)) # debuglog
                logger.debug("labels and namespace end") # debuglog
                for label_key, label_value in ns_label_list:
                    if clusterWide or (namespaceSelector == label_key and bool(label_value) == True):
                        logger.info("Select Namespace: %s" % ns_name)
                        tagged_ns_list.append(ns_name)
                    else:
                        continue

            """Find pods in namespaces"""
            for tagged_ns in tagged_ns_list:
                namespaced_pod_list = k8s_client.CoreV1Api().list_namespaced_pod(tagged_ns)
                """Find images in pods"""
                for pod in namespaced_pod_list.items:
                    containers = pod.status.container_statuses
                    if pod.spec.image_pull_secrets is not None:
                        for item in pod.spec.image_pull_secrets:
                            tmp = str(item)
                            tmp = tmp.replace("\'", "\"")
                            tmp2 = json.loads(tmp)
                            tmp3 = [tmp2.get('name')]
                            pull_secret_decoder(tmp3, tagged_ns)
                    try:
                        for image in containers:
                            pod_name = pod.metadata.name
                            pod_name += '_'
                            pod_name += image.name
                            pod_list[pod_name] = list()
                            image_name_temp = image.image
                            image_id = image.image_id
                            pod_uid = pod.metadata.uid
                            if image_name_temp.startswith('sha256'):
                                image_name = image_id
                            else:
                                image_name = image_name_temp
                            pod_list[pod_name].append(image_name)
                            pod_list[pod_name].append(image_id)
                            pod_list[pod_name].append(tagged_ns)
                            pod_list[pod_name].append(pod_uid)

                            unique_image_list[image_name] = image_name
                            logger.debug("containers begin:") # debuglog
                            logger.debug(format(pod_name)) # debuglog
                            logger.debug(format(pod_list[pod_name])) # debuglog
                            logger.debug("containers end:") # debuglog
                    except:
                        logger.info('containers Type is None')
                        continue

                    initContainers = pod.status.init_container_statuses

                    try:
                        for image in initContainers:
                            pod_name = pod.metadata.name
                            pod_name += '_'
                            pod_name += image.name
                            pod_list[pod_name] = list()
                            image_name_temp = image.image
                            image_id = image.image_id
                            pod_uid = pod.metadata.uid
                            if image_name_temp.startswith('sha256'):
                                image_name = image_id
                            else:
                                image_name = image_name_temp
                            pod_list[pod_name].append(image_name)
                            pod_list[pod_name].append(image_id)
                            pod_list[pod_name].append(tagged_ns)
                            pod_list[pod_name].append(pod_uid)

                            unique_image_list[image_name] = image_name
                            logger.debug("InitContainers begin:") # debuglog
                            logger.debug(format(pod_name)) # debuglog
                            logger.debug(format(pod_list[pod_name])) # debuglog
                            logger.debug("InitContainers end:") # debuglog
                    except:
                        continue

            """Scan images"""
            logger.info("image list begin:") 
            for image_name in unique_image_list:
                logger.info("Scanning Image: %s" % (image_name))

                registry = image_name.split('/')[0]
                for reg in registry_list:
                    if  reg.get(registry):
                        os.environ['DOCKER_REGISTRY'] = registry
                        os.environ['TRIVY_USERNAME'] = reg[registry]['username']
                        os.environ['TRIVY_PASSWORD'] = reg[registry]['password']
                        if var_test(reg[registry]['insecure']):
                            os.environ['TRIVY_INSECURE'] = "true"
                    elif not validators.domain(registry):
                        """If registry is not an url"""
                        if reg.get("docker.io"):
                            os.environ['DOCKER_REGISTRY'] = "docker.io"
                            os.environ['TRIVY_USERNAME'] = reg['docker.io']['username']
                            os.environ['TRIVY_PASSWORD'] = reg['docker.io']['password']
                    ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
                    logger.info("Active Registry: %s" % (ACTIVE_REGISTRY))

                TRIVY = ["trivy", "-q", "image", "-f", "json"]
                if REDIS_ENABLED:
                    TRIVY = TRIVY + TRIVY_REDIS
                if OFFLINE_ENABLED:
                    TRIVY = TRIVY + TRIVY_OFFLINE
                TRIVY = TRIVY + [image_name]
                # --ignore-policy trivy.rego

                res = subprocess.Popen(
                    TRIVY, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output, error = res.communicate()

                if error:
                    """Error Logging"""
                    logger.error("TRIVY ERROR: return %s" % (res.returncode))
                    if b"401" in error.strip():
                        logger.error(
                            "Repository: Unauthorized authentication required")
                        trivy_result_list[image_name] = {
                            "ERROR": "Repository authentication required"
                        }
                    elif b"UNAUTHORIZED" in error.strip():
                        logger.error(
                            "Repository: Unauthorized authentication required")
                        trivy_result_list[image_name] = {
                            "ERROR": "Repository authentication required"
                        }
                    elif b"You have reached your pull rate limit." in error.strip():
                        logger.error("You have reached your pull rate limit.")
                        trivy_result_list[image_name] = {
                            "ERROR": "You have reached your pull rate limit"
                        }
                    elif b"unsupported MediaType" in error.strip():
                        logger.error(
                            "Unsupported MediaType: see https://github.com/google/go-containerregistry/issues/377")
                        trivy_result_list[image_name] = {
                            "ERROR": "Unsupported MediaType"
                        }
                    elif b"MANIFEST_UNKNOWN" in error.strip():
                        logger.error("No tag in registry")
                        trivy_result_list[image_name] = {
                            "ERROR": "No tag in registry"
                        }
                    else:
                        logger.error("%s" % (error.strip()))
                        trivy_result_list[image_name] = {
                            "ERROR": "No tag in registry"
                        }
                elif output:
                    trivy_result = json.loads(output.decode("UTF-8"))
                    trivy_result_list[image_name] = trivy_result
                    """DefectDojo Integration"""
                    if defectdojo_host is not None and defectdojo_api_key is not None:
                        DEFECTDOJO_AUTH_TOKEN = "Token " + defectdojo_api_key
                        image_tag = image_name.split(':')[1]

                        headers = dict()
                        headers['Authorization'] = DEFECTDOJO_AUTH_TOKEN
                        files = {
                            'file': output.decode("UTF-8")
                        }
                        body = {
                            'scan_date': datetime.now().strftime("%Y-%m-%d"),
                            'active': True,
                            'verified': False,
                            'scan_type': "Trivy Scan",
                            'product_type_name': "Container Image",
                            'product_name': image_name.split(':')[0],
                            'engagement_name': "trivy-operator",
                            'version': image_tag,
                            'auto_create_context': True, 
                            'close_old_findings': True, # set the findings that are not present anymore to "inactive/mitigated"
                        }

                        response = requests.post(defectdojo_host+"/api/v2/import-scan/", headers=headers, files=files, data=body, verify=False)
                        if response.status_code == 201 :
                                logger.info("Successfully uploaded the results to DefectDojo")
                        else:
                                logger.info("Something went wrong wit push to DefectDojo, please debug " + str(response.text))

            logger.info("image list end:")

            MyLogger.info("result begin:") # WARNING
            for pod_name in pod_list:
                image_name = pod_list[pod_name][0]
                image_id = pod_list[pod_name][1]
                ns_name = pod_list[pod_name][2]
                pod_uid = pod_list[pod_name][3]
                logger.debug("Assigning scanning result for Pod: %s - %s" % (pod_name, image_name)) # debuglog

                try:
                    if validators.domain(image_name.split('/')[0]):
                        docker_registry = image_name.split('/')[0]
                    else:
                        docker_registry = "docker.io"
                except:
                    docker_registry = "docker.io"
                try:
                    docker_image_part = image_name.split('/', 1)[1]
                except:
                    try:
                        docker_image_part = image_name.split('/')[1]
                    except:
                        docker_image_part = image_name
                docker_image = docker_image_part.split(':')[0]
                docker_tag = docker_image_part.split(':')[1]

                trivy_result = trivy_result_list[image_name]
                #logger.debug(trivy_result) # debug
                vul_report[pod_name] = []
                policy_report[pod_name] = []
                if list(trivy_result.keys())[0] == "ERROR":
                    vuls = {"UNKNOWN": 0, "LOW": 0,
                                "MEDIUM": 0, "HIGH": 0,
                                "CRITICAL": 0, "ERROR": 1,
                                "NONE": 0}
                    vuls_long = {
                        "installedVersion": "",
                        "links": [],
                        "primaryLink": "",
                        "resource": "",
                        "score": 0,
                        "severity": "ERROR",
                        "title": "Image Scanning Error",
                        "vulnerabilityID": ""
                    }
                    report_message = "Image Scanning Error: " + str(list(trivy_result.values())[0])
                    report = {
                        "category": "Vulnerability Scan",
                        "message": report_message,
                        "policy": "Image Vulnerability",
                        "rule": "",
                        "properties": {
                            "registry.server": docker_registry,
                            "artifact.repository": docker_image,
                            "artifact.tag": docker_tag,
                            "resultID": str(uuid.uuid4()),
                        },
                        "resources": [],
                        "result": "error",
                        "source": "Trivy Vulnerability"
                    }
                    report["resources"] = [
                        {
                            "apiVersion": "v1",
                            "kind": "Pod",
                            "name": pod_name,
                            "namespace": ns_name,
                            "uid": pod_uid,
                        }
                    ]

                    vul_report[pod_name] += [vuls_long]
                    policy_report[pod_name] += [report]
                    vul_list[pod_name] = [vuls, ns_name, image_name, pod_uid]

                    MyLogger.info(pod_name) # WARNING
                    logger.debug(vul_report[pod_name]) # debuglog
                    logger.debug(vul_list[pod_name]) # debuglog
                else:
                    if 'Results' in trivy_result and 'Vulnerabilities' in trivy_result['Results'][0]:
                        logger.debug("if trivy_result == OK:")
                        vuls = {"UNKNOWN": 0, "LOW": 0,
                                "MEDIUM": 0, "HIGH": 0,
                                "CRITICAL": 0, "ERROR": 0,
                                "NONE": 0}
                        item_list = trivy_result['Results'][0]["Vulnerabilities"]
                        for item in item_list:
                            
                            CONTAINER_VULN.labels(
                                ns_name,
                                pod_name,
                                image_name,
                                item["InstalledVersion"],
                                item["PkgName"],
                                item["Severity"],
                                item["VulnerabilityID"]
                            ).set(1)
                            vuls[item["Severity"]] += 1

                            try:
                                score = item["CVSS"]["nvd"]["V3Score"]
                            except:
                                try:
                                    score = item["CVSS"]["redhat"]["V3Score"]
                                except:
                                    score = 0
                            try:
                                title = item["Title"]
                            except:
                                title = item["Description"]
                            try:
                                pLink = item["PrimaryURL"]
                            except:
                                pLink = ""
                            try:
                                refLink =  item["References"]
                            except:
                                refLink = []

                            if "CRITICAL" or "HIGH" in item["Severity"]:
                                result = "fail"
                                severity = item["Severity"]
                            if "MEDIUM" or "LOW" in item["Severity"]:
                                result = "warn"
                                severity = item["Severity"]
                            if "UNKNOWN" in item["Severity"]:
                                result = "skip"
                                severity = "INFO"

                            vuls_long = {
                                "vulnerabilityID": item["VulnerabilityID"],
                                "resource": item["PkgName"],
                                "installedVersion": item["InstalledVersion"],
                                "primaryLink": pLink,
                                "severity": item["Severity"],
                                "score": score,
                                "links": refLink,
                                "title": title,
                            }
                            report = {
                                "category": "Vulnerability Scan",
                                "message": title,
                                "policy": "Image Vulnerability",
                                "rule": item["VulnerabilityID"],
                                "properties": {
                                    "registry.server": docker_registry,
                                    "artifact.repository": docker_image,
                                    "artifact.tag": docker_tag,
                                    "resource": item["PkgName"],
                                    "score": str(score),
                                    "primaryLink": pLink,
                                    "installedVersion": item["InstalledVersion"],
                                    "resultID": str(uuid.uuid4()),
                                },
                                "resources": [],
                                "severity": severity.lower(),
                                "result": result,
                                "source": "Trivy Vulnerability"
                            }
                            report["resources"] = [
                                {
                                    "apiVersion": "v1",
                                    "kind": "Pod",
                                    "name": pod_name,
                                    "namespace": ns_name,
                                    "uid": pod_uid,
                                }
                            ]
                            vul_report[pod_name] += [vuls_long]
                            policy_report[pod_name] += [report]
                        vul_list[pod_name] = [vuls, ns_name, image_name, pod_uid]

                        MyLogger.info(pod_name) # WARNING
                        logger.debug(vul_report[pod_name]) # debuglog
                        logger.debug(vul_list[pod_name]) # debuglog
                    elif 'Results' in trivy_result and 'Vulnerabilities' not in trivy_result['Results'][0]:
                        logger.debug("if trivy_result has no Vulnerabilities:")
                        # For Alpine Linux
                        vuls = {"UNKNOWN": 0, "LOW": 0,
                                "MEDIUM": 0, "HIGH": 0,
                                "CRITICAL": 0, "ERROR": 0,
                                "NONE": 1}
                        vuls_long = {
                            "installedVersion": "",
                            "links": [],
                            "primaryLink": "",
                            "resource": "",
                            "score": 0,
                            "severity": "NONE",
                            "title": "There ins no vulnerability in this image",
                            "vulnerabilityID": ""
                        }
                        report = {
                            "category": "Vulnerability Scan",
                            "message": "There ins no vulnerability in this image",
                            "policy": "Image Vulnerability",
                            "properties": {
                                "registry.server": docker_registry,
                                "artifact.repository": docker_image,
                                "artifact.tag": docker_tag,
                                "resultID": str(uuid.uuid4()),
                            },
                            "resources": [],
                            "result": "pass",
                            "source": "Trivy Vulnerability"
                        }
                        report["resources"] = [
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "name": pod_name,
                                "namespace": ns_name,
                                "uid": pod_uid,
                            }
                        ]
                        vul_report[pod_name] = [vuls_long]
                        policy_report[pod_name] = [report]
                        vul_list[pod_name] = [vuls, ns_name, image_name, pod_uid]

                        MyLogger.info(pod_name) # WARNING
                        logger.debug(vul_report[pod_name]) # debuglog
                        logger.debug(vul_list[pod_name]) # debuglog
            MyLogger.info("result end:") # WARNING

            date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%sZ")

            for pod_name in vul_list.keys():
                vuls = vul_list[pod_name][0]
                namespace = vul_list[pod_name][1]
                image = vul_list[pod_name][2]
                pod_uid = vul_list[pod_name][3]

                try:
                    if validators.domain(image.split('/')[0]):
                        image_registry = image.split('/')[0]
                    else:
                        image_registry = "docker.io"
                except:
                    image_registry = "docker.io"

                try:
                    image_part_name = image.split('/', 1)[1]
                except:
                    try:
                        image_part_name = image.split('/')[1]
                    except:
                        image_part_name = image
                image_name = image_part_name.split(':')[0]
                image_tag = image_part_name.split(':')[1]

                criticalCount = vuls['CRITICAL']
                highCount = vuls['HIGH']
                mediumCount = vuls['MEDIUM']
                lowCount = vuls['LOW']
                unknownCount = vuls['UNKNOWN']
                pre_stat = vuls['ERROR']
                if pre_stat == 0:
                    status = "OK"
                else:
                    status = "ERROR"
                

                vr_name = "pod"
                vr_name += '-'
                vr_name += pod_name.split('_')[0]
                vr_name += '-'
                vr_name += "container"
                vr_name += '-'
                vr_name += pod_name.split('_')[1]
                # pod-[nginx]-container-[init]

                logger.debug("Generate VR begin:")  # DEBUG!
                logger.debug("Creatting VR for %s" % pod_name) # DEBUG!
                logger.debug(vul_list[pod_name]) # DEBUG!
                logger.debug("Generate VR end:") # DEBUG!

                vulnerabilityReport = {
                    "apiVersion": "trivy-operator.devopstales.io/v1",
                    "kind": "VulnerabilityReport",
                    "metadata": {
                        "name": vr_name,
                        "labels": {
                            "trivy-operator.pod.namespace": namespace,
                            "trivy-operator.pod.name": pod_name.split('_')[0],
                            "trivy-operator.container.name": pod_name.split('_')[1]
                        },
                        "ownerReferences": [
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "name": pod_name.split('_')[0],
                                "uid": pod_uid,
                                "blockOwnerDeletion": False,
                                "controller": True,
                            }
                       ]
                    },
                    "report": {
                        "artifact": {
                            "repository": image_name,
                            "tag": image_tag
                        },
                        "registry": {
                            "server": image_registry
                        },
                        "summary": {
                            "criticalCount": criticalCount,
                            "highCount": highCount,
                            "lowCount": lowCount,
                            "mediumCount": mediumCount,
                            "unknownCount": unknownCount,
                            "status": status
                        },
                        "updateTimestamp": date,
                        "vulnerabilities": []
                    }
                }
                vulnerabilityReport["report"]["vulnerabilities"] = vul_report[pod_name]

                pr_name = ( "trivy-vuln-" + vr_name )
                policyReport = {
                    "apiVersion": "wgpolicyk8s.io/v1alpha2",
                    "kind": "PolicyReport",
                    "metadata": {
                        "name": pr_name,
                        "labels": {
                            "trivy-operator.pod.namespace": namespace,
                            "trivy-operator.pod.name": pod_name.split('_')[0],
                            "trivy-operator.container.name": pod_name.split('_')[1]
                        },
                        "ownerReferences": [
                            {
                                "apiVersion": "v1",
                                "kind": "Pod",
                                "name": pod_name.split('_')[0],
                                "uid": pod_uid,
                                "blockOwnerDeletion": False,
                                "controller": True,
                            }
                       ]
                    },
                    "results": [],
                    "summary": {
                        "error": vuls['ERROR'],
                        "fail": ( criticalCount + highCount ),
                        "pass": vuls['NONE'],
                        "skip": unknownCount,
                        "warn": ( mediumCount + lowCount ),
                    },
                }
                if vuls['NONE'] > 0:
                    policy_report[pod_name][0]["rule"] = ""
                policyReport["results"] = policy_report[pod_name]

                is_vulnerabilityreport_exists = get_vulnerabilityreports(namespace, vr_name)
                MyLogger.info("DEBUG - is_vulnerabilityreport_exists: %s" % is_vulnerabilityreport_exists) # WARNING

                if is_vulnerabilityreport_exists:
                    MyLogger.info("vulnerabilityReport need deletion") # WARNING
                    delete_vulnerabilityreports(namespace, vr_name)
                    create_vulnerabilityreports(vulnerabilityReport, namespace, vr_name)
                else:
                    create_vulnerabilityreports(vulnerabilityReport, namespace, vr_name)

                logger.debug("Generate PR begin:")
                if policyreport:
                    is_policyreports_exists = get_policyreports(namespace, pr_name)
                    MyLogger.info("DEBUG - is_policyreports_exists: %s" % is_policyreports_exists) # WARNING

                    if is_policyreports_exists:
                        MyLogger.info("policyReport need deletion") # WARNING
                        delete_policyreports(namespace, pr_name)
                        create_policyreports(policyReport, namespace, pr_name)
                    else:
                        logger.error("policyreport dose not exists")
                        create_policyreports(policyReport, namespace, pr_name)
                logger.debug("Generate PR end:")


            """Generate Metricfile"""
            for pod_name in vul_list.keys():
                for severity in vul_list[pod_name][0].keys():
                    CONTAINER_VULN_SUM.labels(
                        vul_list[pod_name][1],
                        vul_list[pod_name][2], severity).set(int(vul_list[pod_name][0][severity])
                                                  )
            now = getCurretnTime()
            MyLogger.info("CRON RUN: %s" % now) # WARNING
            nextRunTime = getNextCronRunTime(crontab)
        elif (roundedDownTime > nextRunTime):
            # We missed an execution. Error. Re initialize.
            now = getCurretnTime()
            MyLogger.info("MISSED RUN: %s" % now) # WARNING
            nextRunTime = getNextCronRunTime(crontab)
        sleepTillTopOfNextMinute()
#            await asyncio.sleep(15)
#        else:
#            await asyncio.sleep(15)

#############################################################################
# Admission Controller
#############################################################################

if AC_ENABLED:
    if IN_CLUSTER:
        class ServiceTunnel:
            async def __call__(
                self, fn: kopf.WebhookFn
            ) -> AsyncIterator[kopf.WebhookClientConfig]:
                # https://github.com/kubernetes-client/python/issues/363
                # Use field reference to environment variable instad
                namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")
                name = "trivy-image-validator"
                service_port = int(443)
                container_port = int(8443)
                server = kopf.WebhookServer(
                    port=container_port, host=f"{name}.{namespace}.svc")
                async for client_config in server(fn):
                    client_config["url"] = None
                    client_config["service"] = kopf.WebhookClientConfigService(
                        name=name, namespace=namespace, port=service_port
                    )
                    yield client_config

        def build_certificate(
            logger,
            hostname: Collection[str],
            password: Optional[str] = None,
        ) -> Tuple[bytes, bytes]:
            """
            https://github.com/nolar/kopf/blob/7ba1771306df7db9fa654c2c9bc7983eb5d5061b/kopf/_kits/webhooks.py#L344
            For a self-signed certificate, the CA bundle is the certificate itself
            """
            try:
                import certbuilder
                import oscrypto.asymmetric
            except ImportError:
                logger.error("Need certbuilder")

            # Build a certificate as the framework believe is good enough for itself.
            subject = {'common_name': hostname[0]}
            public_key, private_key = oscrypto.asymmetric.generate_pair(
                'rsa', bit_size=2048)
            builder = certbuilder.CertificateBuilder(subject, public_key)
            builder.ca = True
            builder.key_usage = {'digital_signature',
                                'key_encipherment', 'key_cert_sign', 'crl_sign'}
            builder.extended_key_usage = {'server_auth', 'client_auth'}
            builder.self_signed = True
            builder.subject_alt_domains = list(hostname)
            certificate = builder.build(private_key)
            cert_pem = certbuilder.pem_armor_certificate(certificate)
            pkey_pem = oscrypto.asymmetric.dump_private_key(
                private_key, password, target_ms=10)
            return cert_pem, pkey_pem

        def gen_cert_and_vwc(logger, hostname, cert_file, key_file):
            # Generate cert
            logger.info("Generating a self-signed certificate for HTTPS.")
            certdata, pkeydata = build_certificate(logger, [hostname, "localhost"])
            # write to file
            certf = open(cert_file, "w+")
            certf.write(str(certdata.decode('ascii')))
            certf.close()
            pkeyf = open(key_file, "w+")
            pkeyf.write(str(pkeydata.decode('ascii')))
            pkeyf.close()
            caBundle = base64.b64encode(certdata).decode('ascii')

            # Create own ValidatingWebhookConfiguration
            with k8s_client.ApiClient() as api_client:
                api_instance = k8s_client.AdmissionregistrationV1Api(api_client)
                body = k8s_client.V1ValidatingWebhookConfiguration(
                    api_version='admissionregistration.k8s.io/v1',
                    kind='ValidatingWebhookConfiguration',
                    metadata=k8s_client.V1ObjectMeta(
                        name='trivy-image-validator.devopstales.io'),
                    webhooks=[k8s_client.V1ValidatingWebhook(
                        client_config=k8s_client.AdmissionregistrationV1WebhookClientConfig(
                            ca_bundle=caBundle,
                            service=k8s_client.AdmissionregistrationV1ServiceReference(
                                name="trivy-image-validator",
                                namespace=os.environ.get(
                                    "POD_NAMESPACE", "trivy-operator"),
                                path="/validate1",
                                port=443
                            )
                        ),
                        admission_review_versions=["v1beta1", "v1"],
                        failure_policy="Fail",
                        match_policy="Equivalent",
                        name='validate1.trivy-image-validator.devopstales.io',
                        namespace_selector=k8s_client.V1LabelSelector(
                            match_labels={"trivy-operator-validation": "true"}
                        ),
                        rules=[k8s_client.V1RuleWithOperations(
                            api_groups=[""],
                            api_versions=["v1"],
                            operations=["CREATE"],
                            resources=["pods"],
                            scope="*"
                        )],
                        side_effects="None",
                        timeout_seconds=30
                    )]
                )
            pretty = 'true'
            field_manager = 'trivy-operator'
            try:
                api_response = api_instance.create_validating_webhook_configuration(
                    body, pretty=pretty, field_manager=field_manager)
            except ApiException as e:
                if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
                    logger.info(
                        "validating webhook configuration already exists!!!")
                else:
                    logger.error(
                        "Exception when calling AdmissionregistrationV1Api->create_validating_webhook_configuration: %s\n" % e)

#############################################################################

"""Admission Server Creation"""

if AC_ENABLED:
    @kopf.on.startup()
    def configure(settings: kopf.OperatorSettings, logger, **_):
        # Auto-detect the best server (K3d/Minikube/simple):
        if IN_CLUSTER:
            if IS_GLOBAL:
                logger.info("Start admission server")
                settings.admission.server = ServiceTunnel()
                # Automaticle create ValidatingWebhookConfiguration
                settings.admission.managed = 'trivy-image-validator.devopstales.io'
            else:
                logger.info("Loading cluster config")
                k8s_config.load_incluster_config()

                log_level_info_map = {'DEBUG': logging.DEBUG,
                                    'INFO': logging.INFO,
                                    'WARNING': logging.WARNING,
                                    'ERROR': logging.ERROR,
                                    }
                log_level = os.environ.get("LOG_LEVEL", "INFO")
                settings.posting.level = log_level_info_map.get(log_level, logging.INFO)

                namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")
                name = "trivy-image-validator"
                hostname = f"{name}.{namespace}.svc"
                cert_file = "/home/trivy-operator/trivy-cache/cert.pem"
                key_file = "/home/trivy-operator/trivy-cache/key.pem"

                if os.path.exists(cert_file):
                    certfile = open(cert_file).read()
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, certfile)
                    certExpires = datetime.strptime(
                        str(cert.get_notAfter(), "ascii"), "%Y%m%d%H%M%SZ")
                    daysToExpiration = (certExpires - datetime.now()).days
                    logger.info("Day to certifiacet expiration: %s" % daysToExpiration)  # infolog
                    if daysToExpiration <= 7:  # debug 365
                        MyLogger.info("Certificate Expires soon. Regenerating.")
                        # delete cert file
                        os.remove(cert_file)
                        os.remove(key_file)
                        # delete validating webhook configuration
                        with k8s_client.ApiClient() as api_client:
                            api_instance = k8s_client.AdmissionregistrationV1Api(
                                api_client)
                            name = 'trivy-image-validator.devopstales.io'
                            try:
                                api_response = api_instance.delete_validating_webhook_configuration(
                                    name)
                            except ApiException as e:
                                logger.error(
                                    "Exception when calling AdmissionregistrationV1Api->delete_validating_webhook_configuration: %s\n" % e)
                        # gen cert and vwc
                        gen_cert_and_vwc(logger, hostname, cert_file, key_file)
                else:
                    gen_cert_and_vwc(logger, hostname, cert_file, key_file)

                # Start Admission Server
                settings.admission.server = kopf.WebhookServer(
                    port=8443,
                    host=hostname,
                    certfile=cert_file,
                    pkeyfile=key_file
                )

        else:
            settings.admission.server = kopf.WebhookAutoServer(port=443)
            settings.admission.managed = 'trivy-image-validator.devopstales.io'


"""Admission Controller"""

if AC_ENABLED:
    @kopf.on.validate('pod', operation='CREATE')
    def validate1(logger, namespace, name, annotations, spec, **_):
        logger.info("Admission Controller is working")
        image_list = []
        vul_list = {}
        registry_list = []
        current_namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")

        """Try to get Registry auth values"""
        if IN_CLUSTER:
            k8s_config.load_incluster_config()
        else:
            k8s_config.load_kube_config()
        v1 = k8s_client.CoreV1Api()
        try:
            # if no namespace-scanners created
            nsScans = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                group="trivy-operator.devopstales.io",
                version="v1",
                plural="namespace-scanners",
            )           
            for nss in nsScans["items"]:
                if nss["spec"]["registry"]:
                    registry_list = nss["spec"]["registry"]
                if nss["spec"]['image_pull_secrets']:
                    secret_names = spec['image_pull_secrets']
                    for secret_name in secret_names:
                        try:
                            secret = v1.read_namespaced_secret(secret_name, current_namespace)
                            secret_data = secret.data['.dockerconfigjson']
                            data = json.loads(base64.b64decode(secret_data).decode("utf-8"))
                            registry_list.append(data['auths'])
                            logger.debug(format(data['auths'])) # debuglog
                        except ApiException as e:
                            logger.error("%s secret dose not exist in namespace %s" % (secret_name, current_namespace))
                            logger.debug("Exception when calling CoreV1Api->read_namespaced_secret: %s\n" % e) # debuglog
        except:
            logger.info("No ns-scan object created yet.")

        """Get conainers"""
        containers = spec.get('containers')
        initContainers = spec.get('initContainers')

        try:
            for icn in initContainers:
                initContainers_array = json.dumps(icn)
                initContainer = json.loads(initContainers_array)
                image_name = initContainer["image"]
                image_list.append(image_name)
        except:
            print("")

        try:
            for cn in containers:
                container_array = json.dumps(cn)
                container = json.loads(container_array)
                image_name = container["image"]
                image_list.append(image_name)
        except:
            print("containers is None")

        """Get Images"""
        for image_name in image_list:
            registry = image_name.split('/')[0]
            logger.info("Scanning Image: %s" % (image_name)) # info

            """Login to registry"""
            try:
                for reg in registry_list:
                    if reg.get(registry):
                        os.environ['DOCKER_REGISTRY'] = registry
                        os.environ['TRIVY_USERNAME'] = reg[registry]['username']
                        os.environ['TRIVY_PASSWORD'] = reg[registry]['password']
                        if var_test(reg[registry]['insecure']):
                            os.environ['TRIVY_INSECURE'] = "true"
                    elif not validators.domain(registry):
                        """If registry is not an url"""
                        if reg.get("docker.io"):
                            os.environ['DOCKER_REGISTRY'] = "docker.io"
                            os.environ['TRIVY_USERNAME'] = reg[registry]['username']
                            os.environ['TRIVY_PASSWORD'] = reg[registry]['password']
            except:
                logger.info("No registry auth config is defined.") # info
            ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
            logger.debug("Active Registry: %s" % (ACTIVE_REGISTRY)) # debuglog

            """Scan Images"""
            TRIVY = ["trivy", "-q", "image", "-f", "json"]
            if REDIS_ENABLED:
                TRIVY = TRIVY + TRIVY_REDIS
            if OFFLINE_ENABLED:
                TRIVY = TRIVY + TRIVY_OFFLINE
            TRIVY = TRIVY + [image_name]
            # --ignore-policy trivy.rego

            res = subprocess.Popen(
                TRIVY, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = res.communicate()
            if error:
                """Error Logging"""
                logger.error("TRIVY ERROR: return %s" % (res.returncode))
                if b"unknown tag" in error.strip():
                    logger.error("Repository: No tag in registry")
                elif b"401" in error.strip():
                    logger.error("Repository: Unauthorized authentication required")
                elif b"UNAUTHORIZED" in error.strip():
                    logger.error("Repository: Unauthorized authentication required")
                elif b"You have reached your pull rate limit." in error.strip():
                    logger.error("You have reached your pull rate limit.")
                elif b"unsupported MediaType" in error.strip():
                    logger.error(
                        "Unsupported MediaType: see https://github.com/google/go-containerregistry/issues/377")
                elif b"MANIFEST_UNKNOWN" in error.strip():
                    logger.error("No tag in registry")
                else:
                    logger.error("%s" % str(error.strip().decode("utf-8")))
                """Error action"""
                se = {"ERROR": 1}
                vul_list[image_name] = [se, namespace]

            elif output:
                trivy_result = json.loads(output.decode("UTF-8"))
                item_list = trivy_result['Results'][0]["Vulnerabilities"]
                vuls = {"UNKNOWN": 0, "LOW": 0,
                        "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
                for item in item_list:
                    vuls[item["Severity"]] += 1
                vul_list[image_name] = [vuls, namespace]

            """Generate log"""
            logger.info("severity: %s" % (vul_list[image_name][0]))  # info

            """Generate Metricfile"""
            for image_name in vul_list.keys():
                for severity in vul_list[image_name][0].keys():
                    AC_VULN.labels(vul_list[image_name][1], image_name, severity).set(
                        int(vul_list[image_name][0][severity]))
            # logger.info("Prometheus Done") # Debug

            # Get vulnerabilities from annotations
            vul_annotations = {"UNKNOWN": 0, "LOW": 0,
                            "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            for sev in vul_annotations:
                try:
                    #                logger.info("%s: %s" % (sev, annotations['trivy.security.devopstales.io/' + sev.lower()])) # Debug
                    vul_annotations[sev] = annotations['trivy.security.devopstales.io/' + sev.lower()]
                except:
                    continue

            # Check vulnerabilities
            # logger.info("Check vulnerabilities:") # Debug
            if "ERROR" in vul_list[image_name][0]:
                logger.error("Trivy can't scann the image")
                raise kopf.AdmissionError(
                    f"Trivy can't scan the image: %s" % (image_name))
            else:
                for sev in vul_annotations:
                    an_vul_num = vul_annotations[sev]
                    vul_num = vul_list[image_name][0][sev]
                    if int(vul_num) > int(an_vul_num):
                        #                    logger.error("%s is bigger" % (sev)) # Debug
                        raise kopf.AdmissionError(
                            f"Too much vulnerability in the image: %s" % (image_name))
                    else:
                        #                    logger.info("%s is ok" % (sev)) # Debug
                        continue

#############################################################################
# ClustereScanner
#############################################################################
@kopf.on.resume('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
async def startup_sc_deployer( logger, spec, **kwargs):
    logger.info("ClustereScanner Created")

    ds_name = "kube-bech-scanner"
    ds_image = "devopstales/kube-bench-scnner:2.5"
    pod_name = os.environ.get("POD_NAME")
    pod_uid = os.environ.get("POD_UID")
    namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")

    try:
        service_account = os.environ.get("SERVICE_ACCOUNT")
    except:
        service_account = None
        logger.info("ClustereScannerProfile is not configured")
        raise kopf.AdmissionError("ClustereScannerProfile is not configured")

    try:
        scan_profile = spec['scanProfileName']
        logger.info("ClustereScannerProfile is set to %s" % scan_profile)
    except:
        scan_profile = None
        logger.info("serviceAccountName is not in environment variables")

    daemonset = {
        "apiVersion": "apps/v1",
        "kind": "DaemonSet",
        "metadata": { 
            "name": ds_name, 
            "labels": { "app": ds_name },
            "annotations": { "prometheus.io/port": "9115", "prometheus.io/scrape": "true" }
        },
        "spec": {
            "selector": { "matchLabels": { "app": ds_name, } },
            "template": { 
                "metadata": { "labels": { "app": ds_name, } },
                "spec": { 
                    "hostPID": True,
                    "serviceAccountName": service_account,
                    "containers": [ {
                        "name": ds_name,
                        "image": ds_image,
                        "ports": [ { "containerPort": 9115 } ],
                        "env": [ { "name": "NODE_NAME", "valueFrom": { "fieldRef": { "fieldPath": "spec.nodeName" } } } ],
                    } ],
                },
            }
        },
    }

    if pod_name:
        daemonset['metadata']['ownerReferences'] = [ { "apiVersion": "v1", "kind": "Pod", "name": pod_name, "uid": pod_uid, "blockOwnerDeletion": False, "controller": True, } ]

    daemonset['spec']['template']['spec']['containers'][0]['volumeMounts'] = [
        { "name": "var-lib-etcd", "mountPath": "/var/lib/etcd", "readOnly": True },
        { "name": "var-lib-kubelet", "mountPath": "/var/lib/kubelet", "readOnly": True },
        { "name": "var-lib-kube-scheduler", "mountPath": "/var/lib/kube-scheduler", "readOnly": True },
        { "name": "var-lib-kube-controller-manager", "mountPath": "/var/lib/kube-controller-manager", "readOnly": True },
        { "name": "etc-systemd", "mountPath": "/etc/systemd", "readOnly": True },
        { "name": "lib-systemd", "mountPath": "/lib/systemd/", "readOnly": True },
        { "name": "srv-kubernetes", "mountPath": "/srv/kubernetes/", "readOnly": True },
        { "name": "etc-kubernetes", "mountPath": "/etc/kubernetes", "readOnly": True },
        { "name": "usr-bin", "mountPath": "/usr/local/mount-from-host/bin", "readOnly": True },
        { "name": "etc-cni-netd", "mountPath": "/etc/cni/net.d/", "readOnly": True },
        { "name": "opt-cni-bin", "mountPath": "/opt/cni/bin/", "readOnly": True },
        { "name": "etc-passwd", "mountPath": "/etc/passwd", "readOnly": True },
        { "name": "etc-group", "mountPath": "/etc/group", "readOnly": True },
    ]
    daemonset['spec']['template']['spec']['volumes'] = [
        { "name": "var-lib-etcd", "hostPath": { "path": "/var/lib/etcd" } },
        { "name": "var-lib-kubelet", "hostPath": { "path": "/var/lib/kubelet" } },
        { "name": "var-lib-kube-scheduler", "hostPath": { "path": "/var/lib/kube-scheduler" } },
        { "name": "var-lib-kube-controller-manager", "hostPath": { "path": "/var/lib/kube-controller-manager" } },
        { "name": "etc-systemd", "hostPath": { "path": "/etc/systemd" } },
        { "name": "lib-systemd", "hostPath": { "path": "/lib/systemd" } },
        { "name": "srv-kubernetes", "hostPath": { "path": "/srv/kubernetes" } },
        { "name": "etc-kubernetes", "hostPath": { "path": "/etc/kubernetes" } },
        { "name": "usr-bin", "hostPath": { "path": "/usr/bin" } },
        { "name": "etc-cni-netd", "hostPath": { "path": "/etc/cni/net.d/" } },
        { "name": "opt-cni-bin", "hostPath": { "path": "/opt/cni/bin/" } },
        { "name": "etc-passwd", "hostPath": { "path": "/etc/passwd" } },
        { "name": "etc-group", "hostPath": { "path": "/etc/group" } },
    ]

    """Test daemonset"""
    def test_daemonset_exists(namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.AppsV1Api(api_client)
        try:
            api_response = api_instance.read_namespaced_daemon_set(
                name, namespace )
            return True
        except ApiException as e:
            if e.status != 404:
                logger.error("Exception when testing daemonset - %s : %s\n" % (name, e))
                return False
            else:
                return False

    """Generate daemonset"""
    def create_daemonset(body, namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.AppsV1Api(api_client)
            pretty = 'true'
            field_manager = 'trivy-operator'
            body = body
            namespace = namespace
        try:
            api_response = api_instance.create_namespaced_daemon_set(
                namespace, body, pretty=pretty,  field_manager=field_manager)
        except ApiException as e:
            if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
                logger.info("daemonset %s already exists!!!" % name)
            else:
                logger.error("Exception when creating daemonset - %s : %s\n" % (name, e))

    is_daemonset_exists = test_daemonset_exists(namespace, ds_name)

    if is_daemonset_exists:
        logger.info("daemonset already exists") # WARNING
    else:
        create_daemonset(daemonset, namespace, ds_name)

@kopf.on.delete('trivy-operator.devopstales.io', 'v1', 'cluster-scanners')
async def startup_sc_deleter( logger, spec, **kwargs):
    ds_name = "kube-bech-scanner"
    namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")

    """Test daemonset"""
    def test_daemonset_exists(namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.AppsV1Api(api_client)
        try:
            api_response = api_instance.read_namespaced_daemon_set(
                name, namespace )
            return True
        except ApiException as e:
            if e.status != 404:
                logger.error("Exception when testing daemonset - %s : %s\n" % (name, e))
                return False
            else:
                return False

    """Delete daemonset"""
    def delete_daemonset(namespace, name):
        with k8s_client.ApiClient() as api_client:
            api_instance = k8s_client.AppsV1Api(api_client)
        try:
            api_response = api_instance.delete_namespaced_daemon_set(
                name, namespace)
        except ApiException as e:
            logger.error("Exception when deleting daemonset - %s : %s\n" % (name, e))

    is_daemonset_exists = test_daemonset_exists(namespace, ds_name)

    if is_daemonset_exists:
        delete_daemonset(namespace, ds_name)
    else:
        logger.info("daemonset dose not exists: nothing to delete") # WARNING

#############################################################################
# print to operator log
# print(f"And here we are! Creating: %s" % (ns_name), file=sys.stderr) # debug
# message to CR
#    return {'message': 'hello world'}  # will be the new status
# events to CR describe
# kopf.event(body, type="SomeType", reason="SomeReason", message="Some message")
