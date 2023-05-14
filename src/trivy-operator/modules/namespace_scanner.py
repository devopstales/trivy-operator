import subprocess, json, base64, kopf, os, validators, requests, uuid
import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException
from datetime import datetime, timezone

from modules.get_variables import (
    OFFLINE_ENABLED,
    DB_REPOSITORY,
    REDIS_ENABLED,
    TRIVY_REDIS,
    TRIVY_OFFLINE,
    IN_CLUSTER,
    CURRENT_NAMESPACE,
)
from modules.prometheus import (
    CONTAINER_VULN,
    CONTAINER_VULN_SUM,
)
from modules.timer import get_crontab, getNextCronRunTime, roundDownTime, sleepTillTopOfNextMinute, getCurretnTime
from modules.helper_functions import var_test

def trivy_cache_download(logger):
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

#############################################################################
# Namespace Scanner helpers
#############################################################################

def test_secret_names(logger, spec):
    try:
        secret_names = spec['image_pull_secrets']
        secret_names_present = True
        logger.debug("image_pull_secrets:") # DEBUG-LOG
    except:
        secret_names_present = False
        logger.warning("image_pull_secrets is not set")
    return secret_names_present, secret_names

def test_scan_selectors(logger, spec):
    try:
        clusterWide = var_test(spec['clusterWide'])
        logger.debug("namespace-scanners - clusterWide:") # DEBUG-LOG
        logger.debug(format(clusterWide)) # DEBUG-LOG
    except:
        logger.warning("clusterWide is not set, checking namespaceSelector")
        clusterWide = None

    try:
        namespaceSelector = spec['namespace_selector']
        logger.debug("namespace-scanners - namespace_selector:") # DEBUG-LOG
        logger.debug(format(namespaceSelector)) # DEBUG-LOG
    except:
        logger.warning("namespace_selector is not set")
        namespaceSelector = None

    if clusterWide is None and namespaceSelector is None:
        logger.error("Either clusterWide need to be set to 'true' or namespace_selector should be set")
        raise kopf.PermanentError("Either clusterWide need to be set to 'true' or namespace_selector should be set")
    
    return clusterWide, namespaceSelector

"""Get auth data from pull secret"""
def pull_secret_decoder(logger, spec, secret_names, secret_namespace):
    v1 = k8s_client.CoreV1Api()
    try:
        registry_list = spec['registry']
        logger.debug("Get registry auth config.") # DEBUG-LOG
    except:
        registry_list = list()
        logger.debug("Can't get registry auth config.") # DEBUG-LOG

    for secret_name in secret_names:
        try:
            secret = v1.read_namespaced_secret(secret_name, secret_namespace)
            if '.dockerconfigjson' in secret.data:
                secret_data = secret.data['.dockerconfigjson']
                data = json.loads(base64.b64decode(secret_data).decode("utf-8"))
                registry_list.append(data['auths'])
                logger.debug(format(data['auths'])) # DEBUG-LOG
            elif '.dockercfg' in secret.data:
                secret_data = secret.data['.dockercfg']
                data = json.loads(base64.b64decode(secret_data).decode("utf-8"))
                registry_list.append(data)
                logger.debug(format(data)) # DEBUG-LOG
            else:
                logger.error("Unknown pull secret format")
                logger.debug(format(secret.data)) # DEBUG-LOG
        except ApiException as e:
            logger.error("%s secret dose not exist in namespace %s" % (secret_name, secret_namespace))
            logger.debug("Exception when calling CoreV1Api->read_namespaced_secret: %s\n" % e) # DEBUG-LOG
    return registry_list

def get_namespaces(logger, spec):
    CLUSTERWIDE, NAMESPACE_SELECTOR = test_scan_selectors(logger, spec)
    tagged_ns_list = []

    """Find Namespaces"""
    namespace_list = k8s_client.CoreV1Api().list_namespace()
    logger.debug("namespace list begin:") # DEBUG-LOG
    logger.debug(format(namespace_list)) # DEBUG-LOG
    logger.debug("namespace list end:") # DEBUG-LOG

    for ns in namespace_list.items:
        try:
            ns_label_list = ns.metadata.labels.items()
            ns_name = ns.metadata.name
        except Exception as e:
            logger.error(str(e))

        """Find Namespaces with selector tag"""
        logger.debug("labels and namespace begin") # DEBUG-LOG
        logger.debug(format(ns_label_list)) # DEBUG-LOG
        logger.debug(format(ns_name)) # DEBUG-LOG
        logger.debug("labels and namespace end") # DEBUG-LOG
        for label_key, label_value in ns_label_list:
            if CLUSTERWIDE or (NAMESPACE_SELECTOR == label_key and bool(label_value) == True):
                logger.info("Select Namespace: %s" % ns_name)
                tagged_ns_list.append(ns_name)
            else:
                continue
    return tagged_ns_list

def get_image_from_containers(logger, containers, pod_uid, pod_name, tagged_ns):
    pod_list = {}
    unique_image_list = {}
    try:
        for image in containers:
            pod_name += '_'
            pod_name += image.name
            pod_list[pod_name] = list()
            image_name_temp = image.image
            image_id = image.image_id
            if image_name_temp.startswith('sha256'):
                image_name = image_id
            else:
                image_name = image_name_temp
            pod_list[pod_name].append(image_name)
            pod_list[pod_name].append(image_id)
            pod_list[pod_name].append(tagged_ns)
            pod_list[pod_name].append(pod_uid)

            unique_image_list[image_name] = image_name
            logger.debug("containers begin:") # DEBUG-LOG
            logger.debug(format(pod_name)) # DEBUG-LOG
            logger.debug(format(pod_list[pod_name])) # DEBUG-LOG
            logger.debug("containers end:") # DEBUG-LOG
    except:
        logger.info('containers Type is None')
    return pod_list, unique_image_list

def get_images_from_pods(logger, tagged_ns_list):
    pod_list = {}
    unique_image_list = {}
    """Find pods in namespaces"""
    for tagged_ns in tagged_ns_list:
        namespaced_pod_list = k8s_client.CoreV1Api().list_namespaced_pod(tagged_ns)
        """Find images in pods"""
        for pod in namespaced_pod_list.items:
            containers = pod.status.container_statuses
            pod_uid = pod.metadata.uid
            pod_name = pod.metadata.name
            if pod.spec.image_pull_secrets is not None:
                for item in pod.spec.image_pull_secrets:
                    tmp = str(item)
                    tmp = tmp.replace("\'", "\"")
                    tmp2 = json.loads(tmp)
                    tmp3 = [tmp2.get('name')]
                    pull_secret_decoder(tmp3, tagged_ns)


            initContainers = pod.status.init_container_statuses
            container_pod_list, container_unique_image_list = get_image_from_containers(logger, containers, pod_uid, pod_name, tagged_ns)
            pod_list.update(container_pod_list)
            unique_image_list.update(container_unique_image_list)

            init_container_pod_list, init_container_unique_image_list = get_image_from_containers(logger, initContainers, pod_uid, pod_name, tagged_ns)
            pod_list.update(init_container_pod_list)
            unique_image_list.update(init_container_unique_image_list)

    return unique_image_list, pod_list

def configure_registry_auth(logger, registry_list, current_registry):
    for reg in registry_list:
        if  reg.get(current_registry):
            os.environ['DOCKER_REGISTRY'] = current_registry
            os.environ['TRIVY_USERNAME'] = reg[current_registry]['username']
            os.environ['TRIVY_PASSWORD'] = reg[current_registry]['password']
            if var_test(reg[current_registry]['insecure']):
                os.environ['TRIVY_INSECURE'] = "true"
        elif not validators.domain(current_registry):
            """If registry is not an url"""
            if reg.get("docker.io"):
                os.environ['DOCKER_REGISTRY'] = "docker.io"
                os.environ['TRIVY_USERNAME'] = reg['docker.io']['username']
                os.environ['TRIVY_PASSWORD'] = reg['docker.io']['password']
        ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
        logger.info("Active Registry: %s" % (ACTIVE_REGISTRY))

def trivy_scan_error_handler(logger, error, res, image_name):
    trivy_result_list = {}
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
    return trivy_result_list

def test_detect_dojo_vars(logger, spec):
    try:
        defectdojo_host = spec['integrations']['defectdojo']['host']
        defectdojo_api_key = spec['integrations']['defectdojo']['api_key']
        logger.info("defectdojo integration is configured")
        logger.debug("namespace-scanners integrations - defectdojo:") # debuglog
        logger.debug("host: " % format(defectdojo_host)) # debuglog
        logger.debug("api_key: " % format(defectdojo_api_key)) # debuglog
    except:
        defectdojo_host = None
        defectdojo_api_key = None
        logger.info("defectdojo integration is not set")
    return defectdojo_host, defectdojo_api_key

def push_to_DefectDojo(logger, spec, output, image_name):
    """DefectDojo Integration"""
    defectdojo_host, defectdojo_api_key = test_detect_dojo_vars(logger, spec)
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

def get_image_vulnerability(logger, spec, unique_image_list, registry_list):
    """Scan images"""
    logger.info("image list begin:") 
    for image_name in unique_image_list:
        logger.info("Scanning Image: %s" % (image_name))

        registry = image_name.split('/')[0]
        configure_registry_auth(logger, registry_list, registry)

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
            trivy_result_list = trivy_scan_error_handler(logger, error, res, image_name)
        elif output:
            trivy_result = json.loads(output.decode("UTF-8"))
            trivy_result_list[image_name] = trivy_result
            push_to_DefectDojo(logger, spec, output, image_name)
    logger.info("image list end:")
    return trivy_result_list

def generate_vul_report(pod_name, trivy_result):
    vul_report = {}
    vul_report[pod_name] = []
    if list(trivy_result.keys())[0] == "ERROR":
        vuls_long = {
            "installedVersion": "",
            "fixedVersion": "",
            "links": [],
            "primaryLink": "",
            "resource": "",
            "score": 0,
            "severity": "ERROR",
            "title": "Image Scanning Error",
            "vulnerabilityID": "",
            "publishedDate": "",
        }
        vul_report[pod_name] += [vuls_long]
    else:
        if 'Results' in trivy_result and 'Vulnerabilities' in trivy_result['Results'][0]:
            item_list = trivy_result['Results'][0]["Vulnerabilities"]
            for item in item_list:
                try:
                    title = item["Title"]
                except:
                    title = item["Description"]
                try:
                    score = item["CVSS"]["nvd"]["V3Score"]
                except:
                    try:
                        score = item["CVSS"]["redhat"]["V3Score"]
                    except:
                        score = 0
                try:
                    fixed_version = item["FixedVersion"]
                except:
                    fixed_version = ""
                try:
                    pLink = item["PrimaryURL"]
                except:
                    pLink = ""
                try:
                    refLink =  item["References"]
                except:
                    refLink = []
                try:
                    published_date = item["PublishedDate"]
                except:
                    published_date = ""
                vuls_long = {
                    "vulnerabilityID": item["VulnerabilityID"],
                    "resource": item["PkgName"],
                    "installedVersion": item["InstalledVersion"],
                    "fixedVersion": fixed_version,
                    "primaryLink": pLink,
                    "severity": item["Severity"],
                    "score": score,
                    "links": refLink,
                    "title": title,
                    "publishedDate": published_date
                }
                vul_report[pod_name] += [vuls_long]
        elif 'Results' in trivy_result and 'Vulnerabilities' not in trivy_result['Results'][0]:
            vuls_long = {
                "installedVersion": "",
                "fixedVersion": "",
                "links": [],
                "primaryLink": "",
                "resource": "",
                "score": 0,
                "severity": "NONE",
                "title": "There ins no vulnerability in this image",
                "vulnerabilityID": "",
                "publishedDate": "",
            }
            vul_report[pod_name] += [vuls_long]
    return vul_report

def generate_policy_report(trivy_result, ns_name, pod_name, pod_uid, image_name):
    policy_report = {}
    policy_report[pod_name] = []

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

    if list(trivy_result.keys())[0] == "ERROR":
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
        policy_report[pod_name] += [report]
    else:
        if 'Results' in trivy_result and 'Vulnerabilities' in trivy_result['Results'][0]:
            item_list = trivy_result['Results'][0]["Vulnerabilities"]
            for item in item_list:
                try:
                    title = item["Title"]
                except:
                    title = item["Description"]
                try:
                    score = item["CVSS"]["nvd"]["V3Score"]
                except:
                    try:
                        score = item["CVSS"]["redhat"]["V3Score"]
                    except:
                        score = 0
                try:
                    fixed_version = item["FixedVersion"]
                except:
                    fixed_version = ""
                try:
                    pLink = item["PrimaryURL"]
                except:
                    pLink = ""
                try:
                    refLink =  item["References"]
                except:
                    refLink = []
                try:
                    published_date = item["PublishedDate"]
                except:
                    published_date = ""
                if "CRITICAL" or "HIGH" in item["Severity"]:
                    result = "fail"
                    severity = item["Severity"]
                if "MEDIUM" or "LOW" in item["Severity"]:
                    result = "warn"
                    severity = item["Severity"]
                if "UNKNOWN" in item["Severity"]:
                    result = "skip"
                    severity = "INFO" 
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
                        "fixedVersion": fixed_version,
                        "resultID": str(uuid.uuid4()),
                        "publishedDate": published_date
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
                policy_report[pod_name] += [report]
        elif 'Results' in trivy_result and 'Vulnerabilities' not in trivy_result['Results'][0]:
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
            policy_report[pod_name] += [report]
    return policy_report

def get_pod_vuln_list(logger, pod_name, trivy_result, ns_name, image_name, pod_uid):
    vul_list = {}
    if list(trivy_result.keys())[0] == "ERROR":
        vuls = {"UNKNOWN": 0, "LOW": 0,
                    "MEDIUM": 0, "HIGH": 0,
                    "CRITICAL": 0, "ERROR": 1,
                    "NONE": 0}           
        vul_list[pod_name] = [vuls, ns_name, image_name, pod_uid]
    else:
        if 'Results' in trivy_result and 'Vulnerabilities' in trivy_result['Results'][0]:
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
                
            vul_list[pod_name] = [vuls, ns_name, image_name, pod_uid]
        elif 'Results' in trivy_result and 'Vulnerabilities' not in trivy_result['Results'][0]:
            logger.debug("if trivy_result has no Vulnerabilities:")
            # For Alpine Linux
            vuls = {"UNKNOWN": 0, "LOW": 0,
                    "MEDIUM": 0, "HIGH": 0,
                    "CRITICAL": 0, "ERROR": 0,
                    "NONE": 1}
            vul_list[pod_name] = [vuls, ns_name, image_name, pod_uid]
    return vul_list

def map_vuln_to_pods(logger, trivy_result_list, pod_list):
    vul_report = {}
    policy_report = {}
    vul_list = {}
    for pod_name in pod_list:
        image_name = pod_list[pod_name][0]
        image_id = pod_list[pod_name][1]
        ns_name = pod_list[pod_name][2]
        pod_uid = pod_list[pod_name][3]

        trivy_result = trivy_result_list[image_name]
        vul_report = generate_vul_report(pod_name, trivy_result)
        policy_report = generate_policy_report(trivy_result, ns_name, pod_name, pod_uid, image_name)
        vul_list = get_pod_vuln_list(logger, pod_name, trivy_result, ns_name, image_name, pod_uid)
    return vul_report, policy_report, vul_list

"""Test VulnerabilityReport"""
def get_vulnerabilityreports(logger, namespace, name):
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
def delete_vulnerabilityreports(logger, namespace, name):
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

"""Generate VulnerabilityReport"""
def create_vulnerabilityreports(logger, body, namespace, name):
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
        logger.info("New vulnerabilityReport created") # WARNING
    except ApiException as e:
        if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
            logger.info("VulnerabilityReport %s already exists!!!" % name)
        else:
            logger.error("Exception when creating VulnerabilityReport - %s : %s\n" % (name, e))

def generate_vuln_report(logger, vul_list, vul_report):
    date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%sZ")
    for pod_name in vul_list.keys():
        vuls = vul_list[pod_name][0]
        namespace = vul_list[pod_name][1]
        image = vul_list[pod_name][2]
        pod_uid = vul_list[pod_name][3]

        vr_name = f"pod-{pod_name.split('_')[0]}-container-{pod_name.split('_')[1]}"

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
        is_vulnerabilityreport_exists = get_vulnerabilityreports(logger, namespace, vr_name)
        logger.info("DEBUG - is_vulnerabilityreport_exists: %s" % is_vulnerabilityreport_exists)

        if is_vulnerabilityreport_exists:
            logger.info("vulnerabilityReport need deletion") # WARNING
            delete_vulnerabilityreports(logger, namespace, vr_name)
            create_vulnerabilityreports(logger, vulnerabilityReport, namespace, vr_name)
        else:
            create_vulnerabilityreports(logger, vulnerabilityReport, namespace, vr_name)

"""Test policyReport"""
def get_policyreports(logger, namespace, name):
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
def create_policyreports(logger, body, namespace, name):
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
        logger.info("New policyReport created") # WARNING
    except ApiException as e:
        if e.status == 409:  # if the object already exists the K8s API will respond with a 409 Conflict
            logger.info("policyReport %s already exists!!!" % name)
        else:
            logger.error("Exception when creating policyReport - %s : %s\n" % (name, e))

"""Delete policyReport"""
def delete_policyreports(logger, namespace, name):
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

def generate_policy_report(logger, spec, vul_list, policy_report):
    try:
        policyreport_enabled = var_test(spec['integrations']['policyreport'])
        logger.info("policyreport integration is configured")
        logger.debug("namespace-scanners integrations - policyreport:") # debuglog
        logger.debug(format(policyreport)) # debuglog
    except:
        logger.info("policyreport integration is not set")
        policyreport = False

    if policyreport_enabled:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%sZ")
        for pod_name in vul_list.keys():
            vuls = vul_list[pod_name][0]
            namespace = vul_list[pod_name][1]
            image = vul_list[pod_name][2]
            pod_uid = vul_list[pod_name][3]

            vr_name = f"pod-{pod_name.split('_')[0]}-container-{pod_name.split('_')[1]}"
            criticalCount = vuls['CRITICAL']
            highCount = vuls['HIGH']
            mediumCount = vuls['MEDIUM']
            lowCount = vuls['LOW']
            unknownCount = vuls['UNKNOWN']

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

            is_policyreports_exists = get_policyreports(namespace, pr_name)

            if is_policyreports_exists:
                logger.info("policyReport need deletion") # WARNING
                delete_policyreports(logger, namespace, pr_name)
                create_policyreports(logger, policyReport, namespace, pr_name)
            else:
                logger.error("policyreport dose not exists")
                create_policyreports(logger, policyReport, namespace, pr_name)


#############################################################################
# Namespace Scanner
#############################################################################

def namespace_scanner(logger, spec):
    logger.info(f"NamespaceScanner Created in {CURRENT_NAMESPACE} namespace")
    secret_names_present, secret_names = test_secret_names(logger, spec)
    crontab = get_crontab(logger,spec)

    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    if secret_names_present:
        registry_list = pull_secret_decoder(logger, spec, secret_names, CURRENT_NAMESPACE)

    """start crontab"""
    nextRunTime = getNextCronRunTime(logger, spec)
    while True:
        roundedDownTime = roundDownTime()
        if (roundedDownTime == nextRunTime):
            ns_list = get_namespaces(logger, spec)
            image_list, pod_list = get_images_from_pods(logger, ns_list)
            vuln_list = get_image_vulnerability(logger, spec, image_list, registry_list)
            vul_report, policy_report, vul_list = map_vuln_to_pods(logger, vuln_list, pod_list)
            generate_vuln_report(logger, vul_list, vul_report)
            generate_policy_report(logger, spec, vul_list, policy_report)

            """Generate Metricfile"""
            for pod_name in vul_list.keys():
                for severity in vul_list[pod_name][0].keys():
                    CONTAINER_VULN_SUM.labels(
                        vul_list[pod_name][1],
                        vul_list[pod_name][2], severity).set(int(vul_list[pod_name][0][severity])
                                                  )
            now = getCurretnTime()
            logger.debug("CRON RUN: %s" % now) # WARNING
            nextRunTime = getNextCronRunTime(crontab)

        elif (roundedDownTime > nextRunTime):
            # We missed an execution. Error. Re initialize.
            now = getCurretnTime()
            logger.debug("MISSED RUN: %s" % now) # WARNING
            nextRunTime = getNextCronRunTime(crontab)
        
        sleepTillTopOfNextMinute()