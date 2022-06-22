import kopf
import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException
import logging
import prometheus_client
import asyncio
import pycron
import os
import sys
import subprocess
import json
import validators
import base64
from typing import AsyncIterator, Optional, Tuple, Collection
from datetime import datetime
from OpenSSL import crypto
from datetime import datetime, timezone
import logging

#############################################################################
# Logging
#############################################################################

VERBOSE_LOG = os.getenv("VERBOSE_LOG", False) in ('true', '1', 'True', 't', 'yes', 'Yes')
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
IN_CLUSTER = os.getenv("IN_CLUSTER", False) in ('true', '1', 'True', 't', 'yes', 'Yes')
IS_GLOBAL = os.getenv("IS_GLOBAL", False) in ('true', '1', 'True', 't', 'yes', 'Yes')
AC_ENABLED = os.getenv("ADMISSION_CONTROLLER", False) in ('true', '1', 'True', 't', 'yes', 'Yes')
REDIS_ENABLED = os.getenv("REDIS_ENABLED", False) in ('true', '1', 'True', 't', 'yes', 'Yes')
if REDIS_ENABLED:
    REDIS_BACKEND = os.getenv("REDIS_BACKEND")
    if not REDIS_BACKEND:
        REDIS_ENABLED = False

        MyLogger.warning("Redis Cache Disabled: %s" % (REDIS_BACKEND))
    else:
        MyLogger.warning("Redis Cache Enabled: %s" % (REDIS_BACKEND))

#############################################################################
# Pretasks
#############################################################################

"""Download trivy cache """

@kopf.on.startup()
async def startup_fn_trivy_cache(logger, **kwargs):
    if REDIS_ENABLED:
        TRIVY_CACHE = ["trivy", "-q", "image", "--cache-backend", REDIS_BACKEND, "--download-db-only"]
    else:
        TRIVY_CACHE = ["trivy", "-q", "image", "--download-db-only"]
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

"""Scanner Creation"""

@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'namespace-scanners')
async def create_fn( logger, spec, **kwargs):
    logger.info("NamespaceScanner Created")

    try:
        crontab = spec['crontab']
        logger.debug("namespace-scanners - crontab:") # debuglog
        logger.debug(format(crontab)) # debuglog
    except:
        logger.error("crontab must be set !!!")
        raise kopf.PermanentError("crontab must be set")

    clusterWide = None
    try:
        clusterWide = bool(spec['clusterWide'])
        logger.debug("namespace-scanners - clusterWide:") # debuglog
        logger.debug(format(clusterWide)) # debuglog
    except:
        logger.info("clusterWide is not set, checking namespaceSelector")
        clusterWide = False

    namespaceSelector = None
    try:
        namespaceSelector = spec['namespace_selector']
        logger.debug("namespace-scanners - namespace_selector:") # debuglog
        logger.debug(format(namespaceSelector)) # debuglog
    except:
        logger.info("namespace_selector is not set")

    if clusterWide == False and namespaceSelector is None:
        logger.error("Either clusterWide need to be set to 'true' or namespace_selector should be set")
        raise kopf.PermanentError("Either clusterWide need to be set to 'true' or namespace_selector should be set")

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
                print("Exception when creating VulnerabilityReport - %s : %s\n" % (name, e))

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
            MyLogger.info("api_response: %s" % api_response) # WARNING
            return True
        except ApiException as e:
            if e.status != 404:
                print("Exception when testing VulnerabilityReport - %s : %s\n" % (name, e))
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
            print("Exception when deleting VulnerabilityReport - %s : %s\n" % (name, e))

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
            MyLogger.info("api_response: %s" % api_response) # WARNING
            return True
        except ApiException as e:
            if e.status != 404:
                print("Exception when testing policyReport - %s : %s\n" % (name, e))
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
                print("Exception when creating policyReport - %s : %s\n" % (name, e))

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
            print("Exception when deleting policyReport - %s : %s\n" % (name, e))

    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    ############################################
    # start crontab
    ############################################

    while True:
        if pycron.is_now(crontab):
            """Find Namespaces"""
            unique_image_list = {}
            pod_list = {}
            trivy_result_list = {}
            vul_list = {}
            vul_report = {}
            tagged_ns_list = []
            policy_report = {}

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
                        tagged_ns_list.append(ns_name)
                    else:
                        continue

            """Find pods in namespaces"""
            for tagged_ns in tagged_ns_list:
                namespaced_pod_list = k8s_client.CoreV1Api().list_namespaced_pod(tagged_ns)
                """Find images in pods"""
                for pod in namespaced_pod_list.items:
                    containers = pod.status.container_statuses
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
                try:
                    registry_list = spec['registry']

                    for reg in registry_list:
                        if reg['name'] == registry:
                            os.environ['DOCKER_REGISTRY'] = reg['name']
                            os.environ['TRIVY_USERNAME'] = reg['user']
                            os.environ['TRIVY_PASSWORD'] = reg['password']
                        elif not validators.domain(registry):
                            """If registry is not an url"""
                            if reg['name'] == "docker.io":
                                os.environ['DOCKER_REGISTRY'] = reg['name']
                                os.environ['TRIVY_USERNAME'] = reg['user']
                                os.environ['TRIVY_PASSWORD'] = reg['password']
                except:
                    logger.debug("No registry auth config is defined.") # debug
                    ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
                    logger.info("Active Registry: %s" % (ACTIVE_REGISTRY))

                if REDIS_ENABLED:
                    TRIVY = ["trivy", "-q", "image", "-f", "json", "--cache-backend", REDIS_BACKEND, image_name]
                else:
                    TRIVY = ["trivy", "-q", "image", "-f", "json", image_name]
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
                    elif b"UNAUTHORIZED" in error.strip():
                        logger.error(
                            "Repository: Unauthorized authentication required")
                    elif b"You have reached your pull rate limit." in error.strip():
                        logger.error("You have reached your pull rate limit.")
                    elif b"unsupported MediaType" in error.strip():
                        logger.error(
                            "Unsupported MediaType: see https://github.com/google/go-containerregistry/issues/377")
                    elif b"MANIFEST_UNKNOWN: manifest unknown; map[Tag:latest]" in error.strip():
                        logger.error("No tag in registry")
                    else:
                        logger.error("%s" % (error.strip()))
                    """Error action"""
                    trivy_result_list[image_name] = "ERROR"
                elif output:
                    trivy_result = json.loads(output.decode("UTF-8"))
                    trivy_result_list[image_name] = trivy_result
            logger.info("image list end:")

            MyLogger.info("result begin:") # WARNING
            for pod_name in pod_list:
                image_name = pod_list[pod_name][0]
                image_id = pod_list[pod_name][1]
                ns_name = pod_list[pod_name][2]
                pod_uid = pod_list[pod_name][3]
                logger.debug("Assigning scanning result for Pod: %s - %s" % (pod_name, image_name)) # debuglog

                trivy_result = trivy_result_list[image_name]
                #logger.debug(trivy_result) # debug
                vul_report[pod_name] = []
                policy_report[pod_name] = []
                if trivy_result == "ERROR":
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
                    report = {
                        "category": "Vulnerability Scan",
                        "message": "Image Scanning Error",
                        "policy": "Image Vulnerability",
                        "rule": item["VulnerabilityID"],
                        "properties": {
                            "registry.server": image_name.split('/')[0],
                            "artifact.repository": image_name.split('/')[1] + "/" + image_name.split('/')[2].split(':')[0],,
                            "artifact.tag": image_name.split(':')[-1],
                        },
                        "resources": [],
                        "severity": "error",
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

                            if "CRITICAL" or "HIGH" in item["Severity"]:
                                result = "fail"
                            elif "MEDIUM" or "LOW" in item["Severity"]:
                                result = "warn"
                            elif "UNKNOWN" in item["Severity"]:
                                result = "skip"

                            vuls_long = {
                                "vulnerabilityID": item["VulnerabilityID"],
                                "resource": item["PkgName"],
                                "installedVersion": item["InstalledVersion"],
                                "primaryLink": pLink,
                                "severity": item["Severity"],
                                "score": score,
                                "links": item["References"],
                                "title": title,
                            }
                            report = {
                                "category": "Vulnerability Scan",
                                "message": title,
                                "policy": "Image Vulnerability",
                                "rule": item["VulnerabilityID"],
                                "properties": {
                                    "registry.server": image_name.split('/')[0],
                                    "artifact.repository": image_name.split('/')[1] + "/" + image_name.split('/')[2].split(':')[0],,
                                    "artifact.tag": image_name.split(':')[-1],
                                    "resource": item["PkgName"],
                                    "score": str(score),
                                    "primaryLink": item["PrimaryURL"],
                                    "installedVersion": item["InstalledVersion"],
                                },
                                "resources": [],
                                "severity": item["Severity"].lower(),
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
                            "rule": item["VulnerabilityID"],
                            "properties": {
                                "registry.server": image_name.split('/')[0],
                                "artifact.repository": image_name.split('/')[1] + "/" + image_name.split('/')[2].split(':')[0],,
                                "artifact.tag": image_name.split(':')[-1],
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

                image_registry = image.split('/')[0]
                image_part_name = image.split('/', 1)[1]
                image_name = image_part_name.split(':')[0]
                image_tag = image.split(':')[1]

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

                MyLogger.info("Generate VR begin:") # DEBUG!
                MyLogger.info(pod_name) # DEBUG!
                logger.debug(vul_list[pod_name]) # debug
                MyLogger.info("Generate VR end:") # DEBUG!

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
                    policy_report[pod_name]["rule"] = ""
                policyReport["results"] = policy_report[pod_name]

                is_vulnerabilityreport_exists = get_vulnerabilityreports(namespace, vr_name)
                MyLogger.info("DEBUG - is_vulnerabilityreport_exists: %s" % is_vulnerabilityreport_exists) # WARNING

                if is_vulnerabilityreport_exists:
                    MyLogger.info("vulnerabilityReport need deletion") # WARNING
                    delete_vulnerabilityreports(namespace, vr_name)
                    create_vulnerabilityreports(vulnerabilityReport, namespace, vr_name)
                else:
                    create_vulnerabilityreports(vulnerabilityReport, namespace, vr_name)

                is_policyreports_exists = get_policyreports(namespace, pr_name)
                MyLogger.info("DEBUG - is_policyreports_exists: %s" % is_policyreports_exists) # WARNING

                if is_policyreports_exists:
                    MyLogger.info("policyReport need deletion") # WARNING
                    delete_policyreports(namespace, pr_name)
                    create_policyreports(policyReport, namespace, pr_name)
                else:
                    create_policyreports(policyReport, namespace, pr_name)


            """Generate Metricfile"""
            for pod_name in vul_list.keys():
                for severity in vul_list[pod_name][0].keys():
                    CONTAINER_VULN_SUM.labels(
                        vul_list[pod_name][1],
                        vul_list[pod_name][2], severity).set(int(vul_list[pod_name][0][severity])
                                                  )
            MyLogger.info("------------------------------------------") # WARNING
            await asyncio.sleep(15)
        else:
            await asyncio.sleep(15)

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
        registry_list = {}

        """Try to get Registry auth values"""
        if IN_CLUSTER:
            k8s_config.load_incluster_config()
        else:
            k8s_config.load_kube_config()
        try:
            # if no namespace-scanners created
            nsScans = k8s_client.CustomObjectsApi().list_cluster_custom_object(
                group="trivy-operator.devopstales.io",
                version="v1",
                plural="namespace-scanners",
            )
            for nss in nsScans["items"]:
                registry_list = nss["spec"]["registry"]
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
                    if reg['name'] == registry:
                        os.environ['DOCKER_REGISTRY'] = reg['name']
                        os.environ['TRIVY_USERNAME'] = reg['user']
                        os.environ['TRIVY_PASSWORD'] = reg['password']
                    elif not validators.domain(registry):
                        """If registry is not an url"""
                        if reg['name'] == "docker.io":
                            os.environ['DOCKER_REGISTRY'] = reg['name']
                            os.environ['TRIVY_USERNAME'] = reg['user']
                            os.environ['TRIVY_PASSWORD'] = reg['password']
            except:
                logger.info("No registry auth config is defined.") # info
            ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
            logger.debug("Active Registry: %s" % (ACTIVE_REGISTRY)) # debuglog

            """Scan Images"""
            if REDIS_ENABLED:
                TRIVY = ["trivy", "-q", "image", "-f", "json", "--cache-backend", REDIS_BACKEND, image_name]
            else:
                TRIVY = ["trivy", "-q", "image", "-f", "json", image_name]
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
                elif b"UNAUTHORIZED" in error.strip():
                    logger.error(
                        "Repository: Unauthorized authentication required")
                elif b"You have reached your pull rate limit." in error.strip():
                    logger.error("You have reached your pull rate limit.")
                elif b"unsupported MediaType" in error.strip():
                    logger.error(
                        "Unsupported MediaType: see https://github.com/google/go-containerregistry/issues/377")
                elif b"MANIFEST_UNKNOWN: manifest unknown; map[Tag:latest]" in error.strip():
                    logger.error("No tag in registry")
                else:
                    logger.error("%s" % (error.strip()))
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
# print to operator log
# print(f"And here we are! Creating: %s" % (ns_name), file=sys.stderr) # debug
# message to CR
#    return {'message': 'hello world'}  # will be the new status
# events to CR describe
# kopf.event(body, type="SomeType", reason="SomeReason", message="Some message")
