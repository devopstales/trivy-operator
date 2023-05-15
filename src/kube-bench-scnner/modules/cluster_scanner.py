
import kopf, subprocess, json, logging, requests
from datetime import datetime, timezone

import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException

from modules.helper_functions import (
    getNextCronRunTime, roundDownTime, getCurretnTime, sleepTillTopOfNextMinute
)

from modules.get_variables import (
    report_name,
    IN_CLUSTER,
    NODE_NAME
)
from modules.prometheus import (
    CIS_VULN
)

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
def create_clusterpolicyreports(logger, body, name):
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

def run_kube_bench(logger, scan_profile):
    if scan_profile is not None:
        KUBE_BENCH_COMMAND = [ "kube-bench", "--nosummary", "--nototals", "--noremediations", "--benchmark", scan_profile, "--json" ]
    else:
        KUBE_BENCH_COMMAND = [ "kube-bench", "--nosummary", "--nototals", "--noremediations", "--json" ]

    res = subprocess.Popen(
        KUBE_BENCH_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = res.communicate()
    if error:
        bench_result = None
        logger.error("kube-bench run failed: %s" % error)
        raise kopf.PermanentError("kube-bench run failed !!!")
    elif output:
        bench_result = json.loads(output.decode("UTF-8"))
    return bench_result

def push_result_to_detectdojo(logger, spec, bench_result, scan_profile):
    logging.captureWarnings(True)
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
    if defectdojo_host is not None and defectdojo_api_key is not None and k8s_cluster is not None:
        headers = dict()
        headers['Authorization'] = "Token " + defectdojo_api_key
        files = {
            'file': bench_result
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
        response = requests.post(
            defectdojo_host+"/api/v2/import-scan/", headers=headers, files=files, data=data, verify=False)
        if response.status_code == 201 :
            logger.info("Successfully uploaded the results to Defect Dojo")
        else:
            logger.info("Something went wrong, please debug " + str(response.text))

        """Add kubernetes node to Defect Dojo"""
        response = requests.get(
            defectdojo_host+"/api/v2/products/?name="+k8s_cluster, headers=headers, verify=False)
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
            response = requests.post(
                defectdojo_host+"/api/v2/endpoints/", headers=headers, data=data, verify=False)
            if response.status_code == 201 :
                logger.info("Successfully added host to Defect Dojo")
            else:
                if "already exists" in response.text:
                    print()
                else:
                    logger.info("Something went wrong, please debug " + str(response.text))

def generate_cluster_policy_report(logger, bench_result):
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
        logger.info("Node Type: %s" % item["node_type"]) # warning
        for test in item["tests"]:
            logger.debug("Tets: %s" % test["desc"]) # warning
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
                logger.debug("id: %s" % result["test_number"]) # warning
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
    logger.debug("DEBUG - is_pClusterPolicyReport_exists: %s" % is_pClusterPolicyReport_exists) # WARNING

    if is_pClusterPolicyReport_exists:
        logger.info("clusterPolicyReport need deletion") # WARNING
        delete_clusterpolicyreports(report_name)
        create_clusterpolicyreports(ClusterPolicyReport, report_name)
    else:
        create_clusterpolicyreports(ClusterPolicyReport, report_name)

def generate_cis_vuln_report(logger, bench_result):
    date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%sZ")

    CIS_VULN_REPORT = {
        "apiVersion": "wgpolicyk8s.io/v1alpha2",
        "kind": "CISReport",
        "metadata": {
            "name": report_name
            # "labels"
            # "ownerReferences"
        },
        "results": [],
    }

    for item in bench_result:
        report = {
            "artifact": {
                "node": NODE_NAME,
                "node_type": item["node_type"],
                "scan_profile": item["version"],
            },
            "summary": {
                "fail": 0,
                "warn": 0,
                "pass": 0,
                "info": 0,
            },
            "updateTimestamp": date,
            "vulnerabilities": []
        }
        for test in item["tests"]:
            report["summary"]["fail"] += test["fail"]
            report["summary"]["warn"] += test["warn"]
            report["summary"]["pass"] += test["pass"]
            report["summary"]["info"] += test["info"]
            for result in test["results"]:

                CIS_vulnerability = {
                    "vulnerabilityID": result["test_number"],
                    "result": result["status"],
                    "description": result["test_desc"],
                    "resolution": result["remediation"],
                    "scored": result["scored"],
                    "multiple":  str(result["IsMultiple"]),
                    }

def start_cluster_scanner(logger, spec):
    logger.info("ClustereScanner Created")

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
    
    nextRunTime = getNextCronRunTime(crontab)
    while True:
        roundedDownTime = roundDownTime()
        if (roundedDownTime == nextRunTime):
            bench_result = run_kube_bench(logger, scan_profile)
            push_result_to_detectdojo(logger, spec, bench_result, scan_profile)
            generate_cluster_policy_report(logger, bench_result)
            generate_cis_vuln_report(logger, bench_result)
        elif (roundedDownTime > nextRunTime):
            now = getCurretnTime()
            logger.debug("MISSED RUN: %s" % now) # WARNING
            nextRunTime = getNextCronRunTime(crontab)
        sleepTillTopOfNextMinute()