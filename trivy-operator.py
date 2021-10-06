import kopf
import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
import prometheus_client
import asyncio
import pycron
import os
import sys
import subprocess
import json

"""
apiVersion: trivy-operator.devopstales.io/v1
kind: NamespaceScanner
metadata:
  name: main-config
  namespace: trivy-operator
spec:
  crontab: "*/5 * * * *"
  namespace_selector: "trivy-scan"
  registry:
  - name: docker.io
    user: "user"
    password: "password"
"""

"""Deploy CRDs"""
@kopf.on.startup()
async def startup_fn_crd(logger, **kwargs):
    scanner_crd = k8s_client.V1CustomResourceDefinition(
        api_version="apiextensions.k8s.io/v1",
        kind="CustomResourceDefinition",
        metadata=k8s_client.V1ObjectMeta(name="namespace-scanners.trivy-operator.devopstales.io"),
        spec=k8s_client.V1CustomResourceDefinitionSpec(
            group="trivy-operator.devopstales.io",
            versions=[k8s_client.V1CustomResourceDefinitionVersion(
                name="v1",
                served=True,
                storage=True,
                subresources=k8s_client.V1CustomResourceSubresources(status={}),
                schema=k8s_client.V1CustomResourceValidation(
                    open_apiv3_schema=k8s_client.V1JSONSchemaProps(
                        type="object",
                        properties={
                            "spec": k8s_client.V1JSONSchemaProps(
                                type="object",
                                x_kubernetes_preserve_unknown_fields=True
                            ),
                            "status": k8s_client.V1JSONSchemaProps(
                                type="object",
                                x_kubernetes_preserve_unknown_fields=True
                            ),
                            "crontab": k8s_client.V1JSONSchemaProps(
                                type="string",
                                pattern="^(\d+|\*)(/\d+)?(\s+(\d+|\*)(/\d+)?){4}$"
                            ),
                            "namespace_selector": k8s_client.V1JSONSchemaProps(
                                type="string",
                            ),
                        }
                    )
                ),
                additional_printer_columns=[k8s_client.V1CustomResourceColumnDefinition(
                  name="NamespaceSelector",
                  type="string",
                  priority=0,
                  json_path=".spec.namespace_selector",
                  description="Namespace Selector for pod scanning"
                ),k8s_client.V1CustomResourceColumnDefinition(
                  name="Crontab",
                  type="string",
                  priority=0,
                  json_path=".spec.crontab",
                  description="crontab value"
                ), k8s_client.V1CustomResourceColumnDefinition(
                  name="Message",
                  type="string",
                  priority=0,
                  json_path=".status.create_fn.message",
                  description="As returned from the handler (sometimes)."
                )]
            )],
            scope="Namespaced",
            names=k8s_client.V1CustomResourceDefinitionNames(
                kind="NamespaceScanner",
                plural="namespace-scanners",
                singular="namespace-scanner",
                short_names=["ns-scan"]
            )
        )
    )

    IN_CLUSTER = os.getenv("IN_CLUSTER", False)
    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()
    

    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.ApiextensionsV1Api(api_client)
        try:
            api_instance.create_custom_resource_definition(scanner_crd)
        except k8s_client.rest.ApiException as e:
            if e.status == 409: # if the CRD already exists the K8s API will respond with a 409 Conflict
                logger.info("CRD already exists!!!")
            else:
                raise e

"""Download trivy cache """
@kopf.on.startup()
async def startup_fn_trivy_cache(logger, **kwargs):
    TRIVY_CACHE = ["trivy", "-q", "-f", "json", "fs", "/opt"]
    trivy_cache_result = (
        subprocess.check_output(TRIVY_CACHE).decode("UTF-8")
    )
    logger.info("trivy cache created...")

"""Scanner Creation"""
@kopf.on.create('trivy-operator.devopstales.io', 'v1', 'namespace-scanners')
async def create_fn(logger, spec, **kwargs):
    CONTAINER_VULN = prometheus_client.Gauge('so_vulnerabilities', 'Container vulnerabilities', ['exported_namespace', 'image', 'severity'])

    """Start Prometheus Exporter"""
    prometheus_client.start_http_server(9115)
    logger.info("Prometheus Exporter started...")

    try:
        crontab = spec['crontab']
    except:
        logger.error("crontab must be set !!!")
        raise kopf.PermanentError("crontab must be set")

    try:
        namespace_selector = spec['namespace_selector']
    except:
        logger.error("namespace_selector must be set !!!")
        raise kopf.PermanentError("namespace_selector must be set")

    while True:
            if pycron.is_now(crontab):
                """Find Namespaces"""
                IN_CLUSTER = os.getenv("IN_CLUSTER", False)
                image_list = {}
                vul_list = {}
                tagged_ns_list = []

                if IN_CLUSTER:
                    k8s_config.load_incluster_config()
                else:
                    k8s_config.load_kube_config()
                namespace_list = k8s_client.CoreV1Api().list_namespace()

                for ns in namespace_list.items:
                    ns_label_list = ns.metadata.labels.items()
                    ns_name = ns.metadata.name

                """Finf Namespaces with selector tag"""
                for label_key, label_value in ns_label_list:
                    if namespace_selector == label_key and bool(label_value) == True:
                        tagged_ns_list.append(ns_name)
                    else:
                        continue

                """Find pods in namespaces"""
                for tagged_ns in tagged_ns_list:
                    pod_list = k8s_client.CoreV1Api().list_namespaced_pod(tagged_ns)
                    """Find images in pods"""
                    for pod in pod_list.items:
                        pod_name = pod.metadata.name
                        images = pod.status.container_statuses
                        for image in images:
                            image_name = image.image
                            image_id = image.image_id
                            image_list[pod_name] = list()
                            image_list[pod_name].append(image_name)
                            image_list[pod_name].append(image_id)
                            image_list[pod_name].append(tagged_ns)

                """Scan images"""
                for image in image_list:
                    logger.info("Scanning Image: %s" % (image_list[image][0]))
                    image_name = image_list[image][0]
                    image_id = image_list[image][1]
                    ns_name = image_list[image][2]
                    registry = image_name.split('/')[0]

                    try:
                        registry_list = spec['registry']
                        
                        for reg in registry_list:
                            if reg['name'] == registry:
                                os.environ['TRIVY_USERNAME']=reg['user']
                                os.environ['TRIVY_PASSWORD']=reg['password']
                    except:
                        logger.info("no registry auth config is defined")

                    TRIVY = ["trivy", "-q", "i", "-f", "json", image_name]
                    # --ignore-policy trivy.rego

                    res = subprocess.Popen(TRIVY,stdout=subprocess.PIPE,stderr=subprocess.PIPE);
                    output,error = res.communicate()
                    if output:
                        trivy_result = json.loads(output.decode("UTF-8"))
                        item_list = trivy_result['Results'][0]["Vulnerabilities"]
                        vuls = {
                            "UNKNOWN": 0,"LOW": 0,
                            "MEDIUM": 0,"HIGH": 0,
                            "CRITICAL": 0
                        }
                        for item in item_list:
                            vuls[item["Severity"]] += 1
                        vul_list[image_name] = [vuls, ns_name]

                        """Generate Metricfile"""
                        for image_name in vul_list.keys():
                            for severity in vul_list[image_name][0].keys():
                                CONTAINER_VULN.labels(vul_list[image_name][1], image_name, severity).set(int(vul_list[image_name][0][severity]))

                    if error:
                        logger.error("TRIVY ERROR: return %s" % (res.returncode))
                        if b"401" in error.strip():
                            logger.error("Repository: Unauthorized authentication required")
                        if b"UNAUTHORIZED" in error.strip():
                            logger.error("Repository: Unauthorized authentication required")
                        if b"You have reached your pull rate limit." in error.strip():
                            logger.error("You have reached your pull rate limit.")

                await asyncio.sleep(15)
            else:
                await asyncio.sleep(15)

## print to operator log
# print(f"And here we are! Creating: %s" % (ns_name), file=sys.stderr) # debug
## message to CR
#    return {'message': 'hello world'}  # will be the new status
## events to CR describe
# kopf.event(body, type="SomeType", reason="SomeReason", message="Some message")