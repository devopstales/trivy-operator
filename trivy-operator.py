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

#############################################################################
# ToDo
#############################################################################
# OP
# cache scanned images ???
# AC
# cache scanned images ???
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
IN_CLUSTER = os.getenv("IN_CLUSTER", False)
IS_GLOBAL = os.getenv("IS_GLOBAL", False)

#############################################################################
# Pretasks
#############################################################################

"""Deploy CRDs"""


@kopf.on.startup()
async def startup_fn_crd(logger, **kwargs):
    scanner_crd = k8s_client.V1CustomResourceDefinition(
        api_version="apiextensions.k8s.io/v1",
        kind="CustomResourceDefinition",
        metadata=k8s_client.V1ObjectMeta(
            name="namespace-scanners.trivy-operator.devopstales.io"),
        spec=k8s_client.V1CustomResourceDefinitionSpec(
            group="trivy-operator.devopstales.io",
            versions=[k8s_client.V1CustomResourceDefinitionVersion(
                name="v1",
                served=True,
                storage=True,
                subresources=k8s_client.V1CustomResourceSubresources(
                    status={}),
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
                ), k8s_client.V1CustomResourceColumnDefinition(
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

    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.ApiextensionsV1Api(api_client)
        try:
            api_instance.create_custom_resource_definition(scanner_crd)
        except ApiException as e:
            if e.status == 409:  # if the CRD already exists the K8s API will respond with a 409 Conflict
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
async def create_fn(logger, spec, **kwargs):
    logger.info("NamespaceScanner Created")

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
            unique_image_list = {}
            pod_list = {}
            trivy_result_list = {}
            vul_list = {}
            tagged_ns_list = []

            if IN_CLUSTER:
                k8s_config.load_incluster_config()
            else:
                k8s_config.load_kube_config()

            namespace_list = k8s_client.CoreV1Api().list_namespace()
            logger.debug("namespace list begin:")
            logger.debug(format(namespace_list))
            logger.debug("namespace list end:")

            for ns in namespace_list.items:
                try:
                    ns_label_list = ns.metadata.labels.items()
                    ns_name = ns.metadata.name
                except Exception as e:
                    logger.error(str(e))

                """Find Namespaces with selector tag"""
                logger.debug("labels and namespace begin")
                logger.debug(format(ns_label_list))
                logger.debug(format(ns_name))
                logger.debug("labels and namespace end")
                for label_key, label_value in ns_label_list:
                    if namespace_selector == label_key and bool(label_value) == True:
                        tagged_ns_list.append(ns_name)
                    else:
                        continue

            """Find pods in namespaces"""
            for tagged_ns in tagged_ns_list:
                namespaced_pod_list = k8s_client.CoreV1Api().list_namespaced_pod(tagged_ns)
                logger.debug("pod list begin:")
                logger.debug(format(namespaced_pod_list))
                logger.debug("pod list end:")
                """Find images in pods"""
                for pod in namespaced_pod_list.items:
                    Containers = pod.status.container_statuses
                    logger.debug("containers begin:")
                    logger.debug(format(Containers))
                    logger.debug("containers end:")
                    for image in Containers:
                        pod_name = pod.metadata.name
                        pod_name += '_'
                        pod_name += image.name
                        pod_list[pod_name] = list()
                        image_name = image.image
                        image_id = image.image_id
                        pod_list[pod_name].append(image_name)
                        pod_list[pod_name].append(image_id)
                        pod_list[pod_name].append(tagged_ns)

                        unique_image_list[image_name] = image_name
                    try:
                        initContainers = pod.status.init_container_statuses
                        logger.debug("initContainers begin:")
                        logger.debug(format(initContainers))
                        logger.debug("initContainers end:")
                        for image in initContainers:
                            pod_name = pod.metadata.name
                            pod_name += '_'
                            pod_name += image.name
                            pod_list[pod_name] = list()
                            image_name = image.image
                            image_id = image.image_id
                            pod_list[pod_name].append(image_name)
                            pod_list[pod_name].append(image_id)
                            pod_list[pod_name].append(tagged_ns)

                            unique_image_list[image_name] = image_name
                    except:
                        continue

            """Scan images"""
            logger.debug("image list begin:")
            logger.debug(format(unique_image_list))
            logger.debug("image list end:")

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
                    logger.debug("No registry auth config is defined.")
                    ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
                    logger.info("Active Registry: %s" %
                                (ACTIVE_REGISTRY))  # Debug

                TRIVY = ["trivy", "-q", "i", "-f", "json", image_name]
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
                    trivy_result_list[image_name] = "scanning_error"
                elif output:
                    trivy_result = json.loads(output.decode("UTF-8"))
                    trivy_result_list[image_name] = trivy_result

            for pod_name in pod_list:
                logger.info("Assigning scanning result for Pod: %s" % (pod_name))
                image_name = pod_list[pod_name][0]
                image_id = pod_list[pod_name][1]
                ns_name = pod_list[pod_name][2]

                trivy_result = trivy_result_list[image_name]
                if trivy_result == 'scanning_error':
                    vuls = {"scanning_error": 1}
                    vul_list[pod_name] = [vuls, ns_name]
                else:
                    if 'Vulnerabilities' in trivy_result['Results'][0]:
                        vuls = {"UNKNOWN": 0, "LOW": 0,
                                "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
                        item_list = trivy_result['Results'][0]["Vulnerabilities"]
                        for item in item_list:
                            #print(item["PkgName"], file=sys.stderr)
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
                        vul_list[pod_name] = [vuls, ns_name]

            """Generate Metricfile"""
            for pod_name in vul_list.keys():
                for severity in vul_list[pod_name][0].keys():
                    CONTAINER_VULN_SUM.labels(
                        vul_list[pod_name][1],
                        image_name, severity).set(int(vul_list[pod_name][0][severity])
                                                  )

            await asyncio.sleep(15)
        else:
            await asyncio.sleep(15)

#############################################################################
# Admission Controller
#############################################################################

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
            log_level = os.environ.get("LOG_LEVEL", "trivy-operator")
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
                logger.info("Day to certifiacet expiration: %s" %
                            daysToExpiration)  # debug
                if daysToExpiration <= 7:  # debug 365
                    logger.warning("Certificate Expires soon. Regenerating.")
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

    for cn in containers:
        container_array = json.dumps(cn)
        container = json.loads(container_array)
        image_name = container["image"]
        image_list.append(image_name)

    """Get Images"""
    for image_name in image_list:
        registry = image_name.split('/')[0]
        logger.info("Scanning Image: %s" % (image_name))

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
            logger.info("No registry auth config is defined.")
        ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
        logger.debug("Active Registry: %s" % (ACTIVE_REGISTRY))

        """Scan Images"""
        TRIVY = ["trivy", "-q", "i", "-f", "json", image_name]
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
            se = {"scanning_error": 1}
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
        logger.info("severity: %s" % (vul_list[image_name][0]))  # Logging

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
        if "scanning_error" in vul_list[image_name][0]:
            logger.error("Trivy can't scann the image")
            raise kopf.AdmissionError(
                f"Trivy can't scann the image: %s" % (image_name))
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
