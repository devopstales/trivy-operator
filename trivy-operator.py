import kopf
import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException
import prometheus_client
import asyncio
import pycron
import os
import subprocess
import json
import validators
import base64
from typing import AsyncIterator, Optional, Tuple, Collection

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

#############################################################################
# ToDo
#############################################################################
# OP
# AC
## namespace selector for admission controller webhook
# cache scanned images ???


#############################################################################
# Global Variables
#############################################################################
CONTAINER_VULN = prometheus_client.Gauge(
    'so_vulnerabilities',
    'Container vulnerabilities',
    ['exported_namespace', 'image', 'severity']
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

    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()


    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.ApiextensionsV1Api(api_client)
        try:
            api_instance.create_custom_resource_definition(scanner_crd)
        except ApiException as e:
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
                        Containers = pod.status.container_statuses
                        for image in Containers:
                            pod_name = pod.metadata.name
                            pod_name += '_'
                            pod_name += image.name
                            image_list[pod_name] = list()
                            image_name = image.image
                            image_id = image.image_id
                            image_list[pod_name].append(image_name)
                            image_list[pod_name].append(image_id)
                            image_list[pod_name].append(tagged_ns)
                        try:
                            initContainers = pod.status.init_container_statuses
                            for image in initContainers:
                                pod_name = pod.metadata.name
                                pod_name += '_'
                                pod_name += image.name
                                image_list[pod_name] = list()
                                image_name = image.image
                                image_id = image.image_id
                                image_list[pod_name].append(image_name)
                                image_list[pod_name].append(image_id)
                                image_list[pod_name].append(tagged_ns)
                        except:
                            continue

                """Scan images"""
                logger.info("%s" % (image_list)) # debug
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
                                os.environ['DOCKER_REGISTRY']=reg['name']
                                os.environ['TRIVY_USERNAME']=reg['user']
                                os.environ['TRIVY_PASSWORD']=reg['password']
                            elif not validators.domain(registry):
                                """If registry is not an url"""
                                if reg['name'] == "docker.io":
                                    os.environ['DOCKER_REGISTRY']=reg['name']
                                    os.environ['TRIVY_USERNAME']=reg['user']
                                    os.environ['TRIVY_PASSWORD']=reg['password']
                    except:
                        logger.info("No registry auth config is defined.")
                        ACTIVE_REGISTRY = os.getenv("DOCKER_REGISTRY")
                        logger.info("Active Registry: %s" % (ACTIVE_REGISTRY)) # Debug

                    TRIVY = ["trivy", "-q", "i", "-f", "json", image_name]
                    # --ignore-policy trivy.rego

                    res = subprocess.Popen(TRIVY,stdout=subprocess.PIPE,stderr=subprocess.PIPE);
                    output,error = res.communicate()

                    if error:
                        """Error Logging"""
                        logger.error("TRIVY ERROR: return %s" % (res.returncode))
                        if b"401" in error.strip():
                            logger.error("Repository: Unauthorized authentication required")
                        elif b"UNAUTHORIZED" in error.strip():
                            logger.error("Repository: Unauthorized authentication required")
                        elif b"You have reached your pull rate limit." in error.strip():
                            logger.error("You have reached your pull rate limit.")
                        elif b"unsupported MediaType" in error.strip():
                            logger.error("Unsupported MediaType: see https://github.com/google/go-containerregistry/issues/377")
                        else:
                            logger.error("%s" % (error.strip()))
                        """Error action"""
                        vuls = { "scanning_error": 1 }
                        vul_list[image_name] = [vuls, ns_name]
                    elif output:
                        trivy_result = json.loads(output.decode("UTF-8"))
                        item_list = trivy_result['Results'][0]["Vulnerabilities"]
                        vuls = { "UNKNOWN": 0,"LOW": 0,"MEDIUM": 0,"HIGH": 0,"CRITICAL": 0 }
                        for item in item_list:
                            vuls[item["Severity"]] += 1
                        vul_list[image_name] = [vuls, ns_name]

                """Generate Metricfile"""
                for image_name in vul_list.keys():
                    for severity in vul_list[image_name][0].keys():
                        CONTAINER_VULN.labels(
                            vul_list[image_name][1],
                            image_name, severity).set(int(vul_list[image_name][0][severity])
                        )

                await asyncio.sleep(15)
            else:
                await asyncio.sleep(15)

#############################################################################
# Admission Controller
#############################################################################
# https://github.com/nolar/kopf/issues/785#issuecomment-859931945
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
            server = kopf.WebhookServer(port=container_port, host=f"{name}.{namespace}.svc")
            async for client_config in server(fn):
                client_config["url"] = None
                client_config["service"] = kopf.WebhookClientConfigService(
                    name=name, namespace=namespace, port=service_port
                )
                yield client_config

    def build_certificate(
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
        public_key, private_key = oscrypto.asymmetric.generate_pair('rsa', bit_size=2048)
        builder = certbuilder.CertificateBuilder(subject, public_key)
        builder.ca = True
        builder.key_usage = {'digital_signature', 'key_encipherment', 'key_cert_sign', 'crl_sign'}
        builder.extended_key_usage = {'server_auth', 'client_auth'}
        builder.self_signed = True
        builder.subject_alt_domains = list(hostname)
        certificate = builder.build(private_key)
        cert_pem = certbuilder.pem_armor_certificate(certificate)
        pkey_pem = oscrypto.asymmetric.dump_private_key(private_key, password, target_ms=10)
        return cert_pem, pkey_pem

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
          # test if file exists
            # delete cert file
            # delete validating webhook configuration ??
            ## https://github.com/kubernetes-client/python/blob/e8e6a86a30159a21b950ed873e69514abb5d359f/kubernetes/docs/AdmissionregistrationV1Api.md#delete_validating_webhook_configuration
          # Generate cert
          logger.info("Generating a self-signed certificate for HTTPS.")
          namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")
          name = "trivy-image-validator"
          hostname = f"{name}.{namespace}.svc"
          certdata, pkeydata = build_certificate([hostname, "localhost"])
          # write to file
          certf = open("/home/trivy-operator/trivy-cache/cert.pem","w+")
          certf.write(str(certdata.decode('ascii')))
          certf.close()
          pkeyf = open("/home/trivy-operator/trivy-cache/key.pem","w+")
          pkeyf.write(str(pkeydata.decode('ascii')))
          pkeyf.close()
          caBundle = base64.b64encode(certdata).decode('ascii')

          # Start Admission Server
          settings.admission.server = kopf.WebhookServer(
              port=8443,
              host=hostname,
              certfile=certf.name,
              pkeyfile=pkeyf.name
          )

          '''Create own ValidatingWebhookConfiguration'''
          k8s_config.load_incluster_config()
          with k8s_client.ApiClient() as api_client:
              api_instance = k8s_client.AdmissionregistrationV1Api(api_client)
              body = k8s_client.V1ValidatingWebhookConfiguration(
                  api_version='admissionregistration.k8s.io/v1',
                  kind='ValidatingWebhookConfiguration',
                  metadata=k8s_client.V1ObjectMeta(name='trivy-image-validator.devopstales.io'),
                  webhooks=[k8s_client.V1ValidatingWebhook(
                      client_config=k8s_client.AdmissionregistrationV1WebhookClientConfig(
                          ca_bundle=caBundle,
                          service=k8s_client.AdmissionregistrationV1ServiceReference(
                              name="trivy-image-validator",
                              namespace=os.environ.get("POD_NAMESPACE", "trivy-operator"),
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
              api_response = api_instance.create_validating_webhook_configuration(body, pretty=pretty, field_manager=field_manager)
          except ApiException as e:
              if e.status == 409: # if the object already exists the K8s API will respond with a 409 Conflict
                  logger.info("validating webhook configuration already exists!!!")
              else:
                logger.error("Exception when calling AdmissionregistrationV1Api->create_validating_webhook_configuration: %s\n" % e)
        
    else:
      settings.admission.server = kopf.WebhookAutoServer(port=443)
      settings.admission.managed = 'trivy-image-validator.devopstales.io'

@kopf.on.validate('pod', operation='CREATE')
def validate1(logger, namespace, name, annotations, spec, **_):
    logger.info("Admission Controller is working")