import kopf, os, base64, certbuilder, json, validators, subprocess
from typing import AsyncIterator, Optional, Tuple, Collection
from oscrypto import asymmetric as oscrypto_asymmetric
from OpenSSL import crypto
from datetime import datetime

import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException

from modules.helper_functions import var_test
from modules.get_variables import (
    IN_CLUSTER,
    IS_GLOBAL,
    REDIS_ENABLED,
    TRIVY_REDIS,
    OFFLINE_ENABLED,
    TRIVY_OFFLINE,
)
from modules.prometheus import (
    AC_VULN
)

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

    # Build a certificate as the framework believe is good enough for itself.
    subject = {'common_name': hostname[0]}
    public_key, private_key = oscrypto_asymmetric.generate_pair(
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
    pkey_pem = oscrypto_asymmetric.dump_private_key(
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

def load_admission_server_configuration(logger, settings):
    logger.info("Loading cluster config")

    name = "trivy-image-validator"
    namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")
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
            logger.info("Certificate Expires soon. Regenerating.")
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

def create_admission_server(logger, settings):
    # Auto-detect the best server (K3d/Minikube/simple):
    if IN_CLUSTER:
        if IS_GLOBAL:
            logger.info("Start admission server")
            settings.admission.server = ServiceTunnel()
            # Automaticle create ValidatingWebhookConfiguration
            settings.admission.managed = 'trivy-image-validator.devopstales.io'
        else:
            if IN_CLUSTER:
                k8s_config.load_incluster_config()
            else:
                k8s_config.load_kube_config()
            load_admission_server_configuration(logger, settings)

    else:
        settings.admission.server = kopf.WebhookAutoServer(port=443)
        settings.admission.managed = 'trivy-image-validator.devopstales.io'

def get_registry_list(logger, spec):
    """Try to get Registry auth values"""
    registry_list = []
    v1 = k8s_client.CoreV1Api()
    current_namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")
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
    return registry_list

def get_image_list(logger, spec):
    image_list = []
    """Get conainers"""
    containers = spec.get('containers')
    initContainers = spec.get('initContainers')

    try:
        """Get Images from initContainers"""
        for icn in initContainers:
            initContainers_array = json.dumps(icn)
            initContainer = json.loads(initContainers_array)
            image_name = initContainer["image"]
            image_list.append(image_name)
    except:
        logger.error("Error when getting images from initContainers")

    try:
        """Get Images from Containers"""
        for cn in containers:
            container_array = json.dumps(cn)
            container = json.loads(container_array)
            image_name = container["image"]
            image_list.append(image_name)
    except:
        logger.error("Error when getting images from Containers")

    return image_list

def get_vul_list(logger, namespace, image_list, registry_list, annotations):
    vul_list = {}

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

    return vul_list

def generate_metricfile(logger, image_list, vul_list, annotations):
    for image_name in image_list:
        logger.info("severity: %s" % (vul_list[image_name][0]))  # info
        for image_name in vul_list.keys():
             for severity in vul_list[image_name][0].keys():
                 AC_VULN.labels(vul_list[image_name][1], image_name, severity).set(
                        int(vul_list[image_name][0][severity]))
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


def start_admission_controller(logger, spec, annotations):
    logger.info("Admission Controller is working")
    namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")
    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()
    registry_list = get_registry_list(logger, spec)
    image_list = get_image_list(logger, spec)
    vul_list = get_vul_list(logger, namespace, image_list, registry_list)
    generate_metricfile(logger, image_list, vul_list, annotations)