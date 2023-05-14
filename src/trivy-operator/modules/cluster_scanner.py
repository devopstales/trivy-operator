import os, kopf

import kubernetes.client as k8s_client
import kubernetes.config as k8s_config
from kubernetes.client.rest import ApiException

from modules.get_variables import (
    IN_CLUSTER
)

"""Test daemonset"""
def test_daemonset_exists(logger, namespace, name):
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
def create_daemonset(logger, body, namespace, name):
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

def create_cluster_scanner(logger, spec):
    logger.info("ClustereScanner Created")

    ds_name = "kube-bech-scanner"
    ds_image = "devopstales/kube-bench-scnner:2.5" # get tag from variable?
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
        daemonset['metadata']['ownerReferences'] = [
            {
                "apiVersion": "v1", 
                "kind": "Pod", 
                "name": pod_name, 
                "uid": pod_uid, 
                "blockOwnerDeletion": False, 
                "controller": True,
            }
        ]
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

    if IN_CLUSTER:
        k8s_config.load_incluster_config()
    else:
        k8s_config.load_kube_config()

    is_daemonset_exists = test_daemonset_exists(logger, namespace, ds_name)

    if is_daemonset_exists:
        logger.info("daemonset already exists") # WARNING
    else:
        create_daemonset(logger, daemonset, namespace, ds_name)

"""Test daemonset"""
def test_daemonset_exists(logger, namespace, name):
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
def delete_daemonset(logger, namespace, name):
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.AppsV1Api(api_client)
    try:
        api_response = api_instance.delete_namespaced_daemon_set(
            name, namespace)
    except ApiException as e:
        logger.error("Exception when deleting daemonset - %s : %s\n" % (name, e))

def delete_cluster_scanner(logger, spec):
    ds_name = "kube-bech-scanner"
    namespace = os.environ.get("POD_NAMESPACE", "trivy-operator")

    is_daemonset_exists = test_daemonset_exists(logger, namespace, ds_name)

    if is_daemonset_exists:
        delete_daemonset(logger, namespace, ds_name)
    else:
        logger.info("daemonset dose not exists: nothing to delete") # WARNING