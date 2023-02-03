#!/usr/bin/env python3

from __main__ import db
from flask_login import UserMixin
from flask import flash
from itsdangerous import base64_decode
import kubernetes.config as k8s_config
import kubernetes.client as k8s_client
from kubernetes.client.rest import ApiException
from functions.logger import logger

##############################################################
## Kubernetes Config
##############################################################

class k8sConfig(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    k8s_server_url = db.Column(db.Text, unique=True, nullable=False)
    k8s_context = db.Column(db.Text, unique=True, nullable=False)
    k8s_server_ca = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Kubernetes Server URL %r>' % self.k8s_server_url

def k8sServerConfigCreate(k8s_server_url, k8s_context, k8s_server_ca):
    k8s = k8sConfig.query.filter_by(k8s_server_url=k8s_server_url).first()
    k8s_data = k8sConfig(
        k8s_server_url = k8s_server_url,
        k8s_context = k8s_context,
        k8s_server_ca = k8s_server_ca
    )
    if k8s is None:
        db.session.add(k8s_data)
        db.session.commit()

def k8sServerConfigGet():
    # User.query.filter_by(username=current_username).first()
    k8s_config_list = k8sConfig.query.get(1)
    return k8s_config_list

def k8sServerConfigList():
    k8s_config_list = k8sConfig.query
    return k8s_config_list

def k8sServerDelete(k8s_context):
    k8s = k8sConfig.query.filter_by(k8s_context=k8s_context).first()
    if k8s:
        db.session.delete(k8s)
        db.session.commit()

def k8sServerConfigUpdate(k8s_context_old, k8s_server_url, k8s_context, k8s_server_ca):
    k8s = k8sConfig.query.filter_by(k8s_context=k8s_context_old).first()
    if k8s:
        k8s.k8s_server_url = k8s_server_url
        k8s.k8s_context = k8s_context
        k8s.k8s_server_ca = k8s_server_ca
        db.session.commit()

##############################################################
## Kubernetes Config
##############################################################

def ErrorHandler(error, action):
    if error.status == 401:
        flash("401 - Unauthorized: User cannot coonekt to Kubernetes", "danger")
    elif error.status == 403:
        flash("403 - Forbidden: User cannot %s" % action, "danger")
    else:
        flash(error, "danger")

def k8sClientConfigGet(username_role, user_token):
    k8sConfig = k8sServerConfigGet()
    k8s_server_url = k8sConfig.k8s_server_url
    k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
    if k8s_server_ca:
        file = open("CA.crt", "w+")
        file.write( k8s_server_ca )
        file.close 

    if username_role == "Admin":
        # k8s_config.load_incluster_config()
        k8s_config.load_kube_config()
    elif username_role == "User":
        configuration = k8s_client.Configuration()
        configuration.host = k8s_server_url
        configuration.verify_ssl = True
        configuration.ssl_ca_cert = 'CA.crt'
        configuration.debug = False
        configuration.api_key_prefix['authorization'] = 'Bearer'
        configuration.api_key["authorization"] = str(user_token["id_token"])
        k8s_client.Configuration.set_default(configuration)

##############################################################
## Kubernetes Namespace
##############################################################

def k8sListNamespaces(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    try:
        namespace_list = k8s_client.CoreV1Api().list_namespace()
        return namespace_list, None
    except ApiException as e:
        namespace_list = ""
        return namespace_list, e

def k8sNamespaceListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    namespace_list = []
    try:
        namespaces, error = k8sListNamespaces(username_role, user_token)
        if error is None:
            for ns in namespaces.items:
                namespace_list.append(ns.metadata.name)
            return namespace_list
        else:
            ErrorHandler(error, "get namespace list")
            return namespace_list
    except:
        return namespace_list

def k8sNamespacesGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    NAMESPACE_LIST = []
    try:
        namespaces, error = k8sListNamespaces(username_role, user_token)
        if error is None:
            for ns in namespaces.items:
                NAMESPACE_DADTA = {
                    "name": "",
                    "status": "",
                }
                NAMESPACE_DADTA['name'] = ns.metadata.name
                NAMESPACE_DADTA['status'] = ns.status.__dict__['_phase']
                NAMESPACE_LIST.append(NAMESPACE_DADTA)
            return NAMESPACE_LIST
        else:
            ErrorHandler(error, "list namespaces")
            return NAMESPACE_LIST
    except:
        return NAMESPACE_LIST

def k8sNamespaceCreate(username_role, user_token, ns_name):
    k8sClientConfigGet(username_role, user_token)
    pretty = 'true'
    field_manager = 'KubeDash'
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CoreV1Api(api_client)
        body = k8s_client.V1Namespace(
            api_version = "",
            kind = "",
            metadata = k8s_client.V1ObjectMeta(
                name = ns_name,
                labels = {
                    "created_by": field_manager
                }
            )
        )
    try:
        api_response = api_instance.create_namespace(body, pretty=pretty, field_manager=field_manager)
        flash("Namespace Created Successfully", "success")
    except ApiException as error:
        ErrorHandler(error, "create namespace")

def k8sNamespaceDelete(username_role, user_token, ns_name):
    k8sClientConfigGet(username_role, user_token)
    pretty = 'true'
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.CoreV1Api(api_client)
    try:
        api_response = api_instance.delete_namespace(ns_name, pretty=pretty)
        flash("Namespace Deleted Successfully", "success")
    except ApiException as error:
        ErrorHandler(error, "create namespace")

##############################################################
## Kubernetes User Role template
##############################################################

def k8sUserClusterRoleTemplateListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role()
        try:
            for cr in cluster_roles.items:
                if "template-cluster-resources___" in cr.metadata.name:
                    CLUSTER_ROLE_LIST.append(cr.metadata.name.split("___")[-1])
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        ErrorHandler(error, "get cluster roles")

def k8sUserRoleTemplateListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    CLUSTER_ROLE_LIST = list()
    try:
        cluster_roles = k8s_client.RbacAuthorizationV1Api().list_cluster_role()
        try:
            for cr in cluster_roles.items:
                if "template-namespaced-resources___" in cr.metadata.name:
                    CLUSTER_ROLE_LIST.append(cr.metadata.name.split("___")[-1])
            return CLUSTER_ROLE_LIST
        except:
            return CLUSTER_ROLE_LIST
    except ApiException as error:
        ErrorHandler(error, "get cluster roles")

##############################################################
## Kubernetes Cluster Role
##############################################################

def k8sClusterRoleGet(name):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
    try:
        api_response = api_instance.read_cluster_role(
            name, pretty=pretty
        )
        return True, None
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when testing ClusterRole - %s : %s\n" % (name, e))
            return True, e
        else:
            return False, None

def k8sClusterRoleCreate(name, body):
    k8sClientConfigGet("Admin", None)
    with k8s_client.ApiClient() as api_client:
        api_instance = k8s_client.RbacAuthorizationV1Api(api_client)
        pretty = 'true'
        field_manager = 'KubeDash'
    try:
        api_response = api_instance.create_cluster_role(
            body, pretty=pretty, field_manager=field_manager
        )
        return True
    except ApiException as e:
        if e.status != 404:
            logger.error("Exception when testing ClusterRole - %s : %s\n" % (name, e))
            return False
        else:
            return False

def k8sClusterRolesAdd():
    admin = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-cluster-resources___admin"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = [
                        "get",
                        "list",
                        "watch"
                    ],
                    resources = [
                    "componentstatuses",
                    "namespaces",
                    "nodes",
                    "persistentvolumes",
                    "mutatingwebhookconfigurations",
                    "validatingwebhookconfigurations",
                    "customresourcedefinitions",
                    "apiservices",
                    "tokenreviews",
                    "selfsubjectaccessreviews",
                    "selfsubjectrulesreviews",
                    "subjectaccessreviews",
                    "certificatesigningrequests",
                    "runtimeclasses",
                    "podsecuritypolicies",
                    "clusterrolebindings",
                    "clusterroles",
                    "priorityclasses",
                    "csidrivers",
                    "csinodes",
                    "storageclasses",
                    "volumeattachment",
                    ]
                ),
            ]
    )
    reader = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-cluster-resources___reader"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = [
                        "get",
                        "list",
                        "watch"
                    ],
                    resources = [
                    "componentstatuses",
                    "namespaces",
                    "nodes",
                    "persistentvolumes",
                    "mutatingwebhookconfigurations",
                    "validatingwebhookconfigurations",
                    "customresourcedefinitions",
                    "apiservices",
                    "tokenreviews",
                    "selfsubjectaccessreviews",
                    "selfsubjectrulesreviews",
                    "subjectaccessreviews",
                    "certificatesigningrequests",
                    "runtimeclasses",
                    "podsecuritypolicies",
                    "clusterrolebindings",
                    "clusterroles",
                    "priorityclasses",
                    "csidrivers",
                    "csinodes",
                    "storageclasses",
                    "volumeattachment",
                    ]
                ),
            ]
    )
    developer = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-namespaced-resources___developer"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = ["*"],
                    resources = [
                    "configmaps",
                    "endpoints",
                    "pods",
                    "pods/log",
                    "pods/portforward",
                    "podtemplates",
                    "replicationcontrollers",
                    "resourcequotas",
                    "secrets",
                    "services",
                    "events",
                    "daemonsets",
                    "deployments",
                    "replicasets",
                    "ingresses",
                    "networkpolicies",
                    "poddisruptionbudgets",
                    ]
                ),
            ]
    )
    deployer = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-namespaced-resources___deployer"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["", "extensions", "apps", "networking.k8s.io", "autoscaling"],
                    verbs = ["*"],
                    resources = ["*"]
                ),
                k8s_client.V1PolicyRule(
                    api_groups = ["batch"],
                    verbs = ["*"],
                    resources = ["jobs", "cronjobs"]
                ),
            ]
    )
    operation = k8s_client.V1ClusterRole(
            api_version = "rbac.authorization.k8s.io/v1",
            kind = "ClusterRole",
            metadata = k8s_client.V1ObjectMeta(
                name = "template-namespaced-resources___operation"
            ),
            rules = [
                k8s_client.V1PolicyRule(
                    api_groups = ["*"],
                    verbs = ["*"],
                    resources = ["*"]
                ),
            ]
    )
    cluster_role_list = ["admin", "reader"]
    namespaced_role_list = ["developer", "deployer", "operation"]
    roleVars = locals()

    for role in cluster_role_list:
        name = "template-cluster-resources___" + role
        is_clusterrole_exists, error = k8sClusterRoleGet(name)
        if error:
            continue
        else:
            if is_clusterrole_exists:
                logger.info("ClusterRole %s already exists" % name) # WARNING
            else:
                k8sClusterRoleCreate(name, roleVars[role])
                logger.info("ClusterRole %s created" % name) # WARNING

    for role in namespaced_role_list:
        name = "template-namespaced-resources___" + role
        is_clusterrole_exists, error = k8sClusterRoleGet(name)
        if error:
            continue
        else:
            if is_clusterrole_exists:
                logger.info("ClusterRole %s already exists" % name) # WARNING
            else:
                k8sClusterRoleCreate(name, roleVars[role])
                logger.info("ClusterRole %s created" % name) # WARNING

##############################################################
## Kubernetes Nodes
##############################################################

def k8sListNodes(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    node_list = list()
    try:
        node_list = k8s_client.CoreV1Api().list_node()
        return node_list, None
    except ApiException as e:
        return node_list, e

def k8sNodesListGet(username_role, user_token):
    k8sClientConfigGet(username_role, user_token)
    nodes, error = k8sListNodes(username_role, user_token)
    NODE_LIST = []
    if error is None:
        for no in nodes.items:
            NODE_INFO = {
                "status": "",
                "name": "",
                "role": "",
                "version": "",
                "os": "",
                "runtime": "",
                "taint": list(),
            }
            NODE_INFO['name'] = no.metadata.name
            taints = no.spec.taints
            if taints:
                for t in taints:
                    if t.value:
                        NODE_INFO["taint"].append(t.key + "=" + t.value)
                    else:
                        NODE_INFO["taint"].append(t.key + "=")
            NODE_INFO['role'] = None
            for label, value in no.metadata.labels.items():
                if label == "kubernetes.io/os":
                    NODE_INFO['os'] = value
                elif label == "node-role.kubernetes.io/master":
                    NODE_INFO['role'] = "Master"
            for key, value in no.status.node_info.__dict__.items():
                if key == "_container_runtime_version":
                    NODE_INFO['runtime'] = value
                elif key == "_kubelet_version":
                    NODE_INFO['version'] = value
            
            for key, value in no.status.conditions[-1].__dict__.items():
                if key == "_type":
                    NODE_INFO['status'] = value
            if NODE_INFO['role'] == None:
                NODE_INFO['role'] = "Worker"
            NODE_LIST.append(NODE_INFO)
        return NODE_LIST
    else:
        ErrorHandler(error, "get node list")
        return NODE_LIST

##############################################################
## StatefulSets
##############################################################

def k8sStatefulSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    STATEFULSET_LIST = list()
    try:
        statefulset_list = k8s_client.AppsV1Api().list_namespaced_stateful_set(ns)
        for sfs in statefulset_list.items:
            STATEFULSET_DATA = {
                "name": sfs.metadata.name,
                "desired": "",
                "current": "",
                "ready": "",
            }
            if sfs.status.replicas:
                STATEFULSET_DATA['desired'] = sfs.status.replicas
            else:
                STATEFULSET_DATA['desired'] = 0
            if sfs.status.current_replicas:
                STATEFULSET_DATA['current'] = sfs.status.current_replicas
            else:
                STATEFULSET_DATA['current'] = 0
            if sfs.status.ready_replicas:
                STATEFULSET_DATA['ready'] = sfs.status.ready_replicas
            else:
                STATEFULSET_DATA['ready'] = 0
            STATEFULSET_LIST.append(STATEFULSET_DATA)
        return STATEFULSET_LIST
    except ApiException as error:
        ErrorHandler(error, "get statefullsets list")
        return STATEFULSET_LIST

##############################################################
## DaemonSets
##############################################################

def k8sDaemonSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    DAEMONSET_LIST = list()
    try:
        daemonset_list = k8s_client.AppsV1Api().list_namespaced_daemon_set(ns)
        for ds in daemonset_list.items:
            DAEMONSET_DATA = {
                "name": ds.metadata.name,
                "desired": "",
                "current": "",
                "ready": "",
            }
            if ds.status.desired_number_scheduled:
                DAEMONSET_DATA['desired'] = ds.status.desired_number_scheduled
            else:
                DAEMONSET_DATA['desired'] = 0
            if ds.status.current_number_scheduled:
                DAEMONSET_DATA['current'] = ds.status.current_number_scheduled
            else:
                DAEMONSET_DATA['current'] = 0
            if ds.status.number_ready:
                DAEMONSET_DATA['ready'] = ds.status.number_ready
            else:
                DAEMONSET_DATA['ready'] = 0
            DAEMONSET_LIST.append(DAEMONSET_DATA)
        return DAEMONSET_LIST
    except ApiException as error:
        ErrorHandler(error, "get daemonsets list")
        return DAEMONSET_LIST

##############################################################
## Deployments
##############################################################

def k8sDeploymentsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    DEPLOYMENT_LIST = list()
    try:
        deployment_list = k8s_client.AppsV1Api().list_namespaced_deployment(ns)
        for d in deployment_list.items:
            DEPLOYMENT_DATA = {
                "name": d.metadata.name,
                "status": "",
            }
            if d.status.ready_replicas and d.status.replicas:
                DEPLOYMENT_DATA['status'] = "%s/%s" % (d.status.ready_replicas, d.status.replicas)
            else:
                DEPLOYMENT_DATA['status'] = "0/0"
            DEPLOYMENT_LIST.append(DEPLOYMENT_DATA)
        return DEPLOYMENT_LIST
    except ApiException as error:
        ErrorHandler(error, "get deployments list")
        return DEPLOYMENT_LIST

##############################################################
## ReplicaSets
##############################################################

def k8sReplicaSetsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    REPLICASET_LIST = list()
    try:
        replicaset_list = k8s_client.AppsV1Api().list_namespaced_replica_set(ns)
        for rs in replicaset_list.items:
            REPLICASET_DATA = {
                "name": rs.metadata.name,
                "owner": "",
                "desired": "",
                "current": "",
                "ready": "",
            }
            if rs.status.fully_labeled_replicas:
                REPLICASET_DATA['desired'] = rs.status.fully_labeled_replicas
            else:
                REPLICASET_DATA['desired'] = 0
            if rs.status.available_replicas:
                REPLICASET_DATA['current'] = rs.status.available_replicas
            else:
                REPLICASET_DATA['current'] = 0
            if rs.status.ready_replicas:
                REPLICASET_DATA['ready'] = rs.status.ready_replicas
            else:
                REPLICASET_DATA['ready'] = 0
            if rs.metadata.owner_references:
                for owner in rs.metadata.owner_references:
                    REPLICASET_DATA['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
            REPLICASET_LIST.append(REPLICASET_DATA)
        return REPLICASET_LIST
    except ApiException as error:
        ErrorHandler(error, "get replicasets list")
        return REPLICASET_LIST

##############################################################
## Pods
##############################################################

def k8sPodListGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    POD_LIST = list()
    print(ns)
    try:
        pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns)
        for pod in pod_list.items:
            POD_SUM = {
                "name": pod.metadata.name,
                "status": pod.status.phase,
                "owner": "",
                "pod_ip": pod.status.pod_ip,
            }
            if pod.metadata.owner_references:
                for owner in pod.metadata.owner_references:
                    POD_SUM['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
            POD_LIST.append(POD_SUM)
        return POD_LIST
    except ApiException as error:
        ErrorHandler(error, "get pod list")
        return POD_LIST

def k8sPodGet(username_role, user_token, ns, po):
    k8sClientConfigGet(username_role, user_token)
    POD_DATA = {}
    try: 
        pod_data = k8s_client.CoreV1Api().read_namespaced_pod(po, ns)
        POD_DATA = {
            # main
            "name": po, # X
            "namespace": ns, # X
            "labels": list(), # X
            "owner": "", # X
            "node": pod_data.spec.node_name, # X
            "priority": pod_data.spec.priority, # X
            "priority_class_name": pod_data.spec.priority_class_name, # X
            "runtime_class_name": pod_data.spec.runtime_class_name, # X
            # Containers
            "containers": list(), # X
            "init_containers": list(), # X
            #  Related Resources
            "image_pull_secrets": [], # X
            "service_account": pod_data.spec.service_account_name, # X
            "pvc": list(), # X
            "cm": list(), # X
            "secrets": list(),
            # Security
            "security_context": pod_data.spec.security_context.to_dict(),
            # Conditions
            "conditions": list(),
        }
        if pod_data.metadata.labels:
            for key, value in pod_data.metadata.labels.items():
                label = {
                    key: value
                }
                POD_DATA['labels'].append(label)
        if pod_data.metadata.owner_references:
            for owner in pod_data.metadata.owner_references:
                POD_DATA['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
        for c in  pod_data.spec.containers:
            if c.env:
                for e in c.env:
                    ed = e.to_dict()
                    for name, val in ed.items():
                        if "value_from" in name and val is not None:
                            for key, value in val.items():
                                if "secret_key_ref" in key and value:
                                    for n, v in value.items():
                                        if "name" in n:
                                            POD_DATA['secrets'].append(v)
            for cs in pod_data.status.container_statuses:
                if cs.name == c.name:
                    if cs.ready:
                        CONTAINERS = {
                            "name": c.name,
                            "image": c.image,
                            "ready": "Running",
                            "restarts": cs.restart_count,
                        }
                    else:
                        CONTAINERS = {
                            "name": c.name,
                            "image": c.image,
                            "ready": cs.state.waiting.reason,
                            "restarts": cs.restart_count,
                        }
            POD_DATA['containers'].append(CONTAINERS)
        if pod_data.spec.init_containers:
            for ic in pod_data.spec.init_containers:
                for ics in pod_data.status.init_container_statuses:
                    if ics.name == ic.name:
                        if ics.ready:
                            CONTAINERS = {
                                "name": ic.name,
                                "image": ic.image,
                                "ready": ics.state.terminated.reason,
                                "restarts": ics.restart_count,
                            }
                        else:
                            CONTAINERS = {
                                "name": ic.name,
                                "image": ic.image,
                                "ready": ics.state.waiting.reason,
                                "restarts": ics.restart_count,
                            }
                        POD_DATA['init_containers'].append(CONTAINERS)
        if pod_data.spec.image_pull_secrets:
            for ips in pod_data.spec.image_pull_secrets:
                POD_DATA['image_pull_secrets'].append(ips.to_dict())
        for v in pod_data.spec.volumes:
            # secret
            if v.persistent_volume_claim:
                POD_DATA['pvc'].append(v.persistent_volume_claim.claim_name)
            if v.config_map:
                POD_DATA['cm'].append(v.config_map.name)
            if v.secret:
                POD_DATA['secrets'].append(v.secret.secret_name)
        for c in pod_data.status.conditions:
            CONDITION = {
                c.type: c.status
            }
            POD_DATA['conditions'].append(CONDITION)
        return POD_DATA
    except ApiException as error:
        ErrorHandler(error, "get pods in this namespace")
        return POD_DATA

def k8sPodListVulnsGet(username_role, user_token, ns):
    k8sClientConfigGet(username_role, user_token)
    POD_VULN_LIST = list()
    pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns)
    try:
        vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object("trivy-operator.devopstales.io", "v1", ns, "vulnerabilityreports")
        HAS_REPORT = True
    except:
        vulnerabilityreport_list = False
        HAS_REPORT = False

    for pod in pod_list.items:
        POD_VULN_SUM = {
            "name": pod.metadata.name,
            "status": pod.status.phase,
            "owner": "",
            "pod_ip": pod.status.pod_ip,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "scan_status": None,
        }
        if pod.metadata.owner_references:
            for owner in pod.metadata.owner_references:
                POD_VULN_SUM['owner'] = "%ss/%s" % (owner.kind.lower(), owner.name)
        
        if vulnerabilityreport_list:
            for vr in vulnerabilityreport_list['items']:
                if vr['metadata']['labels']['trivy-operator.pod.name'] == pod.metadata.name:
                    POD_VULN_SUM['critical'] += vr['report']['summary']['criticalCount']
                    POD_VULN_SUM['high'] += vr['report']['summary']['highCount']
                    POD_VULN_SUM['medium'] += vr['report']['summary']['mediumCount']
                    POD_VULN_SUM['low'] += vr['report']['summary']['lowCount']

        if POD_VULN_SUM['critical'] > 0 or POD_VULN_SUM['high'] > 0 or POD_VULN_SUM['medium'] > 0 or POD_VULN_SUM['low'] > 0:
            POD_VULN_SUM['scan_status'] = "OK"
        POD_VULN_LIST.append(POD_VULN_SUM)

    return HAS_REPORT, POD_VULN_LIST

def k8sPodVulnsGet(username_role, user_token, ns, pod):
    k8sClientConfigGet(username_role, user_token)
    pod_list = k8s_client.CoreV1Api().list_namespaced_pod(ns)
    try:
        vulnerabilityreport_list = k8s_client.CustomObjectsApi().list_namespaced_custom_object("trivy-operator.devopstales.io", "v1", ns, "vulnerabilityreports")
    except:
        vulnerabilityreport_list = None

    for po in pod_list.items:
        POD_VULNS = {}
        HAS_REPORT = False
        if po.metadata.name == pod:
            if vulnerabilityreport_list is not None:
                if po.status.phase:
                    HAS_REPORT = True
                    for vr in vulnerabilityreport_list['items']:
                        if vr['metadata']['labels']['trivy-operator.pod.name'] == po.metadata.name:
                            VULN_LIST = list()
                            for vuln in vr['report']['vulnerabilities']:
                                VULN_LIST.append({
                                    "vulnerabilityID": vuln['vulnerabilityID'],
                                    "severity": vuln['severity'],
                                    "score": vuln['score'],
                                    "resource": vuln['resource'],
                                    "installedVersion": vuln['installedVersion'],
                                    #"publishedDate": vuln['publishedDate'],
                                    #"fixedVersion": vuln['fixedVersion'],
                                })
                            POD_VULNS.update({vr['metadata']['labels']['trivy-operator.container.name']: VULN_LIST})
        return HAS_REPORT, POD_VULNS

        # PublishedDate, FixedVersion