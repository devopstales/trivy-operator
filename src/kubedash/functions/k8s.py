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
    k8s_context = db.Column(db.Text, nullable=False)
    k8s_server_ca = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Kubernetes Server URL %r>' % self.k8s_server_url

def k8sConfigCreate(k8s_server_url, k8s_context, k8s_server_ca):
    k8s = k8sConfig.query.filter_by(k8s_server_url=k8s_server_url).first()
    k8s_data = k8sConfig(
        k8s_server_url = k8s_server_url,
        k8s_context = k8s_context,
        k8s_server_ca = k8s_server_ca
    )
    if k8s is None:
        db.session.add(k8s_data)
        db.session.commit()

def k8sConfigGet():
    return k8sConfig.query.get(1)

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

def k8sGetConfig(username_role, user_token):
    k8sConfig = k8sConfigGet()
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
    k8sGetConfig(username_role, user_token)
    try:
        namespace_list = k8s_client.CoreV1Api().list_namespace()
        return namespace_list, None
    except ApiException as e:
        namespace_list = ""
        return namespace_list, e

def k8sGetNamespaceList(username_role, user_token):
    k8sGetConfig(username_role, user_token)
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

def k8sGetNamespaces(username_role, user_token):
    k8sGetConfig(username_role, user_token)
    NAMESPACE_LIST = []
    try:
        namespaces, error = k8sListNamespaces(username_role, user_token)
        if error is None:
            for ns in namespaces.items:
                NAMESPACE_DADTA = {
                    "name": "",
                    "staus": "",
                }
                NAMESPACE_DADTA['name'] = ns.metadata.name
                NAMESPACE_DADTA['staus'] = ns.status.__dict__['_phase']
                NAMESPACE_LIST.append(NAMESPACE_DADTA)
            return NAMESPACE_LIST
        else:
            ErrorHandler(error, "list namespaces")
            return NAMESPACE_LIST
    except:
        return NAMESPACE_LIST

def k8sCreateNamespace(username_role, user_token, ns_name):
    k8sGetConfig(username_role, user_token)
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

def k8sDeleteNamespace(username_role, user_token, ns_name):
    k8sGetConfig(username_role, user_token)
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

def k8sGetUserClusterRoleTemplateList(username_role, user_token):
    k8sGetConfig(username_role, user_token)
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

def k8sGetUserRoleTemplateList(username_role, user_token):
    k8sGetConfig(username_role, user_token)
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

def k8sGetClusterRole(name):
    k8sGetConfig("Admin", None)
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

def k8sCreateClusterRole(name, body):
    k8sGetConfig("Admin", None)
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

def k8sAddClusterRoles():
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
        is_clusterrole_exists, error = k8sGetClusterRole(name)
        if error:
            continue
        else:
            if is_clusterrole_exists:
                logger.info("ClusterRole %s alredy exists" % name) # WARNING
            else:
                k8sCreateClusterRole(name, roleVars[role])

##############################################################
## Kubernetes Nodes
##############################################################

def k8sListNodes(username_role, user_token):
    k8sGetConfig(username_role, user_token)
    node_list = list()
    try:
        node_list = k8s_client.CoreV1Api().list_node()
        return node_list, None
    except ApiException as e:
        return node_list, e

def k8sGetNodesList(username_role, user_token):
    k8sGetConfig(username_role, user_token)
    nodes, error = k8sListNodes(username_role, user_token)
    NODE_LIST = []
    NODE_INFO = {
        "status": "",
        "name": "",
        "role": "",
        "version": "",
        "os": "",
        "runtime": "",
        "taint": "",
    }
    if error is None:
        for no in nodes.items:
            NODE_INFO['name'] = no.metadata.name
            TAINTS = no.spec.taints
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