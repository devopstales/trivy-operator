#!/usr/bin/env python3

from __main__ import app
import requests, json, yaml
from functions.user import email_check, User, UserCreate, UserUpdate, UserDelete, \
    UserCreateSSO
from functions.sso import SSOServerCreate, SSOSererGet, SSOServerUpdate, get_auth_server_info
from functions.k8s import k8sNodesListGet, \
    k8sServerConfigCreate, k8sServerConfigGet, k8sServerConfigList, k8sServerDelete, k8sServerConfigUpdate, \
    k8sNamespaceListGet, k8sNamespacesGet, k8sNamespaceCreate, k8sNamespaceDelete, \
    k8sUserClusterRoleTemplateListGet, k8sUserRoleTemplateListGet, \
    k8sStatefulSetsGet, k8sDaemonSetsGet, k8sDeploymentsGet, k8sReplicaSetsGet, \
    k8sPodListGet, k8sPodGet, \
    k8sPodListVulnsGet, k8sPodVulnsGet
from flask import jsonify, session, render_template, request, redirect, flash, url_for, \
    Response
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import check_password_hash
from itsdangerous import base64_encode, base64_decode

##############################################################
## health
##############################################################

@app.route('/ping', methods=['GET'])
def test():
    return 'pong'

@app.route('/health', methods=['GET'])
def health():
    resp = jsonify(health="healthy")
    resp.status_code = 200
    return resp

##############################################################
## Login
##############################################################

@app.route('/')
def login():
        is_sso_enabled = False
        is_ldap_enabled = False
        authorization_url = None

        ssoServer = SSOSererGet()
        if ssoServer is not None:
            auth_server_info, oauth = get_auth_server_info()
            if auth_server_info is not None:
                auth_url = auth_server_info["authorization_endpoint"]
                authorization_url, state = oauth.authorization_url(
                    auth_url,
                    access_type="offline",  # not sure if it is actually always needed,
                                            # may be a cargo-cult from Google-based example
                )
                session['oauth_state'] = state
                is_sso_enabled = True
            else:
                is_sso_enabled = False
                flash('Cannot connect to identity provider!', "warning")


        return render_template(
            'login.html',
            sso_enabled = is_sso_enabled,
            ldap_enabled = is_ldap_enabled,
            auth_url = authorization_url
        )

@app.route('/', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username, user_type = "Local").first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password_hash, password):
        flash('Please check your login details and try again.', "warning")
        return redirect(url_for('login')) # if user doesn't exist or password is wrong, reload the page
    else:
        login_user(user, remember=remember)
        return redirect(url_for('users'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    try:
        session.pop('oauth_token')
    except:
        print()
    return redirect(url_for('login'))

##############################################################
## Users and Privileges
##############################################################

@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        UserUpdate(username, role)
        flash("User Updated Successfully", "success")

    users = User.query
    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None
    namespace_list = k8sNamespaceListGet(username_role, user_token)
    user_clusterRole_template_list = k8sUserClusterRoleTemplateListGet(username_role, user_token)
    user_role_template_list = k8sUserRoleTemplateListGet(username_role, user_token)
    
    if not bool(user_clusterRole_template_list) or not bool(user_role_template_list):
        from functions.k8s import k8sClusterRolesAdd
        k8sClusterRolesAdd()

    return render_template(
        'users.html',
        users = users,
        current_username = current_username,
        username_role = username_role,
        namespace_list = namespace_list,
        user_clusterRole_template_list = user_clusterRole_template_list,
        user_role_template_list = user_role_template_list,
    )

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def users_add():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        password = request.form['password']
        email = request.form['email']
        email_test = bool(email_check(email))
        if not email_test:
            flash("Email is not valid", "danger")
            return redirect(url_for('users'))
        elif not len(password) >= 8:
            flash("Password must be 8 character in length", "danger")
            return redirect(url_for('users'))
        else:
            UserCreate(username, password, email, role, "Local", None)
            flash("User Created Successfully", "success")
            return redirect(url_for('users'))
    else:
        return redirect(url_for('login'))

@app.route('/users/delete', methods=['GET', 'POST'])
@login_required
def users_delete():
    if request.method == 'POST':
        username = request.form['username']
        UserDelete(username)
        flash("User Deleted Successfully", "success")
        return redirect(url_for('users'))
    else:
        return redirect(url_for('login'))

##############################################################
## SSO Settings
##############################################################

@app.route('/sso-config', methods=['GET', 'POST'])
@login_required
def sso_config():
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    if request.method == 'POST':
        oauth_server_uri = request.form['oauth_server_uri']
        client_id = request.form['client_id']
        client_secret = request.form['client_secret']
        base_uri = request.form['base_uri']
        if not base_uri:
            base_uri = request.root_url.rstrip(request.root_url[-1])
        scope = request.form.getlist('scope')
        while("" in scope):
            scope.remove("")

        request_type = request.form['request_type']
        if request_type == "edit":
            oauth_server_uri_old = request.form['oauth_server_uri_old']
            SSOServerUpdate(oauth_server_uri_old, oauth_server_uri, client_id, client_secret, base_uri, scope)
        elif request_type == "create":
            SSOServerCreate(oauth_server_uri, client_id, client_secret, base_uri, scope)

        flash("SSO Server Updated Successfully", "success")
        return render_template(
            'sso.html',
            oauth_server_uri = oauth_server_uri,
            client_id = client_id,
            client_secret = client_secret,
            base_uri = base_uri,
            scope = scope,
            current_username = current_username,
            username_role = username_role,
        )
    else:
        ssoServer = SSOSererGet()
        if ssoServer is None:
            return render_template(
                'sso.html',
                base_uri = request.root_url.rstrip(request.root_url[-1]),
                current_username = current_username,
                username_role = username_role,
                scope = [
                    "openid",          # mandatory for OpenIDConnect auth
                    "email",           # smallest and most consistent scope and claim
                    "offline_access",  # needed to actually ask for refresh_token
                    "good-service",
                    "profile",
                ]
            )
        else:
            return render_template(
                'sso.html',
                oauth_server_uri = ssoServer.oauth_server_uri,
                client_id = ssoServer.client_id,
                client_secret = ssoServer.client_secret,
                base_uri = ssoServer.base_uri,
                scope  = ssoServer.scope,
                current_username = current_username,
                username_role = username_role,
            )

@app.route("/callback", methods=["GET"])
def callback():
    if 'error' in request.args:
        if request.args.get('error') == 'access_denied':
            flash('Access denied.', "danger")
        else:
            flash('Error encountered.', "danger")
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        ssoServer = SSOSererGet()
        auth_server_info, oauth = get_auth_server_info()
        token_url = auth_server_info["token_endpoint"]
        userinfo_url = auth_server_info["userinfo_endpoint"]

        token = oauth.fetch_token(
            token_url,
            authorization_response = request.url,
            client_secret = ssoServer.client_secret,
            timeout = 60,
            verify = False,
        )
        user_data = oauth.get(
            userinfo_url,
            timeout = 60,
            verify = False,
        ).json()

        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            remote_addr = request.remote_addr
        else:
            remote_addr = request.environ['HTTP_X_FORWARDED_FOR']

## Kubectl config
        k8sConfig = k8sServerConfigGet()
        if k8sConfig is None:
            app.logger.error ("Kubectl Integration is not configured.")
        else:
            # add /info for k8s plugin
            # test /info anf send answer if is dtlogin
            try:
                x = requests.post('http://%s:8080/' % remote_addr, json={
                    "context": k8sConfig.k8s_context,
                    "server": k8sConfig.k8s_server_url,
                    "certificate-authority-data": k8sConfig.k8s_server_ca,
                    "client-id": ssoServer.client_id,
                    "id-token": token["id_token"],
                    "refresh-token": token.get("refresh_token"),
                    "idp-issuer-url": ssoServer.oauth_server_uri,
                    "client_secret": ssoServer.client_secret,
                    }
                )
                app.logger.info("Config sent to client")
                app.logger.info("Answer from clinet: %s" % x.text)
            except:
                app.logger.error ("Kubectl print back error")

        session['oauth_token'] = token
        session['refresh_token'] = token.get("refresh_token")
        email = user_data['email']
        username = user_data["preferred_username"]
        user_token = json.dumps(token)
        user = User.query.filter_by(username=username).first()
        if user is None:
            UserCreateSSO(username, email, user_token, "OpenID")
            user = User.query.filter_by(username=username, user_type = "OpenID").first()
        login_user(user)
        return redirect(url_for('users'))

##############################################################
## Kubectl config
##############################################################

@app.route('/dtlogin')
def index():
    auth_server_info, oauth = get_auth_server_info()
    auth_url = auth_server_info["authorization_endpoint"]

    authorization_url, state = oauth.authorization_url(
        auth_url,
        access_type="offline",  # not sure if it is actually always needed,
                                # may be a cargo-cult from Google-based example
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/k8s-config', methods=['GET', 'POST'])
@login_required
def k8s_config():
    if request.method == 'POST':
        request_type = request.form['request_type']
        if request_type == "create":
            k8s_server_url = request.form['k8s_server_url']
            k8s_context = request.form['k8s_context']
            k8s_server_ca = str(base64_encode(request.form['k8s_server_ca']), 'UTF-8')

            k8sServerConfigCreate(k8s_server_url, k8s_context, k8s_server_ca)
            flash("Kubernetes Config Updated Successfully", "success")
        elif request_type == "edit":
            k8s_server_url = request.form['k8s_server_url']
            k8s_context = request.form['k8s_context']
            k8s_context_old = request.form['k8s_context_old']
            k8s_server_ca = str(base64_encode(request.form['k8s_server_ca']), 'UTF-8')

            k8sServerConfigUpdate(k8s_context_old, k8s_server_url, k8s_context, k8s_server_ca)
            flash("Kubernetes Config Updated Successfully", "success")
        elif request_type == "delete":
            k8s_context = request.form['k8s_context']
            k8sServerDelete(k8s_context)

    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    k8s_servers = k8sServerConfigList()

    return render_template(
        'k8s.html',
        current_username = current_username,
        username_role = username_role,
        k8s_servers = k8s_servers,
    )



@app.route('/export')
@login_required
def export():
    username = current_user.username
    user = User.query.filter_by(username=username, user_type = "OpenID").first()
    user_tmp = User.query.filter_by(username=username).first()
    username_role = user_tmp.role
    if user is None:
        return render_template(
            'export.html',
            preferred_username = current_user.username,
            username_role = username_role
        )
    else:
        ssoServer = SSOSererGet()
        redirect_uri = ssoServer.base_uri+"/callback"
        k8sConfig = k8sServerConfigGet()
        k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
        auth_server_info, oauth = get_auth_server_info()

        token_url = auth_server_info["token_endpoint"]
        token = oauth.refresh_token(
            token_url = token_url,
            refresh_token = session['refresh_token'],
            client_id = ssoServer.client_id,
            client_secret = ssoServer.client_secret,
            verify=False,
            timeout=60,
        )

        userinfo_url = auth_server_info["userinfo_endpoint"]
        user_data = oauth.get(
            userinfo_url,
            timeout=60,
            verify=False,
        ).json()

        return render_template(
            'export.html',
            preferred_username=user_data["preferred_username"],
            username_role = username_role,
            redirect_uri = redirect_uri,
            client_id = ssoServer.client_id,
            client_secret = ssoServer.client_secret,
            id_token = token["id_token"],
            refresh_token = token.get("refresh_token"),
            oauth_server_uri = ssoServer.oauth_server_uri,
            context = k8sConfig.k8s_context,
            k8s_server_url = k8sConfig.k8s_server_url,
            k8s_server_ca = k8s_server_ca
        )

@app.route("/get-file")
def get_file():
    ssoServer = SSOSererGet()
    k8sConfig = k8sServerConfigGet()
    auth_server_info, oauth = get_auth_server_info()
    token_url = auth_server_info["token_endpoint"]
    verify = False

    token = oauth.refresh_token(
        token_url = token_url,
        refresh_token = session['refresh_token'],
        client_id = ssoServer.client_id,
        client_secret = ssoServer.client_secret,
        verify = verify,
        timeout = 60,
    )

    kube_user = {
            "auth-provider": {
                "name": "oidc",
                "config": {
                    "client-id": ssoServer.client_id,
                    "idp-issuer-url": ssoServer.oauth_server_uri,
                    "id-token": token["id_token"],
                    "refresh-token": token.get("refresh_token"),
                }
            }
        }
    if ssoServer.client_secret:
        kube_user["auth-provider"]["config"]["client-secret"] = ssoServer.client_secret
    if verify:
        kube_user["auth-provider"]["config"]["idp-certificate-authority"] = verify
    
    kube_cluster = {
        "certificate-authority-data": k8sConfig.k8s_server_ca,
        "server": k8sConfig.k8s_server_url
    }
    kube_context = {
        "cluster": k8sConfig.context,
        "user": k8sConfig.context,
    }
    config_snippet = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": k8sConfig.context,
            "cluster": kube_cluster
        }],
        "contexts": [{
            "name": k8sConfig.context,
            "context": kube_context
        }],
        "current-context": k8sConfig.context,
        "preferences": {},
        "users": [{
            "name": k8sConfig.context,
            "user": kube_user
        }]
    }

    return Response(
            yaml.safe_dump(config_snippet),
            mimetype="text/yaml",
            headers={
                "Content-Disposition":
                "attachment;filename=kubecfg.yaml"
            }
    )
##############################################################
## Cluster
##############################################################
## Nodes
##############################################################

@app.route("/nodes", methods=['GET', 'POST'])
@login_required
def nodes():
    tr_select = None
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type

    if request.method == 'POST':
        tr_select = request.form.get('tr_select')

    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    node_data = k8sNodesListGet(username_role, user_token)

    return render_template(
        'nodes.html',
        nodes = node_data,
        current_username = current_username,
        username_role = username_role,
        tr_select = tr_select,
    )

##############################################################
## Namespaces
##############################################################

@app.route("/namespaces")
@login_required
def namespaces():
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type

    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    namespace_list = k8sNamespacesGet(username_role, user_token)

    return render_template(
        'namespaces.html',
        namespace_list = namespace_list,
        current_username = current_username,
        username_role = username_role,
    )

@app.route("/namespaces/create", methods=['GET', 'POST'])
@login_required
def namespaces_create():
    if request.method == 'POST':
        namespace = request.form['namespace']
        current_username = current_user.username
        user_tmp = User.query.filter_by(username=current_username).first()
        username_role = user_tmp.role
        username_type = user_tmp.user_type

        if username_type == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        k8sNamespaceCreate(username_role, user_token, namespace)
        return redirect(url_for('namespaces'))
    else:
        return redirect(url_for('namespaces'))

@app.route("/namespaces/delete", methods=['GET', 'POST'])
@login_required
def namespaces_delete():
    if request.method == 'POST':
        namespace = request.form['namespace']
        current_username = current_user.username
        user_tmp = User.query.filter_by(username=current_username).first()
        username_role = user_tmp.role
        username_type = user_tmp.user_type

        if username_type == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        k8sNamespaceDelete(username_role, user_token, namespace)
        return redirect(url_for('namespaces'))
    else:
        return redirect(url_for('namespaces'))

##############################################################
## Workloads
##############################################################
## Statefullsets
##############################################################

@app.route("/statefulsets", methods=['GET', 'POST'])
@login_required
def statefulsets():
    ns_select = "default"
    tr_select = None
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type

    if request.method == 'POST':
        ns_select = request.form.get('ns_select')
        tr_select = request.form.get('tr_select')
        
    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    statefulset_list = k8sStatefulSetsGet(username_role, user_token, ns_select)
    namespace_list = k8sNamespaceListGet(username_role, user_token)

    return render_template(
        'statefulsets.html',
        ns_select = ns_select,
        tr_select = tr_select,
        statefulsets = statefulset_list,
        username_role = username_role,
        current_username = current_username,
        namespaces = namespace_list,
    )

##############################################################
## Daemonsets
##############################################################

@app.route("/daemonsets", methods=['GET', 'POST'])
@login_required
def daemonsets():
    ns_select = "default"
    tr_select = None
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type

    if request.method == 'POST':
        ns_select = request.form.get('ns_select')
        tr_select = request.form.get('tr_select')

    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    daemonset_list = k8sDaemonSetsGet(username_role, user_token, ns_select)
    namespace_list = k8sNamespaceListGet(username_role, user_token)

    return render_template(
        'daemonsets.html',
        ns_select = ns_select,
        daemonsets = daemonset_list,
        username_role = username_role,
        current_username = current_username,
        namespaces = namespace_list,
        tr_select = tr_select,
    )

##############################################################
## Deployments
##############################################################

@app.route("/deployments", methods=['GET', 'POST'])
@login_required
def deployments():
    ns_select = "default"
    tr_select = None
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type

    if request.method == 'POST':
        ns_select = request.form.get('ns_select')
        tr_select = request.form.get('tr_select')

    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    deployments_list = k8sDeploymentsGet(username_role, user_token, ns_select)
    namespace_list = k8sNamespaceListGet(username_role, user_token)

    return render_template(
        'deployments.html',
        ns_select = ns_select,
        tr_select = tr_select,
        deployments = deployments_list,
        username_role = username_role,
        current_username = current_username,
        namespaces = namespace_list,
    )

##############################################################
## ReplicaSets
##############################################################

@app.route("/replicasets", methods=['GET', 'POST'])
@login_required
def replicasets():
    ns_select = "default"
    tr_select = None
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type

    if request.method == 'POST':
        ns_select = request.form.get('ns_select')
        tr_select = request.form.get('tr_select')

    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    replicaset_list = k8sReplicaSetsGet(username_role, user_token, ns_select)
    namespace_list = k8sNamespaceListGet(username_role, user_token)

    return render_template(
        'replicasets.html',
        replicasets = replicaset_list,
        username_role = username_role,
        namespaces = namespace_list,
        current_username = current_username,
        ns_select = ns_select,
        tr_select = tr_select,
    )
##############################################################
## Pods
##############################################################

@app.route("/pods", methods=['GET', 'POST'])
@login_required
def pods():
    ns_select = "default"
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    username_type = user_tmp.user_type

    if request.method == 'POST':
        ns_select = request.form.get('ns_select')

    if username_type == "OpenID":
        user_token = session['oauth_token']
    else:
        user_token = None

    #pod_list = k8sPodListGet(username_role, user_token, ns_select)
    has_report, pod_list = k8sPodListVulnsGet(username_role, user_token, ns_select)
    namespace_list = k8sNamespaceListGet(username_role, user_token)

    return render_template(
        'pods.html',
        pods = pod_list,
        has_report = has_report,
        username_role = username_role,
        namespaces = namespace_list,
        current_username = current_username,
        ns_select = ns_select,
    )

@app.route('/pod-data', methods=['GET', 'POST'])
@login_required
def pods_data():
    if request.method == 'POST':
        po_name = request.form.get('po_name')
        ns_name = request.form.get('ns_name')
        current_username = current_user.username
        user_tmp = User.query.filter_by(username=current_username).first()
        username_role = user_tmp.role
        username_type = user_tmp.user_type

        if username_type == "OpenID":
            user_token = session['oauth_token']
        else:
            user_token = None

        pod_data = k8sPodGet(username_role, user_token, ns_name, po_name)
        has_report, pod_vulns = k8sPodVulnsGet(username_role, user_token, ns_name, po_name)
 
        return render_template(
            'pod-data.html',
            po_now = po_name,
            pod_data = pod_data,
            has_report = has_report,
            pod_vulns = pod_vulns,
            username_role = username_role,
            current_username = current_username,
        )
    else:
        return redirect(url_for('login'))