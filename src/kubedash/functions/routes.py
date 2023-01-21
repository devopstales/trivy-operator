#!/usr/bin/env python3

from __main__ import app
import requests, json, yaml, re
from functions.user import email_check, User, UserCreate, UserUpdate, UserDelete, \
    UserCreateSSO
from functions.sso import SSOServerCreate, SSOSererGet, get_auth_server_info
from functions.k8s import k8sConfigCreate, k8sConfigGet
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
            oauth, auth_server_info = get_auth_server_info()
            auth_url = auth_server_info["authorization_endpoint"]
            authorization_url, state = oauth.authorization_url(
                auth_url,
                access_type="offline",  # not sure if it is actually always needed,
                                        # may be a cargo-cult from Google-based example
            )
            session['oauth_state'] = state
            is_sso_enabled = True

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
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        UserUpdate(username, role)
        flash("User Updated Successfully", "success")

    users = User.query

    return render_template(
        'users.html',
#        base_uri=base_uri,
        users=users,
        current_username=current_username,
        username_role=username_role,
#        namespace_list=namespace_list,
#        user_clusterRole_template_list=user_clusterRole_template_list,
#        user_role_template_list=user_role_template_list,
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
        scope = request.form['scope']

        SSOServerCreate(
            oauth_server_uri,
            client_id, 
            client_secret,
            username_role, 
            base_uri,
            scope
        )
        flash("SSO Server Updated Successfully", "success")
        return render_template(
            'sso.html',
            oauth_server_uri = oauth_server_uri,
            client_id = client_id,
            client_secret = client_secret,
            base_uri = base_uri,
            scope = scope,
            current_username=current_username,
            username_role=username_role,
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
        oauth, auth_server_info = get_auth_server_info()
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
        k8sConfig = k8sConfigGet()
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
    oauth, auth_server_info = get_auth_server_info()
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
    current_username = current_user.username
    user_tmp = User.query.filter_by(username=current_username).first()
    username_role = user_tmp.role
    if request.method == 'POST':
        print(request.form)
        k8s_server_url = request.form['k8s_server_url']
        k8s_context = request.form['k8s_context']
        k8s_server_ca = str(base64_encode(request.form['k8s_server_ca']), 'UTF-8')
        

        k8sConfigCreate(k8s_server_url, k8s_context, k8s_server_ca)
        flash("Kubernetes Config Updated Successfully", "success")

        return render_template(
            'k8s.html',
            k8s_server_url = k8s_server_url,
            k8s_context = k8s_context,
            k8s_server_ca = k8s_server_ca,
            current_username = current_username,
            username_role = username_role,
        )
    else:
        k8sConfig = k8sConfigGet()
        if k8sConfig is None:
            return render_template('k8s.html')
        else:
            k8s_server_ca = str(base64_decode(k8sConfig.k8s_server_ca), 'UTF-8')
            return render_template(
                'k8s.html',
                k8s_server_url = k8sConfig.k8s_server_url,
                k8s_context = k8sConfig.k8s_context,
                k8s_server_ca = k8s_server_ca,
                current_username = current_username,
                username_role = username_role,
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
        k8sConfig = k8sConfigGet()
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
    k8sConfig = k8sConfigGet()
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