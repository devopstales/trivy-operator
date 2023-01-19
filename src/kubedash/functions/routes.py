#!/usr/bin/env python3

from __main__ import app
import requests, json, yaml, re
from functions.user import email_check, User, UserCreate, UserUpdate, UserDelete, \
    UserCreateSSO
from functions.sso import SSOUserCreate, SSOSererGet, get_auth_server_info
from flask import jsonify, session, render_template, request, redirect, flash, url_for, \
    Response
from flask_login import login_user, login_required, current_user, logout_user
from werkzeug.security import check_password_hash

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
        return redirect(url_for('login')) # if user doesn't exist or password is wrong/export, reload the page
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
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        UserUpdate(username, role)
        flash("User Updated Successfully", "success")

    users = User.query
    current_username = current_user.username

    user_tmp = User.query.filter_by(username=current_username).first()
    username_type = user_tmp.user_type
    username_role = user_tmp.role

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
    if request.method == 'POST':
        oauth_server_uri = request.form['oauth_server_uri']
        client_id = request.form['client_id']
        client_secret = request.form['client_secret']
#        base_uri = request.form['base_uri']
#        scope = request.form['scope']

        base_uri = "http://localhost:8000"
        scope = [
            "openid",          # mandatory for OpenIDConnect auth
            "email",           # smallest and most consistent scope and claim
            "offline_access",  # needed to actually ask for refresh_token
            "good-service",
            "profile",
        ]

        SSOUserCreate(oauth_server_uri, client_id, client_secret, base_uri, scope)
        flash("SSO Server Updated Successfully", "success")
        return render_template(
            'sso.html',
            oauth_server_uri = oauth_server_uri,
            client_id = client_id,
            client_secret = client_secret,
            base_uri = base_uri,
            scope = scope,
        )
    else:
        ssoServer = SSOSererGet()
        if ssoServer is None:
            return render_template('sso.html')
        else:
            return render_template(
                'sso.html',
                oauth_server_uri = ssoServer.oauth_server_uri,
                client_id = ssoServer.client_id,
                client_secret = ssoServer.client_secret,
                base_uri = ssoServer.base_uri,
                scope  = ssoServer.scope,
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
            authorization_response=request.url,
            client_secret=ssoServer.client_secret,
            timeout=60,
            verify=False,
        )
        user_data = oauth.get(
            userinfo_url,
            timeout=60,
            verify=False,
        ).json()

        if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
            remote_addr = request.remote_addr
        else:
            remote_addr = request.environ['HTTP_X_FORWARDED_FOR']

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