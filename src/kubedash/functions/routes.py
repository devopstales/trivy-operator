#!/usr/bin/env python3

from __main__ import app
import requests, json, yaml, re
from functions.user import email_check, User, UserCreate, UserUpdate, UserDelete
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
        return render_template('login.html')

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
