#!/usr/bin/env python3

from __main__ import db
from flask_login import UserMixin
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy import PickleType
from requests_oauthlib import OAuth2Session

##############################################################
## functions
##############################################################

class Openid(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    oauth_server_uri = db.Column(db.Text, unique=True, nullable=False)
    client_id = db.Column(db.Text, nullable=False)
    client_secret = db.Column(db.Text, nullable=False)
    base_uri = db.Column(db.Text, nullable=False)
    scope = db.Column(MutableList.as_mutable(PickleType), default=[], nullable=False)

    def __repr__(self):
        return '<Server URL %r>' % self.oauth_server_uri

def SSOServerCreate(oauth_server_uri, client_id, client_secret, base_uri, scopes):
    sso = Openid.query.filter_by(oauth_server_uri=oauth_server_uri).first()
    sso_data = Openid(
        oauth_server_uri = oauth_server_uri,
        client_id = client_id,
        client_secret = client_secret,
        base_uri = base_uri,
        scope = []
    )
    sso_data.scope = scopes
    if sso is None:
        db.session.add(sso_data)
        db.session.commit()

def SSOServerUpdate(oauth_server_uri_old, oauth_server_uri, client_id, client_secret, base_uri, scope):
    sso = Openid.query.filter_by(oauth_server_uri=oauth_server_uri_old).first()
    if sso:
        sso.oauth_server_uri = oauth_server_uri
        sso.client_id = client_id
        sso.client_secret = client_secret
        sso.base_uri = base_uri
        sso.scope = scope
        db.session.commit()

def SSOSererGet():
    return Openid.query.get(1)

def get_auth_server_info():
    ssoServer = SSOSererGet()
    redirect_uri = ssoServer.base_uri+"/callback"
    oauth = OAuth2Session(
        ssoServer.client_id,
        redirect_uri = redirect_uri,
        scope = ssoServer.scope
    )
    try:
        auth_server_info = oauth.get(
            f"{ssoServer.oauth_server_uri}/.well-known/openid-configuration",
            withhold_token=True,
            verify=False,
            timeout=1
        ).json()
    except:
        auth_server_info = None
    return auth_server_info, oauth