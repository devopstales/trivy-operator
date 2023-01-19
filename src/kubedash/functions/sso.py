#!/usr/bin/env python3

from __main__ import db, login_manager
from flask_login import UserMixin
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy import PickleType

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

def SSOUserCreate(oauth_server_uri, client_id, client_secret, base_uri, scopes):
    sso = Openid.query.filter_by(oauth_server_uri=oauth_server_uri).first()
    sso_data = Openid(
        oauth_server_uri = oauth_server_uri,
        client_id = client_id,
        client_secret = client_secret,
        base_uri = base_uri,
        scope = []
    )
    sso_data.scope.append(scopes)
    print(sso_data)
    if sso is None:
        db.session.add(sso_data)
        db.session.commit()

def SSOUserGet():
    return Openid.query.get(1)