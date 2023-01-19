#!/usr/bin/env python3

from __main__ import db, login_manager
import re
from flask_login import UserMixin
from werkzeug.security import generate_password_hash

##############################################################
## functions
##############################################################

def email_check(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(80), unique=True, nullable=True)
    role = db.Column(db.String(5), nullable=False)
    user_type = db.Column(db.String(5), nullable=False)
    tokens = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return '<User %r>' % self.username

def UserCreate(username, password, email, role, user_type, tokens):
    user = User.query.filter_by(username=username).first()
    if password is None:
        user_data = User(
            username      = username,
            password_hash = None,
            email         = email,
            role          = role,
            user_type     = user_type,
            tokens        = tokens
        )
    else:
        user_data = User(
            username      = username,
            password_hash = generate_password_hash(password, method='sha256'),
            email         = email,
            role          = role,
            user_type     = user_type,
            tokens        = tokens
        )
    if user is None:
        db.session.add(user_data)
        db.session.commit()

def UserUpdate(username, role):
    user = User.query.filter_by(username=username).first()
    if user:
        user.role = role
        db.session.commit()

def UserDelete(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()

def UserCreateSSO(username, email, tokens, user_type):
    UserCreate(username, None, email, "User", user_type, tokens)