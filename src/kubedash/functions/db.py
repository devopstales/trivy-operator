#!/usr/bin/env python3

class dbCreate():
    from functions.user import UserCreate
    from __main__ import db, app
    from sqlalchemy_utils import database_exists

    username  = "admin"
    password  = "admin"
    email     = None
    role      = "Admin"
    user_type = "Local"
    tokens    = None

    if database_exists(app.config['SQLALCHEMY_DATABASE_URI']):
        UserCreate(username, password, email, role, user_type, tokens)
    else:
        with app.app_context():
            db.create_all()
            UserCreate(username, password, email, role, user_type, tokens)

