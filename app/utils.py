from functools import wraps
from flask import session, redirect, url_for, flash, current_app

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Veuillez vous connecter.", "error")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return wrapper

import sys

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get ('role') != "admin":
            flash("Accès admin requis.", "error")
            return redirect(url_for("home.home"))
        return f(*args, **kwargs)
    return wrapper

def setup_login(app):
    app.secret_key = "dev"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config ["ALLOWED_EXTENSIONS"]