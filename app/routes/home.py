from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import send_from_directory
from app.db import get_db
from app.utils import login_required
import sqlite3

import sys

home_bp = Blueprint("home", __name__)

@home_bp.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):# TODO : maybe check if the user can open this particular file
    # print (current_app.config["UPLOAD_FOLDER"], sys.stderr)
    return send_from_directory(directory=current_app.config["UPLOAD_FOLDER"], path=filename, as_attchment=True)

@home_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home.home'))
    return redirect(url_for('auth.login'))

@home_bp.route('/home')
@login_required
def home():
    db = get_db()
    
    account = db.execute('''SELECT balance, frozen FROM accounts WHERE user_id = ?''', (session['user_id'],)).fetchone ()
    username = db.execute('''SELECT firstname || ' ' || name AS fullname FROM users WHERE id = ?''', (session['user_id'], )).fetchone ()["fullname"]
    role = session.get('role', 'client')

    return render_template('home.html',
                           balance=account['balance'],
                           frozen=bool(account['frozen']),
                           role=role,
                           username=username,
                           user_id=session['user_id'])
