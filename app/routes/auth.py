from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from app.db import get_db
import sqlite3

auth_bp = Blueprint("auth", __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    email = request.form['email']
    password = request.form['password']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email=?', (email, )).fetchone ()

    # TODO : hash the password in the signup func and here
    if not user or not check_password_hash (user ['password'], password):
        flash("Email ou mot de passe incorrect.", "error")
        return redirect(url_for('auth.login'))

    if user:
        session['user_id'] = user['id']
        session['role'] = user['role']
        return redirect(url_for('home.home'))
    return render_template('login.html'), 401

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    email = request.form['email']
    password = request.form['password']
    firstname = request.form['firstname']
    name = request.form['name']
    db = get_db()  

    password = generate_password_hash(password)

    try:
        db.execute('INSERT INTO users (email, password, firstname, name, role) VALUES (?, ?, ?, ?, ?)', (email, password, firstname, name, 'client'))
        db.commit()
        db.execute('INSERT INTO accounts (user_id) SELECT id FROM users WHERE email = ?', (email,))
        db.commit()
        flash ("Inscription complète.", "success")
        return redirect(url_for('auth.login'))
    except sqlite3.IntegrityError:
        flash("Email déjà utilisée.", "error")
        return redirect(url_for('auth.signup'))

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))