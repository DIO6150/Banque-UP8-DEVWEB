
import os
from flask import Flask, request, render_template, redirect, session, url_for, flash, get_flashed_messages
from werkzeug.security import check_password_hash
import sqlite3
from datetime import datetime
import sys

# TODO: ajouter un flash message au dessus de tous les retours d'erreurs

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret string')

DATABASE = 'bank.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # pour accéder aux colonnes par nom
    return conn

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    email = request.form['email']
    password = request.form['password']
    db = get_db()
    cur = db.execute('SELECT * FROM users WHERE email=? AND password=?', (email, password))
    user = cur.fetchone()

    # TODO : hash the password in the signup func and here
    if not user or user['password'] != password:
        flash("Email ou mot de passe incorrect.", "error")
        return redirect(url_for('login'))


    if user:
        session['user_id'] = user['id']
        session['role'] = user['role']
        return redirect(url_for('home'))
    return render_template('login.html'), 401

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    email = request.form['email']
    password = request.form['password']
    firstname = request.form['firstname']
    name = request.form['name']
    db = get_db()  

    try:
        db.execute('INSERT INTO users (email, password, firstname, name, role) VALUES (?, ?, ?, ?, ?)', (email, password, firstname, name, 'client'))
        db.commit()
        db.execute('INSERT INTO accounts (user_id) SELECT id FROM users WHERE email = ?', (email,))
        db.commit()
        return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        flash("Email déjà utilisée.", "error")
        return redirect(url_for('signup'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    db.row_factory = sqlite3.Row
    cur = db.execute('SELECT balance, frozen FROM accounts WHERE user_id = ?', (session['user_id'],))
    account = cur.fetchone()

    cur = db.execute('SELECT firstname, name FROM users WHERE id = ?', (session['user_id'], ))
    name_tab = cur.fetchone ()
    username = name_tab['firstname'] + " " + name_tab['name']

    # what does that do
    role = session.get('role', 'client')

    return render_template('home.html',
                           balance=account['balance'],
                           frozen=bool(account['frozen']),
                           role=role,
                           username=username)


@app.route('/transaction', methods=['GET', 'POST'])
def transaction():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user_id = session['user_id']
    role = session.get('role')

    if request.method == 'POST':
        type_ = request.form['type']
        amount = float(request.form['amount'])
        now = datetime.now().isoformat(timespec='seconds')

        # Vérifie si compte gelé
        frozen = db.execute('SELECT frozen FROM accounts WHERE user_id = ?', (user_id,)).fetchone()['frozen']
        if frozen:
            return "Compte gelé, opération impossible.", 403

        # Logique par type
        if type_ == 'deposit':
            db.execute('UPDATE accounts SET balance = balance + ? WHERE user_id = ?', (amount, user_id))
        elif type_ == 'withdrawal':
            db.execute('UPDATE accounts SET balance = balance - ? WHERE user_id = ?', (amount, user_id))
        elif type_ in ['loan', 'borrow']:
            db.execute('UPDATE accounts SET balance = balance + ? WHERE user_id = ?', (amount, user_id))
        else:
            return "Type de transaction invalide", 400

        db.execute('INSERT INTO transactions (user_id, type, amount, date) VALUES (?, ?, ?, ?)',
                   (user_id, type_, amount, now))
        db.commit()
        return redirect(url_for('home'))

    # GET
    acc = db.execute('SELECT frozen FROM accounts WHERE user_id = ?', (user_id,)).fetchone()
    return render_template('transaction.html', frozen=bool(acc['frozen']))


@app.route('/admin/toggle/<int:user_id>', methods=['POST'])
def admin_toggle(user_id):
    if session.get('role') != 'admin':
        return "Accès interdit", 403

    db = get_db()
    frozen = db.execute('SELECT frozen FROM accounts WHERE user_id = ?', (user_id,)).fetchone()['frozen']
    db.execute('UPDATE accounts SET frozen = ? WHERE user_id = ?', (int(not frozen), user_id))
    db.commit()
    return redirect(url_for('admin'))

@app.route('/history')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    rows = db.execute('''
        SELECT type, amount, date
        FROM transactions
        WHERE user_id = ?
        ORDER BY date DESC
    ''', (session['user_id'],)).fetchall()
    return render_template('history.html', transactions=rows)

@app.route('/admin/dashboard')
def admin_dashboard():
    if session.get('role') != 'admin':
        return "Accès interdit", 403

    db = get_db()
    stats = db.execute('''
        SELECT
            COUNT(*) AS total_users,
            SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) AS admins,
            SUM(CASE WHEN frozen = 1 THEN 1 ELSE 0 END) AS frozen_accounts,
            SUM(balance) AS total_balance
        FROM users
        JOIN accounts ON users.id = accounts.user_id
    ''').fetchone()

    users = db.execute('''
        SELECT users.id, firstname, name, email, role, balance, frozen
        FROM users
        JOIN accounts ON users.id = accounts.user_id
        ORDER BY email
    ''').fetchall()

    return render_template('admin_dashboard.html', stats=stats, users=users)


@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if session.get('role') != 'admin':
        return "Accès interdit", 403
    db = get_db()

    if request.method == 'POST':
        role = request.form['role']
        balance = float(request.form['balance'])
        frozen = 1 if 'frozen' in request.form else 0

        db.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
        db.execute('UPDATE accounts SET balance = ?, frozen = ? WHERE user_id = ?', (balance, frozen, user_id))
        db.commit()
        return redirect(url_for('admin_dashboard'))

    user = db.execute('''
        SELECT users.email, users.role, accounts.balance, accounts.frozen
        FROM users
        JOIN accounts ON users.id = accounts.user_id
        WHERE users.id = ?
    ''', (user_id,)).fetchone()

    return render_template('admin_user.html', user=user)


@app.route('/user_settings')
def user_settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()

    user = db.execute('''
        SELECT firstname, name, email
        FROM users
        WHERE id = ?
    ''', (session['user_id'], )).fetchall()

    return render_template('user_settings.html', user=user)


if __name__ == '__main__':
    context = ('keys/test/cert.pem', 'keys/test/key.pem')  # Certificat SSL
    app.run(ssl_context=context, host='127.0.0.1', port=5000, debug=True)