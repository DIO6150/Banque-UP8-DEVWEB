from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from app.db import get_db
from app.utils import login_required, allowed_file, admin_required
import sqlite3
import os

admin_bp = Blueprint("admin", __name__)

@admin_bp.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
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


@admin_bp.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
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
        return redirect(url_for('admin.admin_dashboard'))

    user = db.execute('''
        SELECT firstname, name, email, role, balance, frozen
        FROM users
        JOIN accounts ON users.id = accounts.user_id
        WHERE users.id = ?
    ''', (user_id,)).fetchone()

    history = db.execute('''
        SELECT type, amount, date, reason
        FROM transactions
        WHERE user_id = ?
        ORDER BY date DESC
    ''', (session['user_id'],)).fetchall()

    loan_requests = db.execute("""
        SELECT loan_requests.*
        FROM loan_requests
        JOIN users ON users.id = loan_requests.user_id
        ORDER BY created_at DESC
    """).fetchall()


    return render_template('admin_user.html', user=user, loan_requests=loan_requests, transactions=history)


@admin_bp.route('/admin/toggle/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_toggle(user_id):
    db = get_db()
    frozen = db.execute('SELECT frozen FROM accounts WHERE user_id = ?', (user_id,)).fetchone()['frozen']
    db.execute('UPDATE accounts SET frozen = ? WHERE user_id = ?', (int(not frozen), user_id))
    db.commit()
    return redirect(url_for('admin'))

@admin_bp.route("/admin/update_loan_status", methods=["POST"])
@login_required
@admin_required
def update_loan_status():
    loan_id = request.form["loan_id"]
    action = request.form["action"]
    if action not in ["approve", "reject"]:
        flash("Action non reconnue", "error")
        return redirect (request.referrer) or redirect(url_for("admin.admin_dashboard"))

    new_status = "Validée" if action == "approve" else "Refusée"

    db = get_db()
    db.execute("UPDATE loan_requests SET status = ? WHERE id = ?", (new_status, loan_id))
    db.commit()

    flash(f"Demande #{loan_id} {new_status.lower()}.")
    return redirect (request.referrer) or redirect(url_for("admin.admin_dashboard"))
