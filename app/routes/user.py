from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from app.db import get_db
from app.utils import login_required, allowed_file
import sqlite3
import os
import sys

user_bp = Blueprint("user", __name__)

@user_bp.route('/history')
@login_required
def history():
    db = get_db()
    rows = db.execute('''
        SELECT type, amount, date, reason
        FROM transactions
        WHERE user_id = ?
        ORDER BY date DESC
    ''', (session['user_id'],)).fetchall()
    return render_template('history.html', transactions=rows)


@user_bp.route('/transaction', methods=['GET', 'POST'])
@login_required
def transaction():
    db = get_db()
    user_id = session['user_id']
    role = session.get('role')

    if request.method == 'POST':
        type_ = request.form['type']
        amount = float(request.form['amount'])
        now = datetime.now().isoformat(timespec='seconds')
        transfer_to = None
        reason = request.form['reason']

        if (len(reason) > 80): return ("raison trop longue", 400)

        # Vérifie si compte gelé
        frozen = db.execute('SELECT frozen FROM accounts WHERE user_id = ?', (user_id,)).fetchone()['frozen']
        if frozen: return "Compte gelé, opération impossible.", 403

        # Logique par type
        if type_ == 'deposit':
            db.execute('UPDATE accounts SET balance = balance + ? WHERE user_id = ?', (amount, user_id))
            db.execute('INSERT INTO transactions (user_id, type, amount, date, reason) VALUES (?, ?, ?, ?, ?)', (user_id, type_, +amount, now, reason))

        elif type_ == 'transfer':
            if (request.form ['user-id-trans']):
                transfer_to = int(request.form ['user-id-trans'])

                if (transfer_to == user_id):
                    return ("Bénéficiaire et émetteur sont identiques", 400)

                cursor = db.execute('SELECT user_id FROM accounts WHERE user_id = ?', (transfer_to, ))

                if (cursor.fetchone ()):
                    db.execute('UPDATE accounts SET balance = balance - ? WHERE user_id = ?', (amount, user_id))
                    db.execute('UPDATE accounts SET balance = balance + ? WHERE user_id = ?', (amount, transfer_to))
                    db.execute('INSERT INTO transactions (user_id, type, amount, date, reason) VALUES (?, ?, ?, ?, ?)', (transfer_to, type_, +amount, now, reason))
                    db.execute('INSERT INTO transactions (user_id, type, amount, date, reason) VALUES (?, ?, ?, ?, ?)', (user_id, type_, -amount, now, reason))

                else:
                    return ("ID bénéficiaire inconnu", 400)

            else:
                return ("Bénéficiaire non précisé", 400)

        else:
            return "Type de transaction inval   ide", 400

        db.commit()
        return redirect(url_for('home.home'))

    # GET
    acc = db.execute('SELECT frozen FROM accounts WHERE user_id = ?', (user_id,)).fetchone()
    return render_template('transaction.html', frozen=bool(acc['frozen']))

@user_bp.route("/loan_request", methods=["GET", "POST"])
@login_required
def loan_request():
    db = get_db()
    user_id = session["user_id"]
    cursor = db.cursor()

    if request.method == "POST":
        amount = request.form["amount"]
        duration = request.form["duration"]
        reason = request.form["reason"]

        if (len(reason) > 80): return ("raison trop longue", 400)

        document = request.files.get("justification")
        file_path = None


        if document and allowed_file(document.filename):
            filename = secure_filename(document.filename)
            path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
            document.save(path)
            file_path = filename

        elif document and document.filename:
            flash("Format de fichier non autorisé (PDF uniquement)")
            return redirect(url_for('user.loan_request'))

        cursor.execute("""
            INSERT INTO loan_requests (user_id, amount, duration_months, reason, file_path)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, amount, duration, reason, file_path))
        db.commit()
        flash("Votre demande de prêt a bien été soumise.")
        return redirect(url_for("user.loan_request"))

    # Affiche toutes les demandes de l'utilisateur
    cursor.execute("""
        SELECT * FROM loan_requests
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,))
    all_loans = cursor.fetchall()

    return render_template("loan_request.html", all_loans=all_loans)


@user_bp.route("/cancel_loan", methods=["POST"])
@login_required
def cancel_loan_request():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    loan_id = request.form["loan_id"]
    user_id = session["user_id"]

    db = get_db()
    # Vérifie que le prêt appartient bien à l'utilisateur
    loan = db.execute("SELECT * FROM loan_requests WHERE id = ? AND user_id = ?", (loan_id, user_id)).fetchone()
    if not loan or loan["status"] != "En attente":
        flash("Impossible d'annuler cette demande.")
        return redirect(url_for("user.loan_request"))

    db.execute("DELETE FROM loan_requests WHERE id = ?", (loan_id,))
    db.commit()
    flash("Votre demande a été annulée.")
    return redirect(url_for("user.loan_request"))


@user_bp.route('/user_settings', methods=["GET", "POST"])
@login_required
def user_settings():
    db = get_db()

    user = db.execute('''
    SELECT firstname, name, email, password
    FROM users
    WHERE id = ?
    ''', (session['user_id'], )).fetchone()

    if request.method == "POST":
        firstname = request.form["first_name"]
        lastname = request.form["last_name"]
        email = request.form["email"]
        old_password = request.form["current_password"]
        new_password = request.form["new_password"]

        if new_password:
            if not check_password_hash (user ["password"], old_password):
                flash ("Mot de passe incorect")
                return url_for (request.referrer)

            hashed_pw = generate_password_hash(new_password)
            db.execute(
                "UPDATE users SET firstname = ?, name = ?, email = ?, password = ? WHERE id = ?",
                (firstname, lastname, email, hashed_pw, session["user_id"]),
            )
        else:
            db.execute(
                "UPDATE users SET firstname = ?, name = ?, email = ? WHERE id = ?",
                (firstname, lastname, email, session["user_id"]),
            )
        db.commit()
        flash("Modifications enregistrées.", "success")
        return redirect(url_for("user.user_settings"))

    user = db.execute('''
    SELECT firstname, name, email
    FROM users
    WHERE id = ?
    ''', (session['user_id'], )).fetchone()

    return render_template('user_settings.html', user=user)