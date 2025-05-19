import sqlite3
import sys

if len(sys.argv) != 2:
    print("Usage: python make_admin.py user@example.com")
    exit(1)

email = sys.argv[1]

conn = sqlite3.connect('app/instance/bank.db')
cur = conn.cursor()

cur.execute("SELECT id, role FROM users WHERE email = ?", (email,))
user = cur.fetchone()

if not user:
    print("Utilisateur introuvable.")
    exit(1)

if user[1] == 'admin':
    print("Utilisateur est déjà admin.")
else:
    cur.execute("UPDATE users SET role = 'admin' WHERE email = ?", (email,))
    conn.commit()
    print(f"L'utilisateur {email} est maintenant administrateur.")

conn.close()
