import sqlite3

def init_db():
    with open('init.sql', 'r') as f:
        sql_script = f.read()
    conn = sqlite3.connect('bank.db')
    conn.executescript(sql_script)
    conn.commit()
    conn.close()
    print("Base de données initialisée avec succès.")

if __name__ == "__main__":
    init_db()
