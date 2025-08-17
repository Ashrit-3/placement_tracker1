import sqlite3

def init_db():
    conn = sqlite3.connect("database.db")  # This will create database.db if it doesn't exist
    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()
    print("Database initialized!")

if __name__ == "__main__":
    init_db()
