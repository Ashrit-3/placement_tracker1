from flask import Flask, render_template, request, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DB_NAME = 'placement_tracker.db'

# Create DB and tables if not exists
def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        conn.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL
            );
        ''')
        conn.execute('''
            CREATE TABLE jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                company TEXT NOT NULL
            );
        ''')
        conn.commit()
        conn.close()
        print("Database created.")
    else:
        print("Database already exists.")

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

init_db()

# Home page
@app.route('/')
def index():
    return redirect('/login')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                     (username, email, password))
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ? AND password = ?", 
                            (email, password)).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            return redirect('/dashboard')
        else:
            return "Invalid credentials"
    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

# View Jobs
@app.route('/view_jobs')
def view_jobs():
    conn = get_db_connection()
    jobs = conn.execute("SELECT * FROM jobs").fetchall()
    conn.close()
    return render_template('view_jobs.html', jobs=jobs)

# Add Job
@app.route('/add_job', methods=['GET', 'POST'])
def add_job():
    if request.method == 'POST':
        title = request.form['title']
        company = request.form['company']

        conn = get_db_connection()
        conn.execute("INSERT INTO jobs (title, company) VALUES (?, ?)", (title, company))
        conn.commit()
        conn.close()
        return redirect('/view_jobs')
    return render_template('add_job.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
