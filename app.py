from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests

app = Flask(__name__)
app.secret_key = "8314c819a76a41fc1d28f1507776f121"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///placement.db'
db = SQLAlchemy(app)

# ---------------- Database Model ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    skills = db.Column(db.String(300), nullable=True)

# ---------------- Live Jobs Helper ----------------
def get_live_jobs(skills):
    jobs = []
    try:
        response = requests.get("https://remotive.com/api/remote-jobs")
        data = response.json()
        user_skills = [s.strip().lower() for s in skills.split(",")]

        for job in data['jobs']:
            job_title = job.get('title', '').lower()
            job_description = job.get('description', '').lower()
            if any(skill in job_title or skill in job_description for skill in user_skills):
                jobs.append({
                    "title": job.get("title"),
                    "company": job.get("company_name"),
                    "url": job.get("url")
                })
    except Exception as e:
        print("Error fetching live jobs:", e)
    return jobs

# ---------------- Routes ----------------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        skills = request.form['skills']

        if User.query.filter_by(username=username).first():
            return "User already exists!"
        
        new_user = User(username=username, password=password, skills=skills)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for("dashboard"))
        else:
            return "Invalid credentials"
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    jobs = get_live_jobs(user.skills)  # Fetch live jobs based on skills
    return render_template("dashboard.html", user=user, jobs=jobs)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

# ---------------- Initialize Database ----------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

