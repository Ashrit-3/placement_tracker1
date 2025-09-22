from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests
import os
import smtplib
import random
from email.mime.text import MIMEText

# -----------------------------
# App Setup
# -----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "6f788a0945647451d74fafedfd0afe5a"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///placement.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# -----------------------------
# Database Model
# -----------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    skills = db.Column(db.String(250), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
    print("✅ Database created or updated.")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------------
# OTP Email Sender
# -----------------------------
def send_otp_email(receiver_email: str) -> str:
    otp = str(random.randint(100000, 999999))
    sender_email = "balantrapuashrit05@gmail.com"
    password = "tlbdxqtapibxfrhw"

    msg = MIMEText(f"Your OTP is {otp}")
    msg['Subject'] = "YOUR ONE TIME PASSWORD (OTP) FOR REGISTRATION"
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
        return otp
    except Exception as e:
        print(f"❌ Failed to send OTP: {e}")
        return None

# -----------------------------
# Fetch JSearch Live Jobs
# -----------------------------
import requests

def get_live_jobs(max_results=50):
    url = "https://jsearch.p.rapidapi.com/search"
    headers = {
        "X-RapidAPI-Key": "6497d9551amsh7f9a699a9ddb9a8p13e61fjsnf9be9f06a4db",
        "X-RapidAPI-Host": "jsearch.p.rapidapi.com"
    }
    querystring = {
        "query": "remote",  # Fetch remote jobs
        "num_pages": "1"
    }

    jobs = []
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        response.raise_for_status()
        data = response.json()
        for j in data.get("data", [])[:max_results]:
            jobs.append({
                "title": j.get("job_title"),
                "company": j.get("employer_name"),
                "location": j.get("job_city") or "Remote",
                "url": j.get("job_apply_link"),
                "category": j.get("job_employment_type") or "",
                "description": (j.get("job_description") or "")[:250],
            })
    except requests.exceptions.RequestException as e:
        print("❌ Error fetching JSearch jobs:", e)

    return jobs


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        skills = request.form.get("skills")
        user_otp = request.form.get("otp")

        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already exists", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("⚠️ Email already registered", "danger")
            return redirect(url_for("register"))

        if not user_otp:
            otp = send_otp_email(email)
            if not otp:
                flash("❌ Failed to send OTP. Please try again.", "danger")
                return redirect(url_for("register"))

            session['otp'] = otp
            session['username'] = username
            session['email'] = email
            session['password'] = password
            session['skills'] = skills

            flash("✅ OTP sent to your email. Enter it below to verify.", "info")
            return render_template("register.html")

        if 'otp' not in session:
            flash("❌ OTP session expired. Try registering again.", "danger")
            return redirect(url_for("register"))

        if user_otp != session['otp']:
            flash("❌ Invalid OTP. Verification failed.", "danger")
            return render_template("register.html")

        new_user = User(
            username=session['username'],
            email=session['email'],
            password=generate_password_hash(session['password'], method="pbkdf2:sha256"),
            skills=session['skills']
        )
        db.session.add(new_user)
        db.session.commit()

        session.pop('otp')
        session.pop('username')
        session.pop('email')
        session.pop('password')
        session.pop('skills')

        flash("🎉 Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        skills = request.form.get("skills")

        user = User.query.filter_by(username=username).first()

        if not user or not check_password_hash(user.password, password):
            flash("❌ Invalid credentials", "danger")
            return redirect(url_for("login"))

        user.skills = skills
        db.session.commit()

        login_user(user)
        flash("🎉 Logged in successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    jobs = get_live_jobs(50)  # Fetch 50 live remote jobs
    return render_template("dashboard.html", username=current_user.username, jobs=jobs)


@app.route("/jobs")
@app.route("/view_jobs")
@login_required
def jobs():
    jobs_list = get_live_jobs(50)
    return render_template("jobs.html", jobs=jobs_list)

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for("login"))

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
