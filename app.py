from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests
import os
import random

# -----------------------------
# App Setup
# -----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "6f788a0945647451d74fafedfd0afe5a"

# Use Postgres if available (Render), otherwise SQLite (local)
if os.getenv("DATABASE_URL"):
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL").replace("postgres://", "postgresql://")
else:
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
    skills = db.Column(db.String(250), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------------------
# Fake OTP for Render
# -----------------------------
def send_otp_email(receiver_email: str) -> str:
    otp = str(random.randint(100000, 999999))
    print(f"DEBUG OTP for {receiver_email}: {otp}")  # logs OTP
    return otp

# -----------------------------
# Fetch Jobs from JSearch (RapidAPI)
# -----------------------------
def get_live_jobs(query="software engineer", max_results=20):
    url = "https://jsearch.p.rapidapi.com/search"
    headers = {
        "X-RapidAPI-Key": os.getenv("RAPIDAPI_KEY", "6497d9551amsh7f9a699a9ddb9a8p13e61fjsnf9be9f06a4db"),
        "X-RapidAPI-Host": "jsearch.p.rapidapi.com"
    }
    params = {"query": query, "num_pages": 1}
    jobs = []

    try:
        response = requests.get(url, headers=headers, params=params, timeout=8)
        response.raise_for_status()
        data = response.json()
        for job in data.get("data", [])[:max_results]:
            jobs.append({
                "title": job.get("job_title"),
                "company": job.get("employer_name"),
                "location": job.get("job_city") or job.get("job_country"),
                "url": job.get("job_apply_link"),
                "description": (job.get("job_description") or "")[:200]
            })
    except Exception as e:
        print("❌ Error fetching jobs:", e)

    return jobs

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    return render_template("home.html")

# -------- REGISTER --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        skills = request.form.get("skills")

        if User.query.filter_by(username=username).first():
            flash("⚠️ Username already exists", "danger")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("⚠️ Email already registered", "danger")
            return redirect(url_for("register"))

        # Save user data in session for verification
        session["temp_user"] = {
            "username": username,
            "email": email,
            "password": password,
            "skills": skills
        }

        # Fake OTP for demo
        otp = send_otp_email(email)
        session["otp"] = otp

        flash("✅ OTP generated. Enter any 6 digits to continue (demo mode).", "info")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")

# -------- VERIFY OTP --------
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        user_otp = request.form.get("otp")
        if "otp" not in session or "temp_user" not in session:
            flash("❌ Session expired. Please register again.", "danger")
            return redirect(url_for("register"))

        # Accept any OTP for demo
        temp_user = session["temp_user"]
        new_user = User(
            username=temp_user["username"],
            email=temp_user["email"],
            password=generate_password_hash(temp_user["password"], method="pbkdf2:sha256"),
            skills=temp_user["skills"]
        )
        db.session.add(new_user)
        db.session.commit()

        session.pop("otp")
        session.pop("temp_user")

        flash("🎉 Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("verify_otp.html")

# -------- LOGIN --------
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
        return redirect(url_for("dashboard"))

    return render_template("login.html")

# -------- DASHBOARD --------
@app.route("/dashboard")
@login_required
def dashboard():
    jobs = get_live_jobs(current_user.skills or "developer", max_results=20)
    return render_template("dashboard.html", username=current_user.username, jobs=jobs)

# -------- JOBS PAGE --------
@app.route("/jobs")
@login_required
def jobs():
    jobs_list = get_live_jobs(current_user.skills or "developer", max_results=50)
    return render_template("jobs.html", jobs=jobs_list)

# -------- PROFILE --------
@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", user=current_user)

# -------- SETTINGS --------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        username = request.form.get("username")
        skills = request.form.get("skills")
        password = request.form.get("password")

        if username:
            current_user.username = username
        if skills:
            current_user.skills = skills
        if password:
            current_user.password = generate_password_hash(password, method="pbkdf2:sha256")

        db.session.commit()
        flash("✅ Settings updated successfully!", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", user=current_user)

# -------- LOGOUT --------
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
