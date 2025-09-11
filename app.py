from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import smtplib, random, os
from email.mime.text import MIMEText
import requests

app = Flask(__name__)

# ---------------- Config ----------------
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "32d7e9d20fac9c52d7f53ba3dbb897c5")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///placement.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'   # <-- ensures login required works

# ---------------- User Model ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    skills = db.Column(db.String(200))
    otp_verified = db.Column(db.Boolean, default=False)

# ---------------- Load user ----------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- Home ----------------
@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ---------------- Register ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        skills = request.form['skills']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or Email already exists!', 'danger')
            return redirect(url_for('register'))

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['temp_user'] = {'username': username, 'email': email, 'password': password, 'skills': skills}

        # Send OTP via email
        sender_email = os.getenv("balantrapuashrit05@gmail.com")
        app_password = os.getenv("tlbd xqta pibx frhw")
        receiver_email = email
        msg = MIMEText(f"Your OTP is {otp}")
        msg['Subject'] = "Placement Tracker OTP Verification"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, app_password)
                server.sendmail(sender_email, receiver_email, msg.as_string())
        except Exception as e:
            flash(f'Failed to send OTP: {e}', 'danger')
            return redirect(url_for('register'))

        flash('OTP sent to your email! Please verify.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('register.html')

# ---------------- Verify OTP ----------------
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            temp_user = session.get('temp_user')
            new_user = User(
                username=temp_user['username'],
                email=temp_user['email'],
                password=temp_user['password'],
                skills=temp_user['skills'],
                otp_verified=True
            )
            db.session.add(new_user)
            db.session.commit()
            session.pop('otp')
            session.pop('temp_user')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Try again.', 'danger')
            return redirect(url_for('verify_otp'))
    return render_template('verify_otp.html')

# ---------------- Login ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username']
        password = request.form['password']
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.otp_verified:
                flash('Please verify your email first!', 'warning')
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid Credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

# ---------------- Dashboard ----------------
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

# ---------------- Logout ----------------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# ---------------- Live Jobs ----------------
@app.route('/jobs')
@login_required
def jobs():
    response = requests.get("https://remotive.com/api/remote-jobs")
    jobs_data = response.json().get('jobs', [])
    return render_template('jobs.html', jobs=jobs_data)

# ---------------- Run ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
