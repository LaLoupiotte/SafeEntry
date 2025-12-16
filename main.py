from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import jwt
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from apscheduler.schedulers.background import BackgroundScheduler
import requests



app = Flask(__name__)
app.secret_key = "4ppl1c4t1onS€cur1ty$0$5"  

# SQL Alchemy Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app)

ph = PasswordHasher()

app.config["RECAPTCHA_SITE_KEY"] = "6LfkLSEsAAAAACI9P4vDwgU_FfDhdzVA-P1k1hm5"
app.config["RECAPTCHA_SECRET_KEY"] = "6LfkLSEsAAAAABeHaz5NwZkbIjeFr2J2nq-CuelV"



def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(func=delete_old_unverified_users, trigger="interval", days=1)
    scheduler.start()

def verify_recaptcha(response_token):
    secret = app.config["RECAPTCHA_SECRET_KEY"]
    payload = {
        "secret": secret,
        "response": response_token
    }
    resp = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
    result = resp.json()
    return result.get("success", False)


EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")


def is_valid_email(email):
    return EMAIL_REGEX.match(email)

def is_valid_password(password):
    # Example rules: 8+ chars, at least 1 number, 1 letter
    if len(password) < 8:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(129), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    login_attempts = db.Column(db.Integer, default=0)
    is_bruteforced = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False

    
def delete_old_unverified_users():
    cutoff = datetime.utcnow() - timedelta(days=7)
    old_users = User.query.filter(
        User.is_verified == False,
        User.is_bruteforced == False,
        User.created_at < cutoff
    ).all()

    for user in old_users:
        db.session.delete(user)

    db.session.commit()
    print(f"Deleted {len(old_users)} old unverified accounts.")


# Email verification code
JWT_SECRET = "4ppl1c4t1onS€cur1ty$0$5"
JWT_ALGORITHM = "HS256"

def generate_validation_token(email):
    payload = {
        "email": email,
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def send_verification_email(user):
    token = generate_validation_token(user.email)
    verify_email = url_for('verify_email', token=token, _external=True)
    sender_email = "appsec2025026@gmail.com"
    app_password = "getqpuxwjsglxxyh"
    # Create the email
    
    message = MIMEMultipart("alternative")
    message["Subject"] = "Your activation link"
    message["From"] = sender_email
    message["To"] = user.email

    # Email body
    html = f"<html><body><p>Your activation link is: <b>{verify_email}</b></p></body></html>"

    # Attach both plain and HTML versions
    message.attach(MIMEText(html, "html"))

    # Connect to Gmail SMTP server and send email
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, user.email, message.as_string())
        print("Activation email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)

@app.route("/")
def home():
    if "email" in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"])

@app.route("/login", methods=["POST"])
@limiter.limit("10/minute")
def login():
    recaptcha_response = request.form.get("g-recaptcha-response")
    if not verify_recaptcha(recaptcha_response):
        return render_template("index.html",RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Please complete the reCAPTCHA.")
    email = request.form["email"]
    password = request.form["password"]

    if not is_valid_email(email):
        return render_template("index.html", error="Invalid email format.", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"])

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        if user and not user.check_password(password):
            user.login_attempts += 1
            if user.login_attempts > 5:
                user.is_bruteforced = True
                user.is_verified = False
            db.session.commit()

        return render_template("index.html", error="Invalid credentials.", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"])

    if not user.is_verified:
        send_verification_email(user)
        if user.is_bruteforced:
            return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Your account was locked because someone tried to login with a wrong password more than 5 times. You must re-activate it")
        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"],error="Please verify your email first.")

    user.login_attempts = 0
    db.session.commit()
    session["email"] = user.email
    return redirect(url_for("dashboard"))


@app.route("/register", methods=["POST"])
@limiter.limit("3/minute")
def register():
    recaptcha_response = request.form.get("g-recaptcha-response")
    if not verify_recaptcha(recaptcha_response):
        return render_template("index.html",RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Please complete the reCAPTCHA.")
    email = request.form['email']
    password = request.form['password']

    if not is_valid_email(email):
        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Invalid email address.")
    if not is_valid_password(password):
        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Password must be at least 8 characters long, with letters and numbers.")

    if User.query.filter_by(email=email).first():
        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="User already here!")

    new_user = User(email=email)
    new_user.set_password(password)
    new_user.is_verified = False
    db.session.add(new_user)
    db.session.commit()

    send_verification_email(new_user)

    return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], message="Account created! Check your email to verify your account.")

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('email', None)
    return redirect(url_for('home'))

@app.route("/dashboard")
def dashboard():
    if "email" in session:
        return render_template("dashboard.html", email=session['email'])
    return redirect(url_for('home'))

@app.route("/verify/<token>")
def verify_email(token):
    try:
        # Try to decode normally first (valid + not expired)
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload["email"]

    except jwt.ExpiredSignatureError:
        # Decode WITHOUT verifying expiration
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                options={"verify_exp": False}
            )
            email = payload["email"]
        except Exception:
            return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Invalid verification link.")

        # Get user and resend new link
        user = User.query.filter_by(email=email).first()
        if user:
            send_verification_email(user)

        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Verification link expired. A new one was sent.")

    except jwt.InvalidTokenError:
        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Invalid verification link.")

    # Token still valid → verify user
    user = User.query.filter_by(email=email).first()
    if not user:
        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="User not found.")

    user.is_verified = True
    user.is_bruteforced = False
    db.session.commit()

    return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], message="Email verified! You can now log in.")

@app.route("/forgotten_password", methods=["GET", "POST"])
@limiter.limit("3/hour")
def forgotten_password():
    if request.method == "POST":
        email = request.form.get("email")

        if not is_valid_email(email):
            return render_template("forgotten_password.html", error="Invalid email.")

        user = User.query.filter_by(email=email).first()

        if user:
            send_password_reset_email(user)

        return render_template(
            "forgotten_password.html",
            message="If the email exists, a reset link has been sent."
        )

    return render_template("forgotten_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        if payload.get("purpose") != "password_reset":
            raise jwt.InvalidTokenError()

        email = payload["email"]

    except jwt.ExpiredSignatureError:
        return render_template("index.html", error="Reset link expired.")

    except jwt.InvalidTokenError:
        return render_template("index.html", error="Invalid reset link.")

    user = User.query.filter_by(email=email).first()
    if not user:
        return render_template("index.html", error="Invalid reset request.")

    if request.method == "POST":
        password = request.form.get("password")

        if not is_valid_password(password):
            return render_template(
                "reset_password.html",
                error="Password must be at least 8 characters with letters and numbers.",
                token=token
            )

        user.set_password(password)
        user.login_attempts = 0
        user.is_bruteforced = False
        db.session.commit()

        return render_template("index.html", message="Password reset successful. You can now log in.")

    return render_template("reset_password.html", token=token)



def generate_password_reset_token(email):
    payload = {
        "email": email,
        "purpose": "password_reset",
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def send_password_reset_email(user):
    token = generate_password_reset_token(user.email)
    reset_link = url_for("reset_password", token=token, _external=True)

    sender_email = "appsec2025026@gmail.com"
    app_password = "getqpuxwjsglxxyh"

    message = MIMEMultipart("alternative")
    message["Subject"] = "Password reset request"
    message["From"] = sender_email
    message["To"] = user.email

    html = f"""
    <html>
        <body>
            <p>Click the link below to reset your password:</p>
            <p><a href="{reset_link}">{reset_link}</a></p>
            <p>This link expires in 1 hour.</p>
        </body>
    </html>
    """

    message.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, user.email, message.as_string())
    except Exception as e:
        print("Reset email error:", e)




if __name__ in "__main__":
    with app.app_context():
        db.create_all()
        start_scheduler()
    app.run(debug=True)
