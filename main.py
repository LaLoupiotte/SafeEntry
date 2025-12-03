from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re




app = Flask(__name__)
app.secret_key = "4ppl1c4t1onS€cur1ty$0$5"

# SQL Alchemy Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app)

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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.route("/")
def home():
    if "email" in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")

@app.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    email = request.form["email"]
    password = request.form["password"]
    if not is_valid_email(email) or not is_valid_password(password):
        return render_template("index.html", error="Invalid email or password format.")
    
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = email
        return redirect(url_for('dashboard'))
    else:
        return render_template("index.html", error="Invalid credentials.")

@app.route("/register", methods=["POST"])
@limiter.limit("3/minute")
def register():
    email = request.form['email']
    password = request.form['password']

    if not is_valid_email(email):
        return render_template("index.html", error="Invalid email address.")
    if not is_valid_password(password):
        return render_template("index.html", error="Password must be at least 8 characters long, with letters and numbers.")

    user = User.query.filter_by(email=email).first()
    if user:
        return render_template("index.html", error="User already here!")
    else:
        new_user = User(email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['email'] = email
        return redirect(url_for('dashboard'))

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('email', None)
    return redirect(url_for('home'))

@app.route("/dashboard")
def dashboard():
    if "email" in session:
        return render_template("dashboard.html", email=session['email'])
    return redirect(url_for('home'))

if __name__ in "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
