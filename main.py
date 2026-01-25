from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, abort, jsonify
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
import os
from werkzeug.utils import secure_filename
import bleach
from werkzeug.exceptions import Forbidden
import uuid
from PIL import Image
from io import BytesIO



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

# File upload configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



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


EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


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

# Helper functions for meme platform
def allowed_file(filename):
    """Check if file extension is allowed (FR1)"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_input(text):
    """Sanitize user-generated text to prevent Stored XSS (SR2)"""
    if not text:
        return ""
    # Allow only safe tags, strip everything else
    allowed_tags = []  # No HTML tags allowed for captions
    allowed_attributes = {}
    return bleach.clean(text, tags=allowed_tags, attributes=allowed_attributes, strip=True)

def reencode_image(image_file, output_path, max_dimension=4096):
    """
    Re-encode image for security:
    - Validates it's actually an image (prevents polyglot files)
    - Strips all EXIF metadata (GPS, camera info, etc.)
    - Normalizes format
    - Prevents oversized images
    
    Returns: (success: bool, error_message: str)
    """
    try:
        # Open and validate image
        image = Image.open(image_file)
        
        # Verify it's actually an image (not a polyglot file)
        image.verify()
        
        # Reopen after verify (verify() closes the file)
        image_file.seek(0)
        image = Image.open(image_file)
        
        # Convert RGBA to RGB for JPEG compatibility
        if image.mode in ('RGBA', 'LA', 'P'):
            # Create white background for transparent images
            background = Image.new('RGB', image.size, (255, 255, 255))
            if image.mode == 'P':
                image = image.convert('RGBA')
            background.paste(image, mask=image.split()[-1] if image.mode == 'RGBA' else None)
            image = background
        elif image.mode != 'RGB':
            image = image.convert('RGB')
        
        # Resize if too large (prevent resource exhaustion)
        width, height = image.size
        if width > max_dimension or height > max_dimension:
            # Maintain aspect ratio
            if width > height:
                new_width = max_dimension
                new_height = int(height * (max_dimension / width))
            else:
                new_height = max_dimension
                new_width = int(width * (max_dimension / height))
            image = image.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Determine output format based on extension
        ext = os.path.splitext(output_path)[1].lower()
        if ext in ['.jpg', '.jpeg']:
            # Save as JPEG with quality 85, strip all metadata
            image.save(output_path, 'JPEG', quality=85, optimize=True)
        elif ext == '.png':
            # Save as PNG, strip all metadata
            image.save(output_path, 'PNG', optimize=True)
        elif ext == '.gif':
            # For GIF, convert to RGB first if needed, then save
            if image.mode != 'RGB':
                image = image.convert('RGB')
            # Note: PIL doesn't support animated GIFs well, so we save as static
            image.save(output_path, 'GIF', optimize=True)
        else:
            return False, "Unsupported image format"
        
        return True, None
        
    except Exception as e:
        return False, f"Image processing failed: {str(e)}"

def log_audit(action_type, actor_id, target_id=None, target_type=None, details=None, ip_address=None):
    """Log sensitive actions to audit table (SR4)"""
    audit_entry = AuditLog(
        action_type=action_type,
        actor_id=actor_id,
        target_id=target_id,
        target_type=target_type,
        details=details,
        ip_address=ip_address
    )
    db.session.add(audit_entry)
    db.session.commit()

def get_current_user():
    """Get current user from session"""
    if "email" not in session:
        return None
    return User.query.filter_by(email=session["email"]).first()

def require_auth():
    """Require authentication, return user or None"""
    user = get_current_user()
    if not user or not user.is_verified or user.is_banned:
        return None
    return user

def require_admin():
    """Require admin role"""
    user = require_auth()
    if not user or not user.is_admin:
        return None
    return user

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(129), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    login_attempts = db.Column(db.Integer, default=0)
    is_bruteforced = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)  # Admin role
    is_banned = db.Column(db.Boolean, default=False)  # Ban status
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    memes = db.relationship('Meme', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False


class Meme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    caption = db.Column(db.Text, nullable=True)  # Sanitized caption
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    """Read-only audit table for sensitive actions (SR4)"""
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)  # 'delete_meme', 'ban_user', 'role_change'
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_id = db.Column(db.Integer, nullable=True)  # ID of affected resource
    target_type = db.Column(db.String(50), nullable=True)  # 'meme', 'user'
    details = db.Column(db.Text, nullable=True)  # Additional context
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)

    
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
        "exp": datetime.utcnow() + timedelta(days=7)
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

        # Audit log: verification email sent
        try:
            ip_addr = request.remote_addr
        except Exception:
            ip_addr = None
        log_audit(
            action_type="verification_email_sent",
            actor_id=user.id,
            target_id=None,
            target_type=None,
            details=f"Verification email sent to {user.email}",
            ip_address=ip_addr,
        )
    except Exception as e:
        print("Error sending email:", e)

@app.route("/")
def home():
    """Landing page - shows memes"""
    return redirect(url_for('memes'))

@app.route("/login_page")
def login_page():
    """Login/Register page"""
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
    
    # Check if user is banned
    if user.is_banned:
        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Your account has been banned.")

    user.login_attempts = 0
    db.session.commit()
    session["email"] = user.email

    # Audit log: successful login
    log_audit(
        action_type="login",
        actor_id=user.id,
        target_id=None,
        target_type=None,
        details=f"User {user.email} logged in successfully",
        ip_address=request.remote_addr,
    )

    return redirect(url_for("memes"))


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

    # Audit log: user registration
    log_audit(
        action_type="register",
        actor_id=new_user.id,
        target_id=None,
        target_type=None,
        details=f"User registered with email {new_user.email}",
        ip_address=request.remote_addr,
    )

    send_verification_email(new_user)

    return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], message="Account created! Check your email to verify your account.")

@app.route("/auth")
def auth():
    """Alias for login page"""
    return redirect(url_for('login_page'))

@app.route("/logout", methods=["POST"])
def logout():
    # Capture current user before clearing session
    user = get_current_user()

    # Clear session
    session.pop('email', None)

    # Audit log: logout (only if we know the user)
    if user:
        log_audit(
            action_type="logout",
            actor_id=user.id,
            target_id=None,
            target_type=None,
            details=f"User {user.email} logged out",
            ip_address=request.remote_addr,
        )

    return redirect(url_for('memes'))

@app.route("/dashboard")
def dashboard():
    """Admin dashboard - User management (Admin only)"""
    admin = require_admin()
    if not admin:
        abort(403)  # Forbidden - not an admin
    
    # Get all users
    users = User.query.order_by(User.created_at.desc()).all()

    # Pagination for logs (50 per page)
    page = request.args.get("page", 1, type=int)
    logs_pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page,
        per_page=5,
        error_out=False,
    )
    logs = logs_pagination.items

    # Simple mapping for actor emails in template
    user_map = {u.id: u.email for u in users}
    
    return render_template(
        "dashboard.html",
        admin=admin,
        users=users,
        logs=logs,
        logs_page=logs_pagination,
        user_map=user_map,
    )

# Meme platform routes
@app.route("/memes")
def memes():
    """View all memes (public for guests, all for authenticated users)"""
    search_query = request.args.get('search', '').strip()
    
    # Build query
    query = Meme.query
    
    # Apply search filter if provided (FR3)
    if search_query:
        sanitized_query = sanitize_input(search_query)
        query = query.filter(Meme.caption.contains(sanitized_query))

        # Audit log: search (only if user is authenticated)
        user_for_log = get_current_user()
        if user_for_log:
            log_audit(
                action_type="search",
                actor_id=user_for_log.id,
                target_id=None,
                target_type=None,
                details=f"User {user_for_log.email} searched for '{sanitized_query}'",
                ip_address=request.remote_addr,
            )
    
    # Order by newest first
    memes_list = query.order_by(Meme.created_at.desc()).all()
    
    # Get current user info
    user = get_current_user()
    is_admin = user and user.is_admin if user else False
    
    return render_template("memes.html", 
                         memes=memes_list, 
                         user=user,
                         is_admin=is_admin,
                         search_query=search_query)

@app.route("/upload", methods=["GET", "POST"])
@limiter.limit("10/hour")  # Rate limiting for upload (SR3)
def upload_meme():
    """Upload a meme (FR1) - Only authenticated users"""
    user = require_auth()
    if not user:
        return redirect(url_for('memes'))
    
    if request.method == "POST":
        # Check if file is present
        if 'file' not in request.files:
            return render_template("upload.html", error="No file selected", user=user)
        
        file = request.files['file']
        caption = request.form.get('caption', '').strip()
        
        if file.filename == '':
            return render_template("upload.html", error="No file selected", user=user)
        
        # Validate file extension (FR1)
        if not allowed_file(file.filename):
            return render_template("upload.html", error="Invalid file type. Only JPG, PNG, and GIF are allowed.", user=user)
        
        # Validate file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return render_template("upload.html", error="File too large. Maximum size is 10MB.", user=user)
        
        # Sanitize caption (SR2)
        sanitized_caption = sanitize_input(caption)
        
        # Generate secure UUID-based filename to prevent URL guessing
        original_filename = secure_filename(file.filename)
        # Extract and validate file extension
        file_ext = os.path.splitext(original_filename)[1].lower()
        # Ensure extension is in allowed list (security: prevent extension spoofing)
        if file_ext not in ['.jpg', '.jpeg', '.png', '.gif']:
            return render_template("upload.html", error="Invalid file extension.", user=user)
        
        # Generate UUID for filename (prevents direct URL guessing)
        unique_id = str(uuid.uuid4())
        filename = unique_id + file_ext
        
        # Re-encode image for security (removes metadata, validates image, prevents polyglot files)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        success, error_msg = reencode_image(file, file_path)
        
        if not success:
            return render_template("upload.html", error=error_msg or "Failed to process image. Please ensure it's a valid image file.", user=user)
        
        # Create meme record
        meme = Meme(
            user_id=user.id,
            filename=filename,
            caption=sanitized_caption
        )
        db.session.add(meme)
        db.session.commit()

        # Audit log: meme upload
        log_audit(
            action_type="upload_meme",
            actor_id=user.id,
            target_id=meme.id,
            target_type="meme",
            details=f"Meme uploaded: {meme.filename}",
            ip_address=request.remote_addr,
        )
        
        return redirect(url_for('memes'))
    
    return render_template("upload.html", user=user)

@app.route("/delete_meme/<int:meme_id>", methods=["POST"])
def delete_meme(meme_id):
    """Delete a meme with server-side authorization (FR2, SR1)"""
    user = require_auth()
    if not user:
        abort(403)
    
    meme = Meme.query.get_or_404(meme_id)
    
    # Server-side authorization check (SR1 - IDOR protection)
    is_owner = meme.user_id == user.id
    is_admin_user = user.is_admin
    
    if not (is_owner or is_admin_user):
        abort(403)  # Forbidden - not owner and not admin
    
    # Log the deletion (SR4)
    log_audit(
        action_type='delete_meme',
        actor_id=user.id,
        target_id=meme.id,
        target_type='meme',
        details=f"Deleted meme: {meme.filename}",
        ip_address=request.remote_addr
    )
    
    # Delete file from filesystem
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], meme.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Delete from database
    db.session.delete(meme)
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    """Serve uploaded meme files"""
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/search", methods=["GET", "POST"])
@limiter.limit("30/minute")  # Rate limiting for search (SR3)
def search_memes():
    """Keyword-based search for memes (FR3)"""
    if request.method == "POST":
        search_query = request.form.get('search', '').strip()
        return redirect(url_for('memes', search=search_query))
    
    # GET request - redirect to memes with search param
    search_query = request.args.get('search', '').strip()
    return redirect(url_for('memes', search=search_query))

# Admin routes
@app.route("/admin/ban_user/<int:user_id>", methods=["POST"])
def ban_user(user_id):
    """Ban or unban a user (Admin only)"""
    admin = require_admin()
    if not admin:
        abort(403)
    
    target_user = User.query.get_or_404(user_id)
    
    # Prevent self-ban
    if target_user.id == admin.id:
        return jsonify({"error": "Cannot ban yourself"}), 400
    
    # Toggle ban status
    target_user.is_banned = not target_user.is_banned
    action = "banned" if target_user.is_banned else "unbanned"
    
    # Log the action (SR4)
    log_audit(
        action_type='ban_user',
        actor_id=admin.id,
        target_id=target_user.id,
        target_type='user',
        details=f"User {action}: {target_user.email}",
        ip_address=request.remote_addr
    )
    
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route("/admin/make_admin/<int:user_id>", methods=["POST"])
def make_admin(user_id):
    """Grant or revoke admin role (Admin only)"""
    admin = require_admin()
    if not admin:
        abort(403)
    
    target_user = User.query.get_or_404(user_id)
    
    # Toggle admin status
    target_user.is_admin = not target_user.is_admin
    action = "granted admin to" if target_user.is_admin else "revoked admin from"
    
    # Log the action (SR4)
    log_audit(
        action_type='role_change',
        actor_id=admin.id,
        target_id=target_user.id,
        target_type='user',
        details=f"{action} user: {target_user.email}",
        ip_address=request.remote_addr
    )
    
    db.session.commit()
    
    return redirect(url_for('dashboard'))

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

        return render_template("index.html", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"], error="Verification link expired. Register again")

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

            # Audit log: password reset requested
            log_audit(
                action_type="password_reset_request",
                actor_id=user.id,
                target_id=None,
                target_type=None,
                details=f"Password reset requested for {user.email}",
                ip_address=request.remote_addr,
            )

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
        return render_template("index.html", error="Reset link expired.", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"])

    except jwt.InvalidTokenError:
        return render_template("index.html", error="Invalid reset link.", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"])

    user = User.query.filter_by(email=email).first()
    if not user:
        return render_template("index.html", error="Invalid reset request.", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"])

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

        # Audit log: password reset completed
        log_audit(
            action_type="password_reset",
            actor_id=user.id,
            target_id=None,
            target_type=None,
            details=f"Password reset completed for {user.email}",
            ip_address=request.remote_addr,
        )

        return render_template("index.html", message="Password reset successful. You can now log in.", RECAPTCHA_SITE_KEY=app.config["RECAPTCHA_SITE_KEY"])

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

        # Audit log: password reset email sent
        try:
            ip_addr = request.remote_addr
        except Exception:
            ip_addr = None
        log_audit(
            action_type="password_reset_email_sent",
            actor_id=user.id,
            target_id=None,
            target_type=None,
            details=f"Password reset email sent to {user.email}",
            ip_address=ip_addr,
        )
    except Exception as e:
        print("Reset email error:", e)




if __name__ in "__main__":
    with app.app_context():
        db.create_all()
        # Create a default admin user if none exists
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            # Create default admin user
            admin_email = "admin@safeentry.com"
            admin_password = "Admin123!"
            
            # Check if admin email already exists
            existing_user = User.query.filter_by(email=admin_email).first()
            if existing_user:
                # Make existing user an admin
                existing_user.is_admin = True
                existing_user.is_verified = True
                db.session.commit()
                print(f"Existing user {admin_email} has been granted admin privileges.")
            else:
                # Create new admin user
                admin_user = User(email=admin_email)
                admin_user.set_password(admin_password)
                admin_user.is_admin = True
                admin_user.is_verified = True
                db.session.add(admin_user)
                db.session.commit()
                print(f"Admin user created: {admin_email} / {admin_password}")
        start_scheduler()
    app.run(debug=True)
