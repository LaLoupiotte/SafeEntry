# Copilot instructions for SafeEntry (Flask monolith)

Purpose: give AI coding agents the minimal, actionable context to be productive in this repository.

- **Project shape**: single Flask monolith implemented in `main.py`. Templates live in `templates/`, static files in `static/`, uploaded images in `uploads/`. A local SQLite DB (`users.db`) is used via SQLAlchemy.

- **Run / dev workflow**:
  - Activate the included virtualenv: `source flask-auth/bin/activate`.
  - Install deps (typo'd file): `pip install -r requirments.txt`.
  - Start app: `python main.py` (development mode; app currently runs with `debug=True`).
  - Note: running `python -c "import main"` will execute side-effects due to a bug in `main.py` (see "Gotchas").

- **Big picture / architecture**:
  - Authentication & users: `User` model in `main.py` (fields: `email`, `password_hash`, `is_verified`, `is_admin`, etc.). Passwords hashed with Argon2 (`argon2.PasswordHasher`).
  - Email verification & password reset: JWT tokens (`JWT_SECRET` in `main.py`) are used for both verification and password reset. Email is sent via SMTP (credentials are hard-coded in `main.py`).
  - File uploads: `/upload` route. Images are validated and re-encoded with `reencode_image()` (Pillow), renamed to UUID-based filenames and stored in `uploads/`. Served by `/uploads/<filename>`.
  - Audit trail: `AuditLog` model captures sensitive actions (login, logout, ban, role changes, uploads, deletes). Use `log_audit()` for consistent logging.
  - Background job: `start_scheduler()` registers `delete_old_unverified_users()` with APScheduler to remove old unverified accounts.
  - Rate limiting & CSRF: `flask_limiter` and `flask_wtf.CSRFProtect` are enabled globally.

- **Project-specific conventions & patterns** (use these when editing code):
  - Use `get_current_user()` / `require_auth()` / `require_admin()` helpers from `main.py` to check identity and roles.
  - Always call `log_audit()` for sensitive user-facing state changes (bans, role changes, password resets, upload/delete actions).
  - Sanitize any free-text fields with `sanitize_input()` (uses `bleach`) before storing or querying.
  - File uploads: validate extension (`allowed_file()`), check `file_size` against `MAX_FILE_SIZE`, generate UUID filename, and call `reencode_image()` before writing to disk.

- **Key integration points / config to be aware of**:
  - `app.config` values to adjust: `RECAPTCHA_SITE_KEY`, `RECAPTCHA_SECRET_KEY`, `UPLOAD_FOLDER`, `MAX_CONTENT_LENGTH`.
  - Secrets in `main.py`: `JWT_SECRET`, SMTP credentials and the app secret key are hard-coded. Prefer replacing with environment variables (`os.environ`) when changing behavior.
  - Database: `SQLALCHEMY_DATABASE_URI` points to `sqlite:///users.db`. DB created automatically at app start via `db.create_all()`.

- **Important files to inspect when making changes**:
  - `main.py` — whole app lives here; read first.
  - `templates/` — UI surfaces and form names (e.g., `index.html` contains login/register forms using `g-recaptcha-response`).
  - `static/style.css` — minimal styling.
  - `requirments.txt` — dependency list (note filename spelling).

- **Gotchas & immediate bugs to watch for** (keep these in PR notes):
  - The process-guard at the end uses `if __name__ in "__main__":` instead of the correct `if __name__ == "__main__":`. That makes the initialization block run even when `main` is imported (side effects: DB creation, scheduler start, app.run). Fix this to avoid unexpected execution during imports or tests.
  - Hard-coded secrets in `main.py` (JWT secret, SMTP app-password, Flask `secret_key`). Treat as secrets and move to env vars before committing changes that touch auth/email.
  - `reencode_image()` saves files relative to `UPLOAD_FOLDER` — be careful with working directory when running tests. Use absolute paths (or `app.config['UPLOAD_FOLDER']`) when writing tests.
  - There are no unit tests in the repo; changes that import `main.py` may start the server because of the `if __name__` bug.

- **Examples (copyable patterns)**:
  - Audit log entry for ban/unban:
    - `log_audit(action_type='ban_user', actor_id=admin.id, target_id=target_user.id, target_type='user', details=f"User banned: {target_user.email}", ip_address=request.remote_addr)`
  - Image upload flow (high-level): validate extension → check size → `unique_id = str(uuid.uuid4())` → filename = `unique_id + file_ext` → `reencode_image(file, file_path)` → create `Meme` record → `db.session.commit()` → `log_audit(...)`.

- **Suggested quick fixes to reduce cognitive load for agents**:
  - Replace hard-coded secrets with environment variables and document the expected env names (`FLASK_SECRET_KEY`, `JWT_SECRET`, `SMTP_USER`, `SMTP_PASS`).
  - Fix the `if __name__` guard to `==`.
  - Add a small `README.dev` snippet describing `source flask-auth/bin/activate` and `python main.py` so newcomers can run the app quickly.

If any of the above is unclear or you want me to expand an area (e.g., create `.env` support, fix the `if __name__` bug, or add run/test scripts), tell me which part to iterate on.
