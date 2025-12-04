# SafeEntry


## Application Security Project

### Activate the python environment

**Linux or Mac** 
```
source ./flask-auth/bin/activate
pip install -r requirments.txt
```

To deactivate just type `deactivate`

**Windows**
Idk yet


# 🔐 Flask Authentication System

A secure Flask-based authentication system featuring:

- Email verification using JWT tokens  
- reCAPTCHA v2 bot protection  
- Brute-force protection  
- Automatic deletion of unverified accounts  
- Secure password hashing (Argon2)  
- CSRF protection  
- Rate limiting  
- Login / registration system  
- Dashboard for authenticated users  

---

## 🚀 Features

### **1. User Registration**

- Users register with an email and password.  
- Passwords are hashed using **Argon2**.  
- Email and password are validated (regex + complexity rules).  
- Registration is rate-limited: **3 attempts per minute**.  
- A reCAPTCHA challenge prevents bot-based registrations.  
- After registering, users receive an **email verification link**.

---

### **2. Email Verification (JWT Tokens)**

Verification links use JWT tokens containing:

- The user's email  
- A 24-hour expiration time  

Token behavior:

| Condition | Behavior |
|----------|----------|
| Valid token | User gets verified |
| Expired token | Email extracted → New verification link sent |
| Invalid token | Error message shown |

---

### **3. Login System**

- Users must complete **reCAPTCHA** to log in.  
- Passwords are validated using Argon2.  
- Login is rate-limited: **10 attempts per minute**.  
- If login succeeds:  
  - Login attempts reset  
  - User session begins  
- If user is not verified:  
  - A new verification link is automatically sent  

---

### **4. Brute-Force Protection**

If a user enters the wrong password more than **5 times**:

- The account becomes brute-force locked  
- It is marked unverified  
- A reactivation email is required  

Prevents automated password guessing.

---

### **5. reCAPTCHA v2 Protection**

Both login and registration require Google reCAPTCHA v2 (“I’m not a robot”).

Backend verification uses:

