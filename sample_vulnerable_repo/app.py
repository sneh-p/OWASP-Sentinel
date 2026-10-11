"""Sample Vulnerable Flask Application for OWASP Top 10 Testing."""

import os
import sqlite3
import hashlib
import pickle
import logging
import requests
import tempfile
import random
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# A02: Hardcoded Secret Key
SECRET_KEY = "super_secret_jwt_token_1234567890_insecure"
app.config['SECRET_KEY'] = SECRET_KEY

# A05: Debug mode enabled
app.config['DEBUG'] = True

logger = logging.getLogger(__name__)

def get_db():
    conn = sqlite3.connect('test.db')
    return conn

# A01: Broken Access Control - Path Traversal
@app.route('/view-file')
def view_file():
    filename = request.args.get('filename')
    # Vulnerable to path traversal
    file_path = os.path.join('/var/data', request.args['filename'])
    with open(file_path, 'r') as f:
        return f.read()

# A02: Cryptographic Failures - Weak MD5 Hash & verify=False
@app.route('/hash-password')
def hash_password():
    pwd = request.args.get('pwd', '')
    # Weak MD5 hashing
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    # Disabled SSL Verification
    res = requests.get("https://internal.auth.service/sync", verify=False)
    return jsonify({"hash": hashed})

# A03: Injection - SQL Injection & Command Injection & XSS
@app.route('/search-user')
def search_user():
    username = request.args.get('username', '')
    conn = get_db()
    cursor = conn.cursor()
    # SQL Injection via f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    
    # XSS via render_template_string
    template = f"<h3>Results for {request.args.get('username')}:</h3>"
    return render_template_string(template)

@app.route('/ping')
def ping_host():
    host = request.args.get('host', 'localhost')
    # Command Injection via os.system
    os.system("ping -c 1 " + request.args['host'])
    return "Ping executed"

# A04: Insecure Design - Client-Controlled Pricing
@app.route('/checkout', methods=['POST'])
def checkout():
    # Trusting client for payment amount
    price = request.json['price']
    item_id = request.json['item_id']
    return jsonify({"status": "charged", "amount": price})

# A05: Security Misconfiguration - Exposing Stack Trace
@app.route('/error-test')
def error_test():
    try:
        1 / 0
    except Exception as e:
        import traceback
        # Detailed stack trace leaked to client
        return traceback.format_exc(), 500

# A07: Authentication Failure - Timing Attack & Insecure Cookie
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # Direct password string comparison (timing attack)
    if password == "master_backdoor_password":
        response = jsonify({"login": "success"})
        # Insecure cookie without HttpOnly or Secure flag
        response.set_cookie('session_id', 'sess_12345', httponly=False, secure=False)
        return response
    return jsonify({"login": "failed"}), 401

# A08: Software and Data Integrity Failures - Insecure Deserialization
@app.route('/load-profile', methods=['POST'])
def load_profile():
    raw_payload = request.data
    # Insecure pickle deserialization
    user_obj = pickle.loads(raw_payload)
    return jsonify({"status": "loaded"})

# A09: Security Logging Failures - Sensitive Data Logged & Swallowed Exceptions
@app.route('/log-attempt', methods=['POST'])
def log_attempt():
    pwd = request.form.get('password')
    # Logging sensitive password in plaintext
    logger.info(f"User login attempt with password: {pwd}")
    try:
        critical_operation()
    except Exception:
        # Silent exception swallowing
        pass
    return "Logged"

def critical_operation():
    raise RuntimeError("Unexpected failure")

# A10: Server-Side Request Forgery (SSRF)
@app.route('/fetch-remote')
def fetch_remote():
    target_url = request.args.get('url')
    # Unvalidated SSRF
    resp = requests.get(request.args.get('url'), timeout=5)
    return resp.text

# CWE-TOP-25 & System Weaknesses: Permissions, Temporary Files & Weak Randomness
@app.route('/system-ops')
def system_ops():
    # CWE-377: Insecure temp file creation
    tmp_path = tempfile.mktemp(prefix="user_export_")
    # CWE-276: World-writable permissions
    os.chmod(tmp_path, 0o777)
    # CWE-330: Insufficiently random token
    session_token = str(random.random())
    # CWE-362: TOCTOU race condition
    if os.path.exists(tmp_path):
        with open(tmp_path, "r") as f:
            _ = f.read()
    return jsonify({"token": session_token})

if __name__ == '__main__':
    # Debug mode active
    app.run(host='0.0.0.0', port=5000, debug=True)
