"""API, Secrets, and Advanced SAST Vulnerability Demonstration."""

import os
import re
import tempfile
import xml.etree.ElementTree as ET
from flask import Flask, request, jsonify
from jinja2 import Environment

app = Flask(__name__)

# Enterprise Database Connection String with embedded credentials (SEC-SEC-004)
DATABASE_URI = "postgres://db_admin:SuperSecretPass123@10.0.4.15:5432/customer_db"

# High-Entropy API Token (SEC-A02-007)
SECRET_API_TOKEN = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12345"

# Catastrophic ReDoS nested quantifier pattern (SEC-A03-008)
EMAIL_REGEX = re.compile(r"^([a-zA-Z0-9_]+)+$")

# Insecure Jinja2 environment with autoescape disabled (SEC-A03-009)
unsafe_jinja_env = Environment(autoescape=False)

class User:
    def __init__(self, id, name, role="viewer"):
        self.id = id
        self.name = name
        self.role = role

    def update(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

class Item:
    class Query:
        def all(self):
            return [{"id": 1, "item": "Widget"}, {"id": 2, "item": "Gadget"}]
    query = Query()

# OWASP API Security: Mass Assignment (SEC-API-001)
@app.route('/api/user/profile', methods=['PUT'])
def update_profile():
    user = User(1, "Alice")
    # Vulnerable: directly mass-assigning request JSON properties
    user.update(**request.json)
    return jsonify({"status": "updated", "role": user.role})

# OWASP API Security: Unrestricted Resource Consumption (SEC-API-002)
@app.route('/api/inventory', methods=['GET'])
def get_inventory():
    # Vulnerable: fetching all database records without pagination or limits
    items = Item.query.all()
    return jsonify(items)

# OWASP API Security: Broken Function Level Authorization (SEC-API-003)
@app.route('/api/admin/system/flush', methods=['POST'])
def flush_cache():
    # Vulnerable: Admin route without @admin_required or role checks
    return jsonify({"status": "cache flushed"})

# OWASP API Security: Excessive Data Exposure (SEC-API-004)
@app.route('/api/user/<int:user_id>', methods=['GET'])
def get_user_details(user_id):
    # Vulnerable: Exposing password_hash in API response
    return jsonify({
        "id": user_id,
        "username": "admin",
        "password_hash": "$2b$12$e8k...secretHashLeaked...",
        "auth_token": "bearer_secret_token_123"
    })

# Insecure Temporary File Creation via tempfile.mktemp (SEC-A01-005)
@app.route('/api/export', methods=['POST'])
def export_report():
    # Vulnerable TOCTOU race condition
    temp_path = tempfile.mktemp(suffix=".csv")
    with open(temp_path, "w") as f:
        f.write("id,data\n1,test")
    return jsonify({"file": temp_path})

# XML External Entity (XXE) Injection (SEC-A03-007)
@app.route('/api/xml-import', methods=['POST'])
def parse_xml_payload():
    xml_data = request.data
    # Vulnerable to external entity expansion
    root = ET.fromstring(xml_data)
    return jsonify({"tag": root.tag})
