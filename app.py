import os
import sqlite3
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY", "linkpay-pro-secret-2026")
DATABASE = "database.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                service_type TEXT NOT NULL,
                fee REAL NOT NULL,
                due_day INTEGER NOT NULL,
                phone TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                paid_status TEXT DEFAULT 'paid'
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                tenant_username TEXT NOT NULL,
                name TEXT NOT NULL,
                plan TEXT NOT NULL,
                price REAL NOT NULL,
                due_day INTEGER NOT NULL,
                phone TEXT,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (tenant_username) REFERENCES tenants (username)
            )
        """)
        db.execute("""
            INSERT OR IGNORE INTO tenants (id, name, username, password, service_type, fee, due_day, phone, status, paid_status)
            VALUES 
            ('prov_henrique', 'Provedor Henrique', 'henrique', '12345678', 'telecom', 49.90, 20, '11947988158', 'active', 'paid'),
            ('prov_demo', 'Provedor Demonstração', 'admin', '123456', 'telecom', 59.90, 10, '11999999999', 'active', 'paid')
        """)
        db.commit()

init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token de autenticação ausente"}), 401
        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data["user"]
            current_role = data["role"]
        except Exception:
            return jsonify({"error": "Token inválido ou expirado"}), 401
        return f(current_user, current_role, *args, **kwargs)
    return decorated

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if username == "master" and password == "master@2026":
        token = jwt.encode({
            "user": "master",
            "role": "master",
            "exp": datetime.utcnow() + timedelta(days=7)
        }, SECRET_KEY, algorithm="HS256")
        return jsonify({"token": token, "role": "master", "user": "master", "name": "Administrador Master"})

    with get_db() as db:
        tenant = db.execute("SELECT * FROM tenants WHERE LOWER(username) = ?", (username,)).fetchone()
        if tenant and tenant["password"] == password:
            if tenant["status"] == "blocked":
                return jsonify({"error": "Acesso bloqueado. Contate o suporte."}), 403
            token = jwt.encode({
                "user": tenant["username"],
                "role": "tenant",
                "exp": datetime.utcnow() + timedelta(days=7)
            }, SECRET_KEY, algorithm="HS256")
            return jsonify({
                "token": token,
                "role": "tenant",
                "user": tenant["username"],
                "name": tenant["name"],
                "service_type": tenant["service_type"]
            })

    return jsonify({"error": "Usuário ou senha incorretos"}), 401

@app.route("/api/master/tenants", methods=["GET"])
@token_required
def list_tenants(current_user, current_role):
    if current_role != "master":
        return jsonify({"error": "Não autorizado"}), 403
    with get_db() as db:
        rows = db.execute("SELECT * FROM tenants").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/clients", methods=["GET"])
@token_required
def get_clients(current_user, current_role):
    tenant = request.args.get("tenant", current_user) if current_role == "master" else current_user
    with get_db() as db:
        rows = db.execute("SELECT * FROM clients WHERE tenant_username = ?", (tenant,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/clients", methods=["POST"])
@token_required
def add_client(current_user, current_role):
    data = request.get_json()
    tenant = data.get("tenant_username", current_user) if current_role == "master" else current_user
    client_id = "client_" + str(int(datetime.utcnow().timestamp() * 1000))
    with get_db() as db:
        db.execute("""
            INSERT INTO clients (id, tenant_username, name, plan, price, due_day, phone, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            client_id,
            tenant,
            data["name"].strip(),
            data["plan"],
            float(data["price"]),
            int(data["due_day"]),
            data.get("phone", "").strip(),
            data.get("status", "pending")
        ))
        db.commit()
    return jsonify({"message": "Cliente cadastrado", "id": client_id}), 201

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
