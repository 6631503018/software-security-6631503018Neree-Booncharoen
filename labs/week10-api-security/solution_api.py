
"""SECURE reference — Week 10 API Security
API1: Object-level authorization
API3: Allow-list binding
API4: Per-IP rate limiting
"""

import time
from collections import defaultdict
from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "password": "alice123",
        "balance": 100,
        "is_admin": False,
    },
    2: {
        "id": 2,
        "username": "bob",
        "password": "bob123",
        "balance": 50,
        "is_admin": False,
    },
    3: {
        "id": 3,
        "username": "carol",
        "password": "carol123",
        "balance": 9999,
        "is_admin": True,
    },
}

ORDERS = {
    1: [{"order_id": "A-1", "item": "Keyboard", "total": 30}],
    2: [{"order_id": "B-1", "item": "Mouse", "total": 15}],
    3: [{"order_id": "C-1", "item": "Server rack", "total": 5000}],
}

_next_id = 4

# API3: Only allow safe client-supplied fields.
ALLOWED_CREATE_FIELDS = {"username", "password"}


def current_user():
    """Resolve the caller using the lab's X-User-Id header."""
    try:
        user_id = int(request.headers.get("X-User-Id", 0))
        return USERS.get(user_id)
    except (TypeError, ValueError):
        return None


# API1: Object-level authorization
@app.get("/api/users/<int:uid>/orders")
def get_orders(uid):
    caller = current_user()

    if caller is None:
        return jsonify({"error": "authentication required"}), 401

    if caller["id"] != uid and not caller["is_admin"]:
        return jsonify({"error": "forbidden"}), 403

    if uid not in ORDERS:
        return jsonify({"error": "user or orders not found"}), 404

    return jsonify(ORDERS[uid]), 200


# API3: Mass-assignment protection
@app.post("/api/users")
def create_user():
    global _next_id

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400

    user = {
        key: body[key]
        for key in ALLOWED_CREATE_FIELDS
        if key in body
    }

    if not isinstance(user.get("username"), str) or not user["username"].strip():
        return jsonify({"error": "valid username required"}), 400

    if not isinstance(user.get("password"), str) or not user["password"]:
        return jsonify({"error": "valid password required"}), 400

    if any(existing["username"] == user["username"] for existing in USERS.values()):
        return jsonify({"error": "username already exists"}), 409

    # Sensitive properties are controlled by the server.
    user.update({
        "id": _next_id,
        "balance": 0,
        "is_admin": False,
    })

    USERS[_next_id] = user
    _next_id += 1

    return jsonify(user), 201


# API4: Per-IP rate limiting
RATE_LIMIT = 5
RATE_WINDOW = 60
_attempts = defaultdict(list)


def rate_limited(ip):
    now = time.time()

    # Remove attempts outside the time window.
    _attempts[ip] = [
        timestamp
        for timestamp in _attempts[ip]
        if now - timestamp < RATE_WINDOW
    ]

    if len(_attempts[ip]) >= RATE_LIMIT:
        return True

    _attempts[ip].append(now)
    return False


@app.post("/api/login")
def login():
    ip = request.remote_addr or "unknown"

    if rate_limited(ip):
        return jsonify({"error": "too many requests"}), 429

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400

    username = body.get("username")
    password = body.get("password")

    for user in USERS.values():
        if user["username"] == username and user["password"] == password:
            return jsonify({
                "ok": True,
                "user_id": user["id"],
                "is_admin": user["is_admin"],
            }), 200

    return jsonify({"ok": False}), 401


@app.get("/")
def index():
    return "Week 10 SECURE API", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
