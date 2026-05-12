# INTENTIONALLY VULNERABLE — for NeuroGuard demo only
# This file contains 5 deliberate security flaws

from flask import Flask, request, jsonify
import sqlite3

# [VULN 1] Hardcoded secret key
SECRET_KEY = "admin123"

app = Flask(__name__)
app.secret_key = SECRET_KEY


def get_db():
    return sqlite3.connect("users.db")


# [VULN 2] No authentication on admin route
@app.route("/admin/users")
def list_users():
    username = request.args.get("username", "")
    conn = get_db()
    # [VULN 3] SQL injection via f-string interpolation
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    rows = conn.execute(query).fetchall()
    return jsonify(rows)


@app.route("/admin/delete")
def delete_user():
    user_id = request.args.get("id", "")
    conn = get_db()
    # [VULN 4] Second SQL injection vector
    conn.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()
    return "deleted"


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    # [VULN 5] Arbitrary code execution via eval()
    result = eval(expr)
    return str(result)


if __name__ == "__main__":
    app.run(debug=True)
