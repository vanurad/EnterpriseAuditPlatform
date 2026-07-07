import json
import os

from flask import request, jsonify, render_template, make_response
from src.app import app
from src.services.audit_service import AuditService


LAST_AUDIT_RESULT = {}

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVERS_FILE = os.path.join(BASE_DIR, "database", "servers.json")


def load_servers():
    if not os.path.exists(SERVERS_FILE):
        return []

    with open(SERVERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_servers(servers):
    os.makedirs(os.path.dirname(SERVERS_FILE), exist_ok=True)

    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(servers, f, indent=4)


@app.route("/api/servers/list", methods=["GET"])
def list_servers():
    return jsonify({
        "status": "success",
        "servers": load_servers()
    })


@app.route("/api/servers/add", methods=["POST"])
def add_server():
    data = request.get_json()

    servers = load_servers()

    servers.append({
        "name": data.get("name", "").strip(),
        "ip": data.get("ip", "").strip(),
        "username": data.get("username", "").strip(),
        "password": data.get("password", "").strip()
    })

    save_servers(servers)

    return jsonify({
        "status": "success",
        "message": "Server saved successfully."
    })


@app.route("/api/audit/start", methods=["POST"])
def start_audit():
    global LAST_AUDIT_RESULT

    try:
        data = request.get_json()

        results = AuditService.start(
            data["ip"],
            data["username"],
            data["password"]
        )

        LAST_AUDIT_RESULT = results

        return jsonify({
            "status": "success",
            "redirect": "/audit/results"
        })

    except Exception as ex:
        import traceback

        return jsonify({
            "status": "failed",
            "message": str(ex),
            "traceback": traceback.format_exc()
        }), 500


@app.route("/audit/results")
def audit_results():
    results = LAST_AUDIT_RESULT

    system = results.get("system", {})
    services = results.get("services", [])
    password_policy = results.get("password_policy", [])
    account_lockout_policy = results.get("account_lockout_policy", [])
    audit_policy = results.get("audit_policy", [])
    ntp_policy = results.get("ntp_policy", [])
    local_users = results.get("local_users", [])
    local_groups = results.get("local_groups", [])
    security_updates = results.get("security_updates", [])

    all_checks = services + password_policy + account_lockout_policy + audit_policy + ntp_policy

    total = len(all_checks)
    passed = len([item for item in all_checks if item.get("Status") == "PASS"])
    failed = total - passed
    score = round((passed / total) * 100, 2) if total else 0

    return render_template(
        "audit/results.html",
        system=system,
        services=services,
        password_policy=password_policy,
        account_lockout_policy=account_lockout_policy,
        audit_policy=audit_policy,
        ntp_policy=ntp_policy,
        local_users=local_users,
        local_groups=local_groups,
        security_updates=security_updates,
        total=total,
        passed=passed,
        failed=failed,
        score=score
    )


@app.route("/audit/download/html")
def download_html_report():
    results = LAST_AUDIT_RESULT

    system = results.get("system", {})
    services = results.get("services", [])
    password_policy = results.get("password_policy", [])
    account_lockout_policy = results.get("account_lockout_policy", [])
    audit_policy = results.get("audit_policy", [])
    ntp_policy = results.get("ntp_policy", [])
    local_users = results.get("local_users", [])
    local_groups = results.get("local_groups", [])
    security_updates = results.get("security_updates", [])

    all_checks = services + password_policy + account_lockout_policy + audit_policy + ntp_policy

    total = len(all_checks)
    passed = len([item for item in all_checks if item.get("Status") == "PASS"])
    failed = total - passed
    score = round((passed / total) * 100, 2) if total else 0

    html = render_template(
        "audit/download_report.html",
        system=system,
        services=services,
        password_policy=password_policy,
        account_lockout_policy=account_lockout_policy,
        audit_policy=audit_policy,
        ntp_policy=ntp_policy,
        local_users=local_users,
        local_groups=local_groups,
        security_updates=security_updates,
        total=total,
        passed=passed,
        failed=failed,
        score=score
    )

    response = make_response(html)
    response.headers["Content-Type"] = "text/html"
    response.headers["Content-Disposition"] = "attachment; filename=windows_audit_report.html"

    return response