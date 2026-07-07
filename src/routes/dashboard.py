from flask import request
from src.winrm.connection_factory import ConnectionFactory
from src.collectors.system import SystemCollector

from flask import render_template
from src.app import app


@app.route("/")
def dashboard():
    return render_template("dashboard/index.html")


@app.route("/audit")
def audit():
    return render_template("audit/new_audit.html")


@app.route("/reports")
def reports():
    return render_template("reports/reports.html")


@app.route("/settings")
def settings():
    return render_template("settings/settings.html")

@app.route("/test_connection", methods=["POST"])
def test_connection():

    ip = request.form["ip"]
    username = request.form["username"]
    password = request.form["password"]

    try:

        client = ConnectionFactory.connect(
            ip,
            username,
            password
        )

        system = SystemCollector(client)

        data = system.collect()

        return data

    except Exception as e:

        return {
            "status": "failed",
            "message": str(e)
        }, 500
