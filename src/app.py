from flask import Flask

app = Flask(__name__)

app.config["SECRET_KEY"] = "enterprise_audit_platform"

from src.routes import dashboard
from src.routes import api
