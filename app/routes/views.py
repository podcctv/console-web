import socket
from flask import Blueprint, render_template
import app.config as app_config
from app.network import ensure_isp_info, ISP_FULL_NAME, ISP_SHORT_NAME

views_bp = Blueprint("views", __name__)

@views_bp.route("/")
def index():
    ensure_isp_info()
    hostname = ISP_FULL_NAME or socket.gethostname()
    short_isp = ISP_SHORT_NAME or socket.gethostname()
    return render_template("index.html", hostname=hostname, short_isp=short_isp, version=app_config.__version__)
