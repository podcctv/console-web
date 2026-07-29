import logging
from flask import Blueprint, jsonify, Response, request
from app import acme_manager

logger = logging.getLogger(__name__)

acme_bp = Blueprint("acme", __name__)

@acme_bp.route("/.well-known/acme-challenge/<token>")
def acme_challenge_token(token):
    token_file = acme_manager.CHALLENGE_DIR / token
    if token_file.exists():
        return Response(token_file.read_text(), mimetype="text/plain")
    return Response("token not found", status=404)

@acme_bp.route("/.well-known/acme-challenge/<path:filename>")
def acme_challenge_file(filename):
    try:
        challenge_dir = acme_manager.CHALLENGE_DIR
        target_file = challenge_dir / filename
        if target_file.exists() and target_file.is_file():
            content = target_file.read_text(encoding="utf-8", errors="ignore")
            logger.info("Serving ACME HTTP-01 challenge file for %s", filename)
            return Response(content, mimetype="text/plain")
        logger.warning("ACME challenge file not found: %s (path: %s)", filename, target_file)
    except Exception as e:
        logger.exception("Error serving ACME challenge file: %s", e)
    return "Challenge file not found", 404

@acme_bp.route("/acme/status")
@acme_bp.route("/api/acme/status")
def acme_status_route():
    return jsonify(acme_manager.get_cert_status())

@acme_bp.route("/acme/issue")
@acme_bp.route("/api/acme/issue")
def acme_issue_route():
    target = request.args.get("target", "").strip() or None
    email = request.args.get("email", "").strip() or None
    success, msg = acme_manager.issue_cert(target, email)
    return jsonify(success=success, message=msg)

@acme_bp.route("/acme/renew")
@acme_bp.route("/api/acme/renew")
def acme_renew_route():
    success, msg = acme_manager.renew_cert()
    return jsonify(success=success, message=msg)
