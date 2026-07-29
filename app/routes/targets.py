import time
from flask import Blueprint, jsonify, request
from app.targets_manager import load_targets, save_targets

targets_bp = Blueprint("targets", __name__)

@targets_bp.route("/api/targets", methods=["GET", "POST", "DELETE"])
def api_targets():
    if request.method == "GET":
        return jsonify(load_targets())
    elif request.method == "POST":
        data = request.json or {}
        targets = load_targets()
        if "id" in data and any(t["id"] == data["id"] for t in targets):
            targets = [data if t["id"] == data["id"] else t for t in targets]
        else:
            data["id"] = f"t{int(time.time())}"
            targets.append(data)
        save_targets(targets)
        return jsonify(success=True, targets=targets)
    elif request.method == "DELETE":
        tid = request.args.get("id", "")
        targets = [t for t in load_targets() if t["id"] != tid]
        save_targets(targets)
        return jsonify(success=True, targets=targets)
