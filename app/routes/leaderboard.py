"""
NetWatch VPS Leaderboard & Deals API Route (选品榜单 & CN被墙小鸡榜)
"""

from flask import Blueprint, jsonify, request
from app.leaderboard import get_leaderboard_data, CATEGORIES_META

leaderboard_bp = Blueprint("leaderboard", __name__)

@leaderboard_bp.route("/api/leaderboard", methods=["GET"])
def api_leaderboard():
    category = request.args.get("category", "cn_blocked").strip()
    sort_by = request.args.get("sort", "recommend").strip()
    search = request.args.get("q", "").strip()
    region = request.args.get("region", "all").strip()

    data = get_leaderboard_data(category=category, sort_by=sort_by, search=search, region=region)
    return jsonify(data)

@leaderboard_bp.route("/api/leaderboard/categories", methods=["GET"])
def api_leaderboard_categories():
    return jsonify({"categories": CATEGORIES_META})
