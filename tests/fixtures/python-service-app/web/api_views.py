"""Flask blueprint views (synthetic fixture)."""
from __future__ import annotations

from flask import Blueprint, abort, request, session

from web.auth import login_required, require_api_key, require_subscription

bp = Blueprint("api", __name__, url_prefix="/v1")

bp.before_request(require_api_key)


@bp.route("/health")
def health():
    return {"status": "ok"}


@bp.route("/orders/<int:order_id>")
@login_required
def get_order(order_id: int):
    order = Order.query.filter(Order.user_id == session["user_id"]).first()
    if order is None:
        abort(404)
    return {"id": order.id}


@bp.route("/orders", methods=["POST"])
def create_order():
    body = request.get_json(force=True)
    return {"id": 2, "item": body.get("item")}, 201


@bp.route("/orders/<int:order_id>", methods=["DELETE"])
@require_subscription
def delete_order(order_id: int):
    return {"deleted": order_id}
