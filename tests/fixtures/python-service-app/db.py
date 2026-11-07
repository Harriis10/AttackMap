"""Database access for the service (synthetic fixture)."""
from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.settings import settings

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)


class Item:
    """Stand-in ORM model (synthetic fixture)."""


def lookup_order_raw(order_id: int):
    with SessionLocal() as db:
        return db.execute(
            text("SELECT * FROM orders WHERE id = :order_id"),
            {"order_id": order_id},
        ).first()


def orders_scoped_to(user_sub: str):
    with SessionLocal() as db:
        return db.query(Item).filter(Item.owner_id == user_sub).all()
