"""Item routes (synthetic fixture)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.deps import get_current_user
from db import Item, session

router = APIRouter(prefix="/items", tags=["items"])


@router.get("/{item_id}")
def get_item(item_id: int):
    return session.query(Item).get(item_id)


@router.post("/", status_code=201, dependencies=[Depends(get_current_user)])
def create_item(payload: dict):
    return {"id": 1, "owner": payload.get("owner")}
