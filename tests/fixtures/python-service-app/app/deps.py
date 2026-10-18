"""Auth dependencies for the FastAPI app (synthetic fixture)."""
from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, "fixture-public-key", algorithms=["RS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return {"sub": payload["sub"]}


def verify_tenant(user: dict = Depends(get_current_user)) -> dict:
    if not user.get("sub", "").endswith("@example.com"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user
