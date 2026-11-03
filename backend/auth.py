import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

security = HTTPBearer()


def _get_jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET not set. Add it to your .env file.")
    return secret


async def hash_password(password: str) -> str:
    """Hash a password with bcrypt. Runs in executor since bcrypt is CPU-bound."""
    loop = asyncio.get_event_loop()
    hashed = await loop.run_in_executor(
        None, bcrypt.hashpw, password.encode("utf-8"), bcrypt.gensalt()
    )
    return hashed.decode("utf-8")


async def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash. Runs in executor."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, bcrypt.checkpw, password.encode("utf-8"), hashed.encode("utf-8")
    )


def create_token(user_id: int) -> str:
    """Create a JWT token for the given user_id."""
    secret = _get_jwt_secret()
    algorithm = os.getenv("JWT_ALGORITHM", "HS256")
    expire_hours = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(hours=expire_hours),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def decode_token(token: str) -> int:
    """Decode a JWT token and return the user_id. Raises HTTPException on failure."""
    secret = _get_jwt_secret()
    algorithm = os.getenv("JWT_ALGORITHM", "HS256")

    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject",
            )
        return int(user_id)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


def decode_token_raw(token: str) -> int | None:
    """Decode a JWT token and return the user_id, or None on any failure.
    Use this for WebSocket auth where HTTP exceptions don't apply."""
    secret = _get_jwt_secret()
    algorithm = os.getenv("JWT_ALGORITHM", "HS256")

    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
        user_id = payload.get("sub")
        return int(user_id) if user_id is not None else None
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> int:
    """FastAPI dependency that extracts and validates the JWT from the Authorization header.
    Returns the user_id."""
    return decode_token(credentials.credentials)
