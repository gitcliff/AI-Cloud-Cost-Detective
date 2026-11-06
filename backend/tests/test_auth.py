"""Tests for JWT auth module."""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import HTTPException

from auth import create_token, decode_token, decode_token_raw, hash_password, verify_password


class TestCreateAndDecodeToken:
    def test_roundtrip(self):
        token = create_token(42)
        user_id = decode_token(token)
        assert user_id == 42

    def test_decode_raw_valid(self):
        token = create_token(7)
        assert decode_token_raw(token) == 7

    def test_decode_raw_invalid(self):
        assert decode_token_raw("garbage.token.value") is None

    def test_decode_invalid_raises(self):
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not.a.valid.token")
        assert exc_info.value.status_code == 401

    def test_expired_token(self):
        # Create a token that expires immediately
        original = os.environ.get("JWT_EXPIRE_HOURS")
        os.environ["JWT_EXPIRE_HOURS"] = "0"
        try:
            token = create_token(1)
            time.sleep(1)
            with pytest.raises(HTTPException) as exc_info:
                decode_token(token)
            assert exc_info.value.status_code == 401
        finally:
            if original is not None:
                os.environ["JWT_EXPIRE_HOURS"] = original
            else:
                os.environ["JWT_EXPIRE_HOURS"] = "1"

    def test_different_users_different_tokens(self):
        t1 = create_token(1)
        t2 = create_token(2)
        assert t1 != t2
        assert decode_token(t1) == 1
        assert decode_token(t2) == 2


class TestPasswordHashing:
    @pytest.mark.asyncio
    async def test_hash_and_verify(self):
        hashed = await hash_password("secure-password-123")
        assert hashed != "secure-password-123"
        assert await verify_password("secure-password-123", hashed) is True

    @pytest.mark.asyncio
    async def test_wrong_password(self):
        hashed = await hash_password("correct-password")
        assert await verify_password("wrong-password", hashed) is False
