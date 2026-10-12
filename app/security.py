from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException, Request


_secret = secrets.token_bytes(32)
COOKIE = "pve_portfw_csrf"


def issue_token() -> str:
    nonce = secrets.token_hex(24)
    signature = hmac.new(_secret, nonce.encode(), hashlib.sha256).hexdigest()
    return f"{nonce}.{signature}"


def require_mutation_access(request: Request):
    origin = request.headers.get("origin")
    if origin:
        url = urlsplit(origin)
        if url.scheme != request.url.scheme or url.netloc != request.headers.get("host"):
            raise HTTPException(403, "Cross-origin changes are not allowed")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site changes are not allowed")
    cookie = request.cookies.get(COOKIE, "")
    token = request.headers.get("x-csrf-token", "")
    if not cookie or not hmac.compare_digest(cookie.encode(), token.encode()):
        raise HTTPException(403, "CSRF token missing or expired. Reload the panel.")
    nonce, _, signature = token.partition(".")
    expected = hmac.new(_secret, nonce.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature.encode(), expected.encode()):
        raise HTTPException(403, "CSRF token invalid. Reload the panel.")
