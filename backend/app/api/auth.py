"""
API key authentication dependency.

FastAPI uses dependency injection for auth — a function that runs
before the endpoint handler and either passes through or raises
HTTP 401/403. This keeps auth logic out of each endpoint function.

Design notes:

- The API key is read from the API_KEY environment variable.
  In dev with no key set, a known insecure default is used so the
  server still starts and responds. In production (Phase 8), set
  a real random key via your deployment's env var config.

- Constant-time comparison (hmac.compare_digest) prevents timing
  attacks where an attacker infers the correct key length by
  measuring how long the comparison takes.

- The header name is X-API-Key — the de facto standard for API key
  auth in REST APIs. Not X-Auth-Token (old) or Authorization: Bearer
  (that's OAuth/JWT territory, overkill here).

- /api/health deliberately bypasses auth. Load balancers and
  monitoring tools need to check liveness without a key.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status


# In dev with no key set, this default forces the client to send
# SOMETHING, but it's well-known so not secure. Set API_KEY in
# your environment for real use.
_DEV_FALLBACK_KEY = "dev-only-insecure-key"


def _get_expected_key() -> str:
    return os.environ.get("API_KEY", _DEV_FALLBACK_KEY)


async def require_api_key(
    x_api_key: str = Header(
        ...,
        alias="X-API-Key",
        description="API key for authentication. Set via API_KEY environment variable.",
    ),
) -> str:
    """
    FastAPI dependency that validates the X-API-Key header.

    Raises HTTP 401 if the header is missing (FastAPI handles this
    automatically when the header is declared with `...` — required).
    Raises HTTP 403 if the key doesn't match.

    Returns the validated key so endpoints can log it if needed.
    """
    expected = _get_expected_key()
    if not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key.",
        )
    return x_api_key