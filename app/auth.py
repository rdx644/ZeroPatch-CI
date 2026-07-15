"""GitHub OAuth and service-key authentication helpers."""
from __future__ import annotations

import hmac
import os
import secrets
from collections.abc import Mapping
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"


def oauth_enabled() -> bool:
    return bool(os.getenv("GITHUB_CLIENT_ID") and os.getenv("GITHUB_CLIENT_SECRET"))


def callback_url(request: Request) -> str:
    return os.getenv("GITHUB_REDIRECT_URI") or str(request.url_for("github_callback"))


def begin_github_login(request: Request) -> str:
    if not oauth_enabled():
        raise HTTPException(status_code=503, detail="GitHub sign-in is not configured.")
    state = secrets.token_urlsafe(32)
    request.session["github_oauth_state"] = state
    query = urlencode({
        "client_id": os.environ["GITHUB_CLIENT_ID"],
        "redirect_uri": callback_url(request),
        "scope": "read:user user:email",
        "state": state,
    })
    return f"{GITHUB_AUTHORIZE_URL}?{query}"


async def github_identity(request: Request, code: str, state: str) -> Mapping[str, object]:
    expected_state = request.session.pop("github_oauth_state", "")
    if not isinstance(expected_state, str) or not hmac.compare_digest(expected_state, state):
        raise HTTPException(status_code=400, detail="Invalid or expired GitHub sign-in state.")

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        token_response = await client.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": os.environ["GITHUB_CLIENT_ID"],
                "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
                "code": code,
                "redirect_uri": callback_url(request),
            },
        )
        if token_response.status_code != 200:
            raise HTTPException(status_code=502, detail="GitHub token exchange failed.")
        access_token = token_response.json().get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise HTTPException(status_code=502, detail="GitHub did not return an access token.")
        user_response = await client.get(
            GITHUB_USER_URL,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    if user_response.status_code != 200:
        raise HTTPException(status_code=502, detail="GitHub identity lookup failed.")
    identity = user_response.json()
    login = identity.get("login")
    user_id = identity.get("id")
    if not isinstance(login, str) or not isinstance(user_id, int):
        raise HTTPException(status_code=502, detail="GitHub returned an incomplete identity.")
    return {"id": user_id, "login": login, "avatar_url": identity.get("avatar_url")}


def current_identity(request: Request) -> Mapping[str, object]:
    identity = request.session.get("identity")
    if not isinstance(identity, dict) or not isinstance(identity.get("login"), str):
        raise HTTPException(status_code=401, detail="Sign in with GitHub to use the API.")
    return identity


def service_identity(request: Request) -> Mapping[str, object] | None:
    """Match an automation key without ever logging or returning its value."""
    supplied = request.headers.get("X-ZeroPatch-Key", "")
    configured = [value.strip() for value in os.getenv("ZEROPATCH_API_KEYS", "").split(",") if value.strip()]
    if not supplied or not configured:
        return None
    if any(hmac.compare_digest(supplied, value) for value in configured):
        return {"login": "automation", "role": "service"}
    return None


def is_admin(identity: Mapping[str, object]) -> bool:
    if identity.get("role") == "service":
        return True
    login = identity.get("login")
    admins = {value.strip().casefold() for value in os.getenv("ZEROPATCH_ADMIN_LOGINS", "").split(",") if value.strip()}
    return isinstance(login, str) and login.casefold() in admins