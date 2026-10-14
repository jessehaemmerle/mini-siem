from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ..auth import (ROLE_LABELS, SESSION_COOKIE, check_password_policy, create_session,
                    delete_session, hash_password, hash_token, verify_password)
from .deps import client_ip, current_user, get_core

router = APIRouter(prefix="/api/auth", tags=["Anmeldung"])


class LoginIn(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=256)


class PasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(max_length=256)


def _public(user: dict) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "role": user["role"],
        "role_label": ROLE_LABELS.get(user["role"], user["role"]),
    }


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, core=Depends(get_core)):
    ip = client_ip(request) or "?"
    key = f"{ip}|{body.username.lower()}"
    if core.throttle.blocked(key) or core.throttle.blocked(ip):
        raise HTTPException(429, "Zu viele Fehlversuche. Bitte in 15 Minuten erneut versuchen.")
    user = core.db.one("SELECT * FROM users WHERE username = ?", (body.username.strip(),))
    if not user or not user["active"] or not verify_password(body.password, user["password_hash"]):
        core.throttle.failure(key)
        core.throttle.failure(ip)
        core.db.audit(body.username[:100], "login.failed", "", ip)
        raise HTTPException(401, "Benutzername oder Passwort ist falsch")
    core.throttle.success(key)
    hours = int(core.db.get_setting("session_hours") or 12)
    token = create_session(core.db, user["id"], ip, hours)
    secure = core.settings.cookie_secure or request.url.scheme == "https"
    response.set_cookie(SESSION_COOKIE, token, max_age=hours * 3600 * 4, httponly=True,
                        samesite="strict", secure=secure, path="/")
    core.db.audit(user["username"], "login", "", ip)
    return _public(user)


@router.post("/logout")
def logout(request: Request, response: Response, core=Depends(get_core)):
    delete_session(core.db, request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user=Depends(current_user)):
    return _public(user)


@router.post("/password")
def change_password(body: PasswordIn, request: Request, user=Depends(current_user), core=Depends(get_core)):
    row = core.db.one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
    if not row or not verify_password(body.current, row["password_hash"]):
        raise HTTPException(400, "Das aktuelle Passwort ist falsch")
    try:
        check_password_policy(body.new)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    core.db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(body.new), user["id"]))
    # andere Sitzungen dieses Benutzers beenden
    token = request.cookies.get(SESSION_COOKIE)
    core.db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                    (user["id"], hash_token(token or "")))
    core.db.audit(user["username"], "password.change", "", client_ip(request))
    initial = core.settings.data_dir / "initial-admin-password.txt"
    if initial.exists() and user["username"] == core.settings.admin_user:
        initial.unlink()
    return {"ok": True}
