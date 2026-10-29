"""Lantern - quản trị tài khoản. Mọi route ở đây chỉ dành cho role admin (kiểm tra ở server)."""
import sqlite3
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from . import auth, db

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(auth.require_admin)])
ROLES = ("admin", "user")


class UserIn(BaseModel):
    username: str
    name: str
    email: str
    password: str
    role: str = "user"


class UserPatch(BaseModel):
    username: str | None = None
    name: str | None = None
    email: str | None = None
    password: str | None = None  # None hoặc "" = giữ nguyên mật khẩu
    role: str | None = None


# ---------- kiểm tra dữ liệu ----------
def _username(v: str) -> str:
    v = v.strip().lower()
    if not auth.USERNAME_RE.match(v):
        raise HTTPException(400, "Tên đăng nhập gồm 3–30 ký tự: chữ cái, số, dấu _ hoặc .")
    return v


def _name(v: str) -> str:
    v = v.strip()
    if not (1 <= len(v) <= 80) or any(ch in v for ch in "\r\n"):
        raise HTTPException(400, "Họ tên không hợp lệ (1–80 ký tự)")
    return v


def _email(v: str) -> str:
    v = v.strip().lower()
    if len(v) > 254 or not auth.EMAIL_RE.match(v):
        raise HTTPException(400, "Email không hợp lệ")
    return v


def _role(v: str) -> str:
    if v not in ROLES:
        raise HTTPException(400, "Role phải là admin hoặc user")
    return v


def _password(pw: str, username: str, email: str) -> str:
    if not (8 <= len(pw) <= 128):
        raise HTTPException(400, "Mật khẩu phải từ 8 đến 128 ký tự")
    if pw.isdigit() or pw.lower() in (email, username):
        raise HTTPException(400, "Mật khẩu quá dễ đoán")
    return pw


def _public(c, uid: int) -> dict:
    r = c.execute(
        "SELECT u.id,u.username,u.name,u.email,u.role,u.created_at,"
        "(SELECT COUNT(*) FROM assets a WHERE a.user_id=u.id) AS assets FROM users u WHERE u.id=?", (uid,)
    ).fetchone()
    return {"id": r["id"], "username": r["username"], "name": r["name"], "email": r["email"],
            "role": r["role"], "assets": r["assets"], "t": r["created_at"] * 1000}


def _conflicts(c, username: str, email: str, exclude_id: int = 0):
    if c.execute("SELECT 1 FROM users WHERE username=? AND id<>?", (username, exclude_id)).fetchone():
        raise HTTPException(409, "Tên đăng nhập này đã được sử dụng")
    if c.execute("SELECT 1 FROM users WHERE email=? AND id<>?", (email, exclude_id)).fetchone():
        raise HTTPException(409, "Email này đã được sử dụng")


def _other_admins(c, uid: int) -> int:
    return c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND id<>?", (uid,)).fetchone()[0]


# ---------- route ----------
@router.get("/users")
def list_users():
    with db.conn() as c:
        ids = [r[0] for r in c.execute("SELECT id FROM users ORDER BY id")]
        return [_public(c, i) for i in ids]


@router.post("/users", status_code=201)
def create_user(body: UserIn):
    username, name, email, role = _username(body.username), _name(body.name), _email(body.email), _role(body.role)
    pw_hash = auth.hash_pw(_password(body.password, username, email))
    with db.conn() as c:
        _conflicts(c, username, email)
        # Dọn đăng ký đang chờ OTP trùng thông tin, tránh va chạm khi người đó xác thực sau
        c.execute("DELETE FROM pending_signups WHERE email=? OR username=?", (email, username))
        try:
            cur = c.execute(
                "INSERT INTO users(email,name,username,role,pw_hash,created_at) VALUES(?,?,?,?,?,?)",
                (email, name, username, role, pw_hash, int(time.time())),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Tên đăng nhập hoặc email đã được sử dụng")
        return _public(c, cur.lastrowid)


@router.patch("/users/{uid}")
def update_user(uid: int, body: UserPatch, request: Request, me: dict = Depends(auth.current_user)):
    with db.conn() as c:
        t = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not t:
            raise HTTPException(404, "Không tìm thấy tài khoản")
        username = _username(body.username) if body.username is not None else t["username"]
        name = _name(body.name) if body.name is not None else t["name"]
        email = _email(body.email) if body.email is not None else t["email"]
        role = _role(body.role) if body.role is not None else t["role"]
        if role != t["role"]:
            if uid == me["id"]:
                raise HTTPException(400, "Bạn không thể tự đổi role của chính mình")
            if t["role"] == "admin" and _other_admins(c, uid) == 0:
                raise HTTPException(400, "Không thể hạ quyền admin cuối cùng của hệ thống")
        _conflicts(c, username, email, uid)
        new_hash = auth.hash_pw(_password(body.password, username, email)) if body.password else None
        c.execute("DELETE FROM pending_signups WHERE email=? OR username=?", (email, username))
        c.execute("UPDATE users SET username=?, name=?, email=?, role=? WHERE id=?", (username, name, email, role, uid))
        if new_hash:
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (new_hash, uid))
            # Đổi mật khẩu thì đăng xuất các thiết bị khác của người đó (giữ phiên hiện tại nếu là chính admin)
            keep = auth._th(request.cookies.get(auth.COOKIE, "")) if uid == me["id"] else ""
            c.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (uid, keep))
        return _public(c, uid)


@router.delete("/users/{uid}", status_code=204)
def delete_user(uid: int, me: dict = Depends(auth.current_user)):
    if uid == me["id"]:
        raise HTTPException(400, "Bạn không thể xóa chính tài khoản đang đăng nhập")
    with db.conn() as c:
        t = c.execute("SELECT email,role FROM users WHERE id=?", (uid,)).fetchone()
        if not t:
            raise HTTPException(404, "Không tìm thấy tài khoản")
        if t["role"] == "admin" and _other_admins(c, uid) == 0:
            raise HTTPException(400, "Không thể xóa admin cuối cùng của hệ thống")
        # Xóa kèm phiên, tài sản, phát hiện, lần quét (ON DELETE CASCADE) và yêu cầu quên mật khẩu còn dở
        c.execute("DELETE FROM password_resets WHERE email=?", (t["email"],))
        c.execute("DELETE FROM users WHERE id=?", (uid,))
