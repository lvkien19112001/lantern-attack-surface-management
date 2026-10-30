"""Lantern - xác thực người dùng (đăng ký, đăng nhập, phiên bằng cookie)."""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from . import db, mailer

COOKIE = "lantern_session"
PENDING_COOKIE = "lantern_pending"  # đăng ký đang chờ nhập OTP
RESET_COOKIE = "lantern_reset"      # yêu cầu quên mật khẩu đang chờ nhập OTP
SESSION_SECONDS = 7 * 24 * 3600
SECURE_COOKIE = os.getenv("LANTERN_SECURE_COOKIE", "0") == "1"  # đặt 1 khi chạy sau HTTPS
MAX_FAILS, FAIL_WINDOW = 5, 15 * 60

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
USERNAME_RE = re.compile(r"^[a-z0-9_.]{3,30}$")  # lưu và so khớp bằng chữ thường

OTP_TTL = 10 * 60          # mã OTP có hiệu lực 10 phút
PENDING_TTL = 30 * 60      # đăng ký chưa xác thực bị xóa sau 30 phút
RESEND_COOLDOWN = 60       # tối thiểu 60 giây giữa hai lần gửi mã
MAX_OTP_TRIES = 5          # nhập sai 5 lần thì khóa mã, phải xin mã mới
MAX_SENDS = 5              # tối đa 5 lần gửi mã cho một lần đăng ký
SEND_LIMIT = 8             # tối đa 8 yêu cầu gửi mã / IP / 15 phút (chống spam email)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------- mật khẩu ----------
def hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_pw(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:  # noqa: BLE001
        return False


DUMMY_HASH = hash_pw("dummy-password-for-timing")  # chống dò tên đăng nhập qua thời gian phản hồi


# ---------- phiên ----------
def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(c, user_id: int, response: Response):
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    c.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    c.execute(
        "INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        (_th(token), user_id, now, now + SESSION_SECONDS),
    )
    response.set_cookie(
        COOKIE, token, max_age=SESSION_SECONDS, httponly=True, samesite="strict", secure=SECURE_COOKIE, path="/"
    )


def user_from_request(request: Request):
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    r = db.one(
        "SELECT u.id,u.email,u.name,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND s.expires_at>?",
        (_th(token), int(time.time())),
    )
    return r


def current_user(request: Request):
    u = user_from_request(request)
    if not u:
        raise HTTPException(401, "Chưa đăng nhập")
    return u


def require_admin(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Bạn không có quyền thực hiện thao tác này")
    return u


def seed_admin():
    """Tạo (hoặc nâng quyền) tài khoản admin từ biến môi trường LANTERN_ADMIN_* khi khởi động.
    Chỉ chạy nếu có đủ LANTERN_ADMIN_USERNAME và LANTERN_ADMIN_PASSWORD. Không đổi mật khẩu của tài khoản đã tồn tại."""
    username = os.getenv("LANTERN_ADMIN_USERNAME", "").strip().lower()
    pw = os.getenv("LANTERN_ADMIN_PASSWORD", "")
    if not username or not pw:
        return
    email = os.getenv("LANTERN_ADMIN_EMAIL", "").strip().lower() or f"{username}@lantern.local"
    name = os.getenv("LANTERN_ADMIN_NAME", "").strip() or "Administrator"
    if not USERNAME_RE.match(username) or not (8 <= len(pw) <= 128) or not EMAIL_RE.match(email) or len(name) > 80:
        print("[Lantern] Bỏ qua LANTERN_ADMIN_*: username (3-30 ký tự a-z0-9_.), mật khẩu (>=8) hoặc email không hợp lệ.", flush=True)
        return
    with db.conn() as c:
        row = c.execute("SELECT id,role FROM users WHERE username=?", (username,)).fetchone()
        if row:
            if row["role"] != "admin":
                c.execute("UPDATE users SET role='admin' WHERE id=?", (row["id"],))
                print(f"[Lantern] Đã nâng '{username}' lên admin.", flush=True)
            return
        if c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            print(f"[Lantern] Bỏ qua LANTERN_ADMIN_*: email {email} đã thuộc tài khoản khác.", flush=True)
            return
        is_first = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        cur = c.execute(
            "INSERT INTO users(email,name,username,role,pw_hash,created_at) VALUES(?,?,?,'admin',?,?)",
            (email, name, username, hash_pw(pw), int(time.time())),
        )
        if is_first:
            c.execute("UPDATE assets SET user_id=? WHERE user_id IS NULL", (cur.lastrowid,))
        print(f"[Lantern] Đã tạo tài khoản admin '{username}'. Nên xóa LANTERN_ADMIN_PASSWORD khỏi .env sau lần chạy đầu.", flush=True)


# ---------- schema ----------
class RegisterIn(BaseModel):
    username: str
    name: str
    email: str
    password: str


class VerifyIn(BaseModel):
    otp: str


class ForgotIn(BaseModel):
    email: str


class ResetIn(BaseModel):
    otp: str
    password: str


class LoginIn(BaseModel):
    username: str
    password: str


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _client_key(request: Request, username: str) -> str:
    return f"{username}|{_client_ip(request)}"


# ---------- OTP / đăng ký chờ xác thực ----------
def _new_otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def _otp_hash(token: str, code: str) -> str:
    # Gắn mã với token của phiên đăng ký, nên mã chỉ dùng được trên đúng trình duyệt đã đăng ký
    return hashlib.sha256(f"{token}:{code}".encode()).hexdigest()


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


def _rate_limit_sends(c, request: Request, now: int):
    key = f"otp|{_client_ip(request)}"
    c.execute("DELETE FROM login_fails WHERE t < ?", (now - FAIL_WINDOW,))
    n = c.execute("SELECT COUNT(*) FROM login_fails WHERE key=?", (key,)).fetchone()[0]
    if n >= SEND_LIMIT:
        raise HTTPException(429, "Bạn yêu cầu gửi mã quá nhiều lần. Vui lòng thử lại sau 15 phút.")
    c.execute("INSERT INTO login_fails(key,t) VALUES(?,?)", (key, now))


def _pending_row(request: Request):
    token = request.cookies.get(PENDING_COOKIE)
    if not token:
        return None, None
    return token, db.one(
        "SELECT * FROM pending_signups WHERE token_hash=? AND created_at>?",
        (_th(token), int(time.time()) - PENDING_TTL),
    )


def pending_from_request(request: Request):
    return _pending_row(request)[1]


def _deliver_otp(email: str, name: str, code: str):
    try:
        mailer.send_otp(email, name, code, OTP_TTL // 60)
    except mailer.MailError:
        raise HTTPException(502, "Không gửi được email xác thực. Vui lòng thử lại sau ít phút.")


# ---------- route ----------
@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response):
    """Bước 1: kiểm tra thông tin, lưu đăng ký ở trạng thái chờ và gửi OTP tới email.
    Tài khoản CHƯA được tạo cho tới khi xác thực OTP ở /auth/verify."""
    username = body.username.strip().lower()
    name = body.name.strip()
    email = body.email.strip().lower()
    pw = body.password
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "Tên đăng nhập gồm 3–30 ký tự: chữ cái, số, dấu _ hoặc .")
    if not (1 <= len(name) <= 80) or any(ch in name for ch in "\r\n"):
        raise HTTPException(400, "Họ tên không hợp lệ (1–80 ký tự)")
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise HTTPException(400, "Email không hợp lệ")
    if not (8 <= len(pw) <= 128):
        raise HTTPException(400, "Mật khẩu phải từ 8 đến 128 ký tự")
    if pw.lower() in (email, username) or pw.isdigit():
        raise HTTPException(400, "Mật khẩu quá dễ đoán")

    now = int(time.time())
    token = secrets.token_urlsafe(32)
    code = _new_otp()
    pw_hash = hash_pw(pw)  # băm trước khi mở transaction để không giữ khóa DB lâu
    with db.conn() as c:
        c.execute("DELETE FROM pending_signups WHERE created_at < ?", (now - PENDING_TTL,))
        if c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "Email này đã được đăng ký")
        if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(409, "Tên đăng nhập này đã được sử dụng")
        if c.execute("SELECT 1 FROM pending_signups WHERE username=? AND email<>?", (username, email)).fetchone():
            raise HTTPException(409, "Tên đăng nhập này đã được sử dụng")
        _rate_limit_sends(c, request, now)
        old = c.execute("SELECT last_sent FROM pending_signups WHERE email=?", (email,)).fetchone()
        if old and now - old["last_sent"] < RESEND_COOLDOWN:
            wait = RESEND_COOLDOWN - (now - old["last_sent"])
            raise HTTPException(429, f"Email này vừa được gửi mã. Vui lòng đợi {wait} giây rồi thử lại.")
        # Bỏ đăng ký chờ cũ của chính trình duyệt này (nếu người dùng quay lại sửa thông tin)
        prev = request.cookies.get(PENDING_COOKIE)
        if prev:
            c.execute("DELETE FROM pending_signups WHERE token_hash=?", (_th(prev),))
        c.execute("DELETE FROM pending_signups WHERE email=?", (email,))
        c.execute(
            "INSERT INTO pending_signups(token_hash,email,username,name,pw_hash,otp_hash,otp_expires,"
            "attempts,sends,last_sent,created_at) VALUES(?,?,?,?,?,?,?,0,1,?,?)",
            (_th(token), email, username, name, pw_hash, _otp_hash(token, code), now + OTP_TTL, now, now),
        )
    try:
        _deliver_otp(email, name, code)
    except HTTPException:
        with db.conn() as c:
            c.execute("DELETE FROM pending_signups WHERE token_hash=?", (_th(token),))
        raise
    response.set_cookie(
        PENDING_COOKIE, token, max_age=PENDING_TTL, httponly=True, samesite="strict", secure=SECURE_COOKIE, path="/"
    )
    return {"pending": True, "email": _mask_email(email)}


@router.get("/pending")
def pending(request: Request):
    """Trạng thái đăng ký đang chờ OTP (trang /verify dùng để hiển thị email và đồng hồ gửi lại)."""
    row = pending_from_request(request)
    if not row:
        raise HTTPException(404, "Không có đăng ký nào đang chờ xác thực")
    now = int(time.time())
    return {
        "email": _mask_email(row["email"]),
        "resend_in": max(0, RESEND_COOLDOWN - (now - row["last_sent"])) if row["sends"] < MAX_SENDS else -1,
        "expires_in": max(0, row["otp_expires"] - now),
    }


@router.post("/verify")
def verify(body: VerifyIn, request: Request, response: Response):
    """Bước 2: nhập đúng OTP thì tạo tài khoản. Người dùng được đưa về trang đăng nhập để tự đăng nhập."""
    code = body.otp.strip()
    if not (len(code) == 6 and code.isdigit()):
        raise HTTPException(400, "Mã OTP gồm 6 chữ số")
    token = request.cookies.get(PENDING_COOKIE)
    now = int(time.time())
    if not token:
        raise HTTPException(410, "Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại.")
    with db.conn() as c:
        row = c.execute(
            "SELECT * FROM pending_signups WHERE token_hash=? AND created_at>?", (_th(token), now - PENDING_TTL)
        ).fetchone()
        if not row:
            raise HTTPException(410, "Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại.")
        if row["attempts"] >= MAX_OTP_TRIES:
            raise HTTPException(429, "Bạn đã nhập sai quá nhiều lần. Hãy bấm “Gửi lại mã” để nhận mã mới.")
        if row["otp_expires"] < now:
            raise HTTPException(400, "Mã OTP đã hết hạn. Hãy bấm “Gửi lại mã” để nhận mã mới.")
        if not hmac.compare_digest(_otp_hash(token, code), row["otp_hash"]):
            left = MAX_OTP_TRIES - row["attempts"] - 1
            c.execute("UPDATE pending_signups SET attempts=attempts+1 WHERE token_hash=?", (_th(token),))
            c.commit()  # phải lưu số lần sai trước khi báo lỗi
            if left <= 0:
                raise HTTPException(429, "Bạn đã nhập sai quá nhiều lần. Hãy bấm “Gửi lại mã” để nhận mã mới.")
            raise HTTPException(400, f"Mã OTP không đúng. Bạn còn {left} lần thử.")
        # Mã đúng -> tạo tài khoản thật
        is_first = c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        try:
            cur = c.execute(
                "INSERT INTO users(email,name,username,role,pw_hash,created_at) VALUES(?,?,?,?,?,?)",
                (row["email"], row["name"], row["username"], "admin" if is_first else "user", row["pw_hash"], now),
            )
        except sqlite3.IntegrityError:
            # Có người khác chiếm email/username trong lúc chờ
            c.execute("DELETE FROM pending_signups WHERE token_hash=?", (_th(token),))
            c.commit()
            raise HTTPException(409, "Email hoặc tên đăng nhập đã được dùng. Vui lòng đăng ký lại.")
        uid = cur.lastrowid
        if is_first:
            # Tài khoản đầu tiên nhận lại các tài sản có từ trước khi có đăng nhập
            c.execute("UPDATE assets SET user_id=? WHERE user_id IS NULL", (uid,))
        c.execute("DELETE FROM pending_signups WHERE token_hash=?", (_th(token),))
    response.delete_cookie(PENDING_COOKIE, path="/")
    return {"ok": True, "username": row["username"]}


@router.post("/resend")
def resend(request: Request):
    token, row = _pending_row(request)
    if not row:
        raise HTTPException(410, "Phiên đăng ký đã hết hạn. Vui lòng đăng ký lại.")
    now = int(time.time())
    if row["sends"] >= MAX_SENDS:
        raise HTTPException(429, "Đã gửi mã quá số lần cho phép. Vui lòng đăng ký lại sau.")
    wait = RESEND_COOLDOWN - (now - row["last_sent"])
    if wait > 0:
        raise HTTPException(429, f"Vui lòng đợi {wait} giây trước khi gửi lại mã.")
    code = _new_otp()
    with db.conn() as c:
        _rate_limit_sends(c, request, now)
        c.execute(
            "UPDATE pending_signups SET otp_hash=?, otp_expires=?, attempts=0, sends=sends+1, last_sent=? "
            "WHERE token_hash=?",
            (_otp_hash(token, code), now + OTP_TTL, now, _th(token)),
        )
    _deliver_otp(row["email"], row["name"], code)
    return {"resend_in": RESEND_COOLDOWN, "left": MAX_SENDS - row["sends"] - 1}


# ---------- quên mật khẩu ----------
def _send_reset_mail(email: str, name: str, code: str):
    """Chạy nền: gửi mail không làm chậm phản hồi, nên thời gian phản hồi không lộ email có tồn tại hay không."""
    try:
        mailer.send_otp(email, name, code, OTP_TTL // 60, "reset")
    except mailer.MailError:
        pass  # đã ghi log trong mailer; không báo lỗi ra ngoài để không lộ thông tin


def _reset_row(request: Request):
    token = request.cookies.get(RESET_COOKIE)
    if not token:
        return None, None
    return token, db.one(
        "SELECT * FROM password_resets WHERE token_hash=? AND created_at>?",
        (_th(token), int(time.time()) - PENDING_TTL),
    )


def reset_cookie_present(request: Request) -> bool:
    return bool(request.cookies.get(RESET_COOKIE))


def _set_reset_cookie(response: Response, token: str):
    response.set_cookie(
        RESET_COOKIE, token, max_age=PENDING_TTL, httponly=True, samesite="strict", secure=SECURE_COOKIE, path="/"
    )


@router.post("/forgot")
def forgot(body: ForgotIn, request: Request, response: Response, bg: BackgroundTasks):
    """Bước 1: nhận email, gửi OTP nếu email có tài khoản.

    CẢNH BÁO BẢO MẬT: endpoint này báo rõ 404 "Email không tồn tại" khi email chưa đăng ký,
    theo yêu cầu của chủ dự án. Khác với hành vi mặc định ban đầu (trả lời giống hệt dù email
    có tồn tại hay không), cách làm này để lộ cho người ngoài biết EMAIL NÀO ĐÃ ĐĂNG KÝ trong
    hệ thống (user enumeration) -> kẻ tấn công dò được danh sách tài khoản thật để nhắm phishing/
    brute-force đúng người. Đã cân nhắc và chấp nhận đánh đổi này."""
    email = body.email.strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise HTTPException(400, "Email không hợp lệ")
    now = int(time.time())
    with db.conn() as c:
        c.execute("DELETE FROM password_resets WHERE created_at < ?", (now - PENDING_TTL,))
        # Rate-limit theo IP TRƯỚC khi kiểm tra tồn tại, để không bị dùng làm công cụ dò email
        # hàng loạt không giới hạn (dù giờ có báo tồn tại hay không, vẫn phải giới hạn tốc độ thử).
        _rate_limit_sends(c, request, now)
        user = c.execute("SELECT name FROM users WHERE email=?", (email,)).fetchone()
        if not user:
            raise HTTPException(404, "Email không tồn tại trong hệ thống.")
        mail_job = None
        cur = request.cookies.get(RESET_COOKIE)
        old = c.execute("SELECT * FROM password_resets WHERE email=?", (email,)).fetchone()
        cooling = bool(old) and now - old["last_sent"] < RESEND_COOLDOWN
        if cooling and cur and hmac.compare_digest(old["token_hash"], _th(cur)):
            token = cur  # cùng trình duyệt bấm lại quá nhanh: giữ nguyên mã đang có, không gửi thêm
        else:
            token = secrets.token_urlsafe(32)
            if cooling:
                # Trình duyệt khác trong thời gian chờ: không gửi thêm mail (chống spam hộp thư)
                otp_hash, last_sent, sends = old["otp_hash"], old["last_sent"], old["sends"]
            else:
                code = _new_otp()
                otp_hash = _otp_hash(token, code)
                last_sent, sends = now, 1
                mail_job = (email, user["name"], code)
            if cur:
                c.execute("DELETE FROM password_resets WHERE token_hash=?", (_th(cur),))
            c.execute("DELETE FROM password_resets WHERE email=?", (email,))
            c.execute(
                "INSERT INTO password_resets(token_hash,email,otp_hash,otp_expires,attempts,sends,last_sent,created_at) "
                "VALUES(?,?,?,?,0,?,?,?)",
                (_th(token), email, otp_hash, now + OTP_TTL, sends, last_sent, now),
            )
    if mail_job:
        bg.add_task(_send_reset_mail, *mail_job)
    _set_reset_cookie(response, token)
    return {"email": _mask_email(email)}


@router.get("/forgot/status")
def forgot_status(request: Request):
    _, row = _reset_row(request)
    if not row:
        raise HTTPException(404, "Không có yêu cầu đặt lại mật khẩu nào đang chờ")
    now = int(time.time())
    return {
        "email": _mask_email(row["email"]),
        "resend_in": max(0, RESEND_COOLDOWN - (now - row["last_sent"])) if row["sends"] < MAX_SENDS else -1,
    }


@router.post("/forgot/resend")
def forgot_resend(request: Request, bg: BackgroundTasks):
    token, row = _reset_row(request)
    if not row:
        raise HTTPException(410, "Phiên đã hết hạn. Vui lòng bắt đầu lại.")
    now = int(time.time())
    if row["sends"] >= MAX_SENDS:
        raise HTTPException(429, "Đã gửi mã quá số lần cho phép. Vui lòng thử lại sau.")
    wait = RESEND_COOLDOWN - (now - row["last_sent"])
    if wait > 0:
        raise HTTPException(429, f"Vui lòng đợi {wait} giây trước khi gửi lại mã.")
    code = _new_otp()
    with db.conn() as c:
        _rate_limit_sends(c, request, now)
        user = c.execute("SELECT name FROM users WHERE email=?", (row["email"],)).fetchone()
        c.execute(
            "UPDATE password_resets SET otp_hash=?, otp_expires=?, attempts=0, sends=sends+1, last_sent=? "
            "WHERE token_hash=?",
            (_otp_hash(token, code) if user else secrets.token_hex(32), now + OTP_TTL, now, _th(token)),
        )
    if user:
        bg.add_task(_send_reset_mail, row["email"], user["name"], code)
    return {"resend_in": RESEND_COOLDOWN, "left": MAX_SENDS - row["sends"] - 1}


@router.post("/reset")
def reset_password(body: ResetIn, request: Request, response: Response):
    """Bước 2: OTP đúng thì đặt mật khẩu mới, đăng xuất mọi thiết bị. Người dùng tự đăng nhập lại."""
    code, pw = body.otp.strip(), body.password
    if not (len(code) == 6 and code.isdigit()):
        raise HTTPException(400, "Mã OTP gồm 6 chữ số")
    if not (8 <= len(pw) <= 128):
        raise HTTPException(400, "Mật khẩu phải từ 8 đến 128 ký tự")
    if pw.isdigit():
        raise HTTPException(400, "Mật khẩu quá dễ đoán")
    token = request.cookies.get(RESET_COOKIE)
    if not token:
        raise HTTPException(410, "Phiên đã hết hạn. Vui lòng bắt đầu lại.")
    now = int(time.time())
    new_hash = hash_pw(pw)  # băm trước khi mở transaction
    bad = "Mã OTP không đúng hoặc đã hết hạn."
    with db.conn() as c:
        row = c.execute(
            "SELECT * FROM password_resets WHERE token_hash=? AND created_at>?", (_th(token), now - PENDING_TTL)
        ).fetchone()
        if not row:
            raise HTTPException(410, "Phiên đã hết hạn. Vui lòng bắt đầu lại.")
        if pw.lower() == row["email"]:
            raise HTTPException(400, "Mật khẩu quá dễ đoán")
        if row["attempts"] >= MAX_OTP_TRIES:
            raise HTTPException(429, "Bạn đã nhập sai quá nhiều lần. Hãy bấm “Gửi lại mã” để nhận mã mới.")
        if row["otp_expires"] < now:
            raise HTTPException(400, "Mã OTP đã hết hạn. Hãy bấm “Gửi lại mã” để nhận mã mới.")
        if not hmac.compare_digest(_otp_hash(token, code), row["otp_hash"]):
            left = MAX_OTP_TRIES - row["attempts"] - 1
            c.execute("UPDATE password_resets SET attempts=attempts+1 WHERE token_hash=?", (_th(token),))
            c.commit()
            if left <= 0:
                raise HTTPException(429, "Bạn đã nhập sai quá nhiều lần. Hãy bấm “Gửi lại mã” để nhận mã mới.")
            raise HTTPException(400, f"{bad} Bạn còn {left} lần thử.")
        user = c.execute("SELECT id,username FROM users WHERE email=?", (row["email"],)).fetchone()
        if not user:
            c.execute("DELETE FROM password_resets WHERE token_hash=?", (_th(token),))
            c.commit()
            raise HTTPException(400, bad)
        if pw.lower() == user["username"]:
            raise HTTPException(400, "Mật khẩu quá dễ đoán")  # chưa tiêu hao mã, người dùng nhập lại được
        c.execute("UPDATE users SET pw_hash=? WHERE id=?", (new_hash, user["id"]))
        c.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))  # đăng xuất mọi thiết bị
        c.execute("DELETE FROM password_resets WHERE email=?", (row["email"],))
        # Mở khóa đăng nhập (đang bị khóa vì sai nhiều lần) cho tài khoản này
        prefix = user["username"] + "|"
        c.execute("DELETE FROM login_fails WHERE substr(key,1,?)=?", (len(prefix), prefix))
    response.delete_cookie(RESET_COOKIE, path="/")
    return {"ok": True}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response):
    username = body.username.strip().lower()
    key = _client_key(request, username)
    now = int(time.time())
    with db.conn() as c:
        c.execute("DELETE FROM login_fails WHERE t < ?", (now - FAIL_WINDOW,))
        fails = c.execute("SELECT COUNT(*) FROM login_fails WHERE key=?", (key,)).fetchone()[0]
        if fails >= MAX_FAILS:
            raise HTTPException(429, "Thử sai quá nhiều lần. Vui lòng đợi 15 phút rồi thử lại.")
        row = c.execute("SELECT id,email,name,username,role,pw_hash FROM users WHERE username=?", (username,)).fetchone()
        ok = verify_pw(body.password[:128], row["pw_hash"] if row else DUMMY_HASH) and row is not None
        if not ok:
            c.execute("INSERT INTO login_fails(key,t) VALUES(?,?)", (key, now))
            c.commit()
            raise HTTPException(401, "Tên đăng nhập hoặc mật khẩu không đúng")
        c.execute("DELETE FROM login_fails WHERE key=?", (key,))
        start_session(c, row["id"], response)
        return {"id": row["id"], "email": row["email"], "name": row["name"], "username": row["username"], "role": row["role"]}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE)
    if token:
        with db.conn() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (_th(token),))
    response.delete_cookie(COOKIE, path="/")
    response.status_code = 204
    return response


@router.get("/me")
def me(user=Depends(current_user)):
    return user
