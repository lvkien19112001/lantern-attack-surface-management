"""Lantern - gửi email (mã OTP). Dùng SMTP chuẩn, không cần thư viện ngoài.

Cấu hình trong .env (xem .env.example). Nếu chưa đặt LANTERN_SMTP_HOST thì chạy chế độ
phát triển: KHÔNG gửi email thật, mã OTP được in ra cửa sổ terminal của server.
"""
import html
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

log = logging.getLogger("lantern.mail")


class MailError(Exception):
    pass


def _cfg():
    host = os.getenv("LANTERN_SMTP_HOST", "").strip()
    return {
        "host": host,
        "port": int(os.getenv("LANTERN_SMTP_PORT", "587") or 587),
        "user": os.getenv("LANTERN_SMTP_USER", "").strip(),
        "password": os.getenv("LANTERN_SMTP_PASSWORD", ""),
        "from": os.getenv("LANTERN_SMTP_FROM", "").strip() or os.getenv("LANTERN_SMTP_USER", "").strip(),
        # starttls (cổng 587) | ssl (cổng 465) | none
        "security": os.getenv("LANTERN_SMTP_SECURITY", "starttls").strip().lower(),
    }


def build_otp_message(to: str, name: str, code: str, minutes: int, sender: str, purpose: str = "register") -> EmailMessage:
    reset = purpose == "reset"
    what = "Mã đặt lại mật khẩu của bạn là" if reset else "Mã xác thực email của bạn là"
    ignore = ("Nếu bạn không yêu cầu đặt lại mật khẩu, hãy bỏ qua email này, mật khẩu của bạn vẫn an toàn."
              if reset else "Nếu bạn không đăng ký tài khoản Lantern, hãy bỏ qua email này.")
    msg = EmailMessage()
    msg["Subject"] = f"{'Mã đặt lại mật khẩu' if reset else 'Mã xác thực'} Lantern: {code}"
    msg["From"] = formataddr(("Lantern", sender))
    msg["To"] = to
    # Ký tự xuống dòng trong tên đã bị chặn ở auth.py, và ở đây tên chỉ nằm trong phần thân thư.
    msg.set_content(
        f"Xin chào {name},\n\n"
        f"{what}: {code}\n"
        f"Mã có hiệu lực trong {minutes} phút. Không chia sẻ mã này với bất kỳ ai.\n\n"
        f"{ignore}"
    )
    n, c = html.escape(name), html.escape(code)
    msg.add_alternative(
        f"""<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#12263a">
<h2 style="margin:0 0 12px">Lantern</h2>
<p>Xin chào {n},</p>
<p>{what}:</p>
<p style="font-size:32px;font-weight:700;letter-spacing:8px;margin:16px 0;color:#0f766e">{c}</p>
<p>Mã có hiệu lực trong {minutes} phút. Không chia sẻ mã này với bất kỳ ai.</p>
<p style="color:#5c7084;font-size:13px">{ignore}</p>
</div>""",
        subtype="html",
    )
    return msg


def send_otp(to: str, name: str, code: str, minutes: int, purpose: str = "register") -> None:
    cfg = _cfg()
    if not cfg["host"]:
        # Chế độ phát triển: không có SMTP -> in mã ra terminal
        print(f"\n[Lantern DEV] Chưa cấu hình SMTP. Mã OTP ({purpose}) cho {to}: {code}\n", flush=True)
        return
    if not cfg["from"]:
        raise MailError("Thiếu LANTERN_SMTP_FROM (hoặc LANTERN_SMTP_USER)")
    msg = build_otp_message(to, name, code, minutes, cfg["from"], purpose)
    try:
        if cfg["security"] == "ssl":
            s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15, context=ssl.create_default_context())
        else:
            s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=15)
        with s:
            if cfg["security"] == "starttls":
                s.starttls(context=ssl.create_default_context())
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        log.error("Gửi email OTP thất bại: %s", e)
        raise MailError(str(e)) from e
