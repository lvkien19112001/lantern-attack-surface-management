"""Mã hóa thông tin đăng nhập SSH lưu trong DB (mật khẩu / private key / passphrase).

Khóa mã hóa (Fernet, AES128-CBC + HMAC) lấy từ biến môi trường LANTERN_CRED_KEY nếu có,
ngược lại tự sinh một lần và lưu vào data/cred.key (quyền 600) để tồn tại qua các lần khởi động lại.
MẤT file này (hoặc đổi LANTERN_CRED_KEY) đồng nghĩa mọi credential SSH đã lưu không giải mã lại được
-> phải nhập lại từ đầu. Nên sao lưu data/cred.key cùng với lantern.db.
"""
import os
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken  # noqa: F401  (re-exported for callers)
except ImportError:  # thư viện tùy chọn, như paramiko/nmap/subfinder: THIẾU thì chỉ tắt tính năng
    Fernet = None            # credential SSH, KHÔNG được làm sập cả server lúc import app.main

    class InvalidToken(Exception):  # noqa: N818 - giữ tên giống cryptography để except ở nơi khác không vỡ
        pass

_ROOT = Path(__file__).resolve().parent.parent
_KEY_PATH = Path(os.getenv("LANTERN_CRED_KEY_FILE", str(_ROOT / "data" / "cred.key")))


def _load_key() -> bytes:
    env_key = os.getenv("LANTERN_CRED_KEY", "").strip()
    if env_key:
        return env_key.encode()
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _KEY_PATH.exists():
        return _KEY_PATH.read_bytes().strip()
    key = Fernet.generate_key()
    _KEY_PATH.write_bytes(key)
    try:
        os.chmod(_KEY_PATH, 0o600)
    except OSError:
        pass
    return key


_fernet = Fernet(_load_key()) if Fernet is not None else None


def available() -> bool:
    return _fernet is not None


def encrypt(plaintext: str) -> str:
    if _fernet is None:
        raise RuntimeError("chưa cài thư viện cryptography (pip install cryptography)")
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    """Ném cryptography.fernet.InvalidToken nếu khóa sai hoặc dữ liệu hỏng."""
    if _fernet is None:
        raise RuntimeError("chưa cài thư viện cryptography (pip install cryptography)")
    return _fernet.decrypt(token.encode()).decode()
