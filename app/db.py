"""Lớp truy cập SQLite đơn giản."""
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

# Đường dẫn tương đối được hiểu theo thư mục dự án (không phụ thuộc thư mục đang chạy lệnh),
# để chạy ngầm từ Task Scheduler / khi khởi động máy vẫn mở đúng file DB.
_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = os.getenv("LANTERN_DB", "lantern.db")
if not os.path.isabs(DB_PATH):
    DB_PATH = str(_ROOT / DB_PATH)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  username TEXT,                   -- tên đăng nhập, luôn lưu chữ thường (xem migration bên dưới)
  role TEXT NOT NULL DEFAULT 'user',  -- admin | user
  pw_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  must_change_pw INTEGER NOT NULL DEFAULT 0  -- 1 = bắt buộc đổi mật khẩu ở lần đăng nhập kế tiếp
);
-- Đăng ký đang chờ xác thực OTP. Chỉ khi nhập đúng mã mới tạo dòng trong users.
CREATE TABLE IF NOT EXISTS pending_signups(
  token_hash TEXT PRIMARY KEY,     -- SHA-256 của token trong cookie, không lưu token thô
  email TEXT NOT NULL UNIQUE,
  username TEXT NOT NULL,
  name TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  otp_hash TEXT NOT NULL,          -- băm của mã OTP, không lưu mã thô
  otp_expires INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  sends INTEGER NOT NULL DEFAULT 1,
  last_sent INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
-- Yêu cầu đặt lại mật khẩu. Có cả dòng cho email KHÔNG tồn tại (OTP ngẫu nhiên, không gửi mail)
-- để người ngoài không dò được email nào đã đăng ký.
CREATE TABLE IF NOT EXISTS password_resets(
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  otp_hash TEXT NOT NULL,
  otp_expires INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  sends INTEGER NOT NULL DEFAULT 1,
  last_sent INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,     -- SHA-256 của token, không lưu token thô
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_fails(
  key TEXT NOT NULL,
  t INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_login_fails ON login_fails(key, t);
-- Nhóm tài sản (vd nhiều IP thêm cùng lúc). Xóa nhóm chỉ gỡ tài sản khỏi nhóm, không xóa tài sản.
CREATE TABLE IF NOT EXISTS asset_groups(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL COLLATE NOCASE,
  created REAL NOT NULL,
  UNIQUE(user_id, name)
);
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,              -- domain | ip | cidr
  created REAL NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  group_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  fkey TEXT NOT NULL,              -- khóa chống trùng, vd "port:3389", "hsts"
  title TEXT NOT NULL,
  sev TEXT NOT NULL,               -- critical | high | medium | low
  open INTEGER NOT NULL DEFAULT 1,
  created REAL NOT NULL,
  score REAL,                      -- điểm CVSS (chỉ với phát hiện CVE)
  detail TEXT,                     -- JSON: cve, port, product, version (chỉ với phát hiện CVE)
  UNIQUE(asset_id, host, fkey)
);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  target TEXT NOT NULL,
  status TEXT NOT NULL,            -- queued | running | done | failed | cancelled
  notes TEXT DEFAULT '',
  created REAL NOT NULL,
  finished REAL,
  source TEXT NOT NULL DEFAULT 'manual'   -- manual | auto (do lịch quét tự động tạo ra)
);
-- Lịch quét tự động: mỗi tài sản tối đa một lịch, quét lặp lại sau mỗi interval_h giờ.
CREATE TABLE IF NOT EXISTS schedules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL UNIQUE REFERENCES assets(id) ON DELETE CASCADE,
  interval_h INTEGER NOT NULL,
  next_run REAL NOT NULL,
  last_run REAL,
  created REAL NOT NULL,
  at_min INTEGER NOT NULL DEFAULT 0,   -- giờ chạy, tính bằng phút kể từ 00:00 (giờ địa phương của người đặt)
  weekday INTEGER NOT NULL DEFAULT 0,  -- 0=Thứ hai ... 6=Chủ nhật, chỉ dùng cho lịch hằng tuần
  tz INTEGER NOT NULL DEFAULT 0        -- độ lệch múi giờ so với UTC, phút (VN = 420)
);
CREATE TABLE IF NOT EXISTS asset_hosts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  ip TEXT NOT NULL DEFAULT '',     -- IP phân giải được ở lần quét gần nhất
  web TEXT NOT NULL DEFAULT '',    -- https | http | rỗng (không có web)
  server TEXT NOT NULL DEFAULT '', -- header Server
  UNIQUE(asset_id, host)
);
-- Mọi cổng mở nmap thấy (không chỉ cổng rủi ro). open=0 nghĩa là lần quét sau không còn thấy nữa.
CREATE TABLE IF NOT EXISTS services(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  service TEXT NOT NULL DEFAULT '',   -- giao thức nmap nhận diện: http, ssh...
  product TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  cpe TEXT NOT NULL DEFAULT '',
  first_seen REAL NOT NULL,
  last_seen REAL NOT NULL,
  open INTEGER NOT NULL DEFAULT 1,
  UNIQUE(asset_id, host, port)
);
CREATE INDEX IF NOT EXISTS ix_services_asset ON services(asset_id);
-- Cache kết quả tra CVE theo CPE (xem vulns.py) để khỏi gọi lại NVD mỗi lần quét
CREATE TABLE IF NOT EXISTS cve_cache(
  cpe TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  fetched REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,              -- new_host | host_gone
  host TEXT NOT NULL,
  created REAL NOT NULL
);
"""


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init():
    with conn() as c:
        c.executescript(SCHEMA)
        # Migration: DB cũ (trước khi có đăng nhập) chưa có cột assets.user_id.
        # Thêm cột, giữ nguyên dữ liệu. Tài sản cũ (user_id NULL) sẽ thuộc về
        # tài khoản đầu tiên đăng ký (xem auth.register).
        cols = [r["name"] for r in c.execute("PRAGMA table_info(assets)")]
        if "user_id" not in cols:
            c.execute("ALTER TABLE assets ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
        if "group_id" not in cols:
            c.execute("ALTER TABLE assets ADD COLUMN group_id INTEGER REFERENCES asset_groups(id) ON DELETE SET NULL")
        c.execute("CREATE INDEX IF NOT EXISTS ix_assets_user ON assets(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS ix_assets_group ON assets(group_id)")
        for tbl, col, typ in (("findings", "score", "REAL"), ("findings", "detail", "TEXT"),
                              ("asset_hosts", "ip", "TEXT NOT NULL DEFAULT ''"),
                              ("asset_hosts", "web", "TEXT NOT NULL DEFAULT ''"),
                              ("asset_hosts", "server", "TEXT NOT NULL DEFAULT ''")):
            if col not in [r["name"] for r in c.execute(f"PRAGMA table_info({tbl})")]:
                c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {typ}")
        # Dọn các phát hiện web cũ (khóa "web:*") còn sót lại từ phiên bản trước
        c.execute("DELETE FROM findings WHERE fkey LIKE 'web:%'")
        _migrate_username(c)
        _migrate_role(c)
        _migrate_must_change(c)
        scols = [r["name"] for r in c.execute("PRAGMA table_info(scans)")]
        kcols = [r["name"] for r in c.execute("PRAGMA table_info(schedules)")]
        for col in ("at_min", "weekday", "tz"):
            if col not in kcols:
                c.execute(f"ALTER TABLE schedules ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
        if "source" not in scols:
            c.execute("ALTER TABLE scans ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'")
        # Scan đang chạy mà server bị tắt thì đánh dấu thất bại
        c.execute("UPDATE scans SET status='failed', notes='Bị gián đoạn do khởi động lại' WHERE status IN ('running','queued')")


def _migrate_username(c):
    """DB cũ (đăng nhập bằng email) chưa có cột users.username.
    Thêm cột, tạo username từ phần trước @ của email cho tài khoản đã có (đảm bảo duy nhất),
    rồi tạo chỉ mục UNIQUE. Người dùng cũ đăng nhập bằng username này."""
    cols = [r["name"] for r in c.execute("PRAGMA table_info(users)")]
    if "username" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN username TEXT")
    taken = {r[0] for r in c.execute("SELECT username FROM users WHERE username IS NOT NULL")}
    for r in c.execute("SELECT id,email FROM users WHERE username IS NULL ORDER BY id").fetchall():
        base = re.sub(r"[^a-z0-9_.]", "", r["email"].split("@")[0].lower())[:24]
        if len(base) < 3:
            base = f"user{r['id']}"
        name, n = base, 1
        while name in taken:
            n += 1
            name = f"{base}{n}"
        taken.add(name)
        c.execute("UPDATE users SET username=? WHERE id=?", (name, r["id"]))
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username ON users(username)")


def _migrate_role(c):
    """DB cũ chưa có cột users.role. Thêm cột (mặc định 'user'); nếu hệ thống chưa có admin nào
    thì tài khoản tạo sớm nhất (chủ hệ thống) được nâng lên admin để không bị khóa khỏi phần quản lý."""
    cols = [r["name"] for r in c.execute("PRAGMA table_info(users)")]
    if "role" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] == 0:
        c.execute("UPDATE users SET role='admin' WHERE id=(SELECT MIN(id) FROM users)")


def _migrate_must_change(c):
    """DB cũ chưa có cột users.must_change_pw (cờ bắt buộc đổi mật khẩu)."""
    cols = [r["name"] for r in c.execute("PRAGMA table_info(users)")]
    if "must_change_pw" not in cols:
        c.execute("ALTER TABLE users ADD COLUMN must_change_pw INTEGER NOT NULL DEFAULT 0")


def rows(sql, args=()):
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args)]


def one(sql, args=()):
    r = rows(sql, args)
    return r[0] if r else None
