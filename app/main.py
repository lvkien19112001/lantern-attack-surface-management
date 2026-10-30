"""Lantern ASM - API chính."""
import asyncio
import json
import re
import sqlite3
import sys
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request  # noqa: E402
from fastapi.responses import FileResponse, RedirectResponse, Response  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from . import admin, auth, crypto, db, reports, scanner, sshscan  # noqa: E402
from .auth import current_user  # noqa: E402


@asynccontextmanager
async def lifespan(_):
    db.init()
    auth.seed_admin()
    task = asyncio.create_task(_scheduler())
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="Lantern ASM", version="0.2.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)

# /api/auth/* (đăng ký, xác thực OTP, quên mật khẩu, đăng nhập, đăng xuất, me) là công khai; mọi route còn lại dưới /api cần đăng nhập
app.include_router(auth.router, prefix="/api")
app.include_router(admin.router)  # /api/admin/*: chỉ role admin
router = APIRouter(prefix="/api", dependencies=[Depends(current_user)])


class AssetIn(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    authorized: bool = False


class BulkAssetIn(BaseModel):
    targets: str = Field(min_length=3, max_length=20000)   # nhiều mục, cách nhau bằng xuống dòng, dấu phẩy hoặc khoảng trắng
    group: str = Field(default="", max_length=60)
    authorized: bool = False


class ScanIn(BaseModel):
    asset_id: int


class SshCredIn(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    port: int = Field(default=22, ge=1, le=65535)
    auth_type: str = Field(pattern="^(password|key)$")
    secret: str = Field(min_length=1, max_length=20000)   # mật khẩu, hoặc nội dung private key PEM
    passphrase: str = Field(default="", max_length=500)   # chỉ dùng khi auth_type=key và key có mã hóa


class FindingPatch(BaseModel):
    open: bool


class IdsIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=5000)


class FindingBulkPatch(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=2000)
    open: bool


INTERVALS = (1, 6, 12, 24, 168)   # giờ: mỗi giờ, 6h, 12h, hằng ngày, hằng tuần


class ScheduleIn(BaseModel):
    interval_h: int
    at: str = "00:00"      # HH:MM theo giờ địa phương của người đặt
    weekday: int = 0       # 0=Thứ hai ... 6=Chủ nhật (chỉ dùng khi interval_h = 168)
    tz: int = 0            # phút lệch so với UTC (VN = 420)


def _next_run(interval_h, at_min, weekday, tz, now):
    """Mốc chạy kế tiếp (epoch, luôn > now) bám theo giờ:phút người dùng chọn.
    Các mốc xếp đều theo chu kỳ trong giờ địa phương: 1/6/12 giờ lặp từ giờ:phút đó (vd 08:30, 14:30, 20:30, 02:30),
    hằng ngày là giờ:phút đó mỗi ngày, hằng tuần là thứ + giờ:phút đó. Không phụ thuộc múi giờ của server."""
    period = interval_h * 3600
    offset = at_min * 60
    if interval_h == 168:
        offset += ((weekday - 3) % 7) * 86400    # 01/01/1970 là thứ Năm (=3 nếu thứ Hai=0)
    local = now + tz * 60
    offset %= period
    t = local - ((local - offset) % period) + period
    return t - tz * 60


def _ms(ts):
    return int(ts * 1000) if ts else None


@app.get("/api/health")
def health():
    return {"ok": True}


@router.get("/assets")
def list_assets(u: dict = Depends(current_user)):
    return [{"id": r["id"], "name": r["name"], "kind": r["kind"], "t": _ms(r["created"]),
             "gid": r["group_id"], "ss": r["ss"], "sf": _ms(r["sf"])}
            for r in db.rows(
                "SELECT a.*, "
                "(SELECT status FROM scans s WHERE s.asset_id=a.id ORDER BY s.created DESC, s.id DESC LIMIT 1) AS ss, "
                "(SELECT finished FROM scans s WHERE s.asset_id=a.id ORDER BY s.created DESC, s.id DESC LIMIT 1) AS sf "
                "FROM assets a WHERE a.user_id=? ORDER BY a.created DESC", (u["id"],))]


@router.post("/assets", status_code=201)
def add_asset(body: AssetIn, u: dict = Depends(current_user)):
    if not body.authorized:
        raise HTTPException(400, "Bạn phải xác nhận sở hữu hoặc được phép kiểm tra tài sản này.")
    try:
        kind, value = scanner.parse_target(body.name)
    except ValueError as e:
        raise HTTPException(422, str(e))
    try:
        with db.conn() as c:
            cur = c.execute("INSERT INTO assets(name,kind,created,user_id) VALUES(?,?,?,?)",
                            (value, kind, time.time(), u["id"]))
            return {"id": cur.lastrowid, "name": value, "kind": kind, "t": _ms(time.time())}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Tài sản đã tồn tại.")


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, u: dict = Depends(current_user)):
    with db.conn() as c:
        cur = c.execute("DELETE FROM assets WHERE id=? AND user_id=?", (asset_id, u["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "Không tìm thấy tài sản.")
        c.execute("DELETE FROM asset_groups WHERE user_id=? AND id NOT IN "
                  "(SELECT group_id FROM assets WHERE group_id IS NOT NULL)", (u["id"],))


# ---------- credential SSH (quét có xác thực) ----------
def _owned_asset(asset_id, uid):
    a = db.one("SELECT * FROM assets WHERE id=? AND user_id=?", (asset_id, uid))
    if not a:
        raise HTTPException(404, "Không tìm thấy tài sản.")
    return a


@router.get("/assets/{asset_id}/ssh-credential")
def get_ssh_credential(asset_id: int, u: dict = Depends(current_user)):
    """Không bao giờ trả về secret/passphrase đã lưu, chỉ cho biết đã cấu hình hay chưa."""
    _owned_asset(asset_id, u["id"])
    r = db.one("SELECT username, port, auth_type, updated FROM ssh_credentials WHERE asset_id=?", (asset_id,))
    if not r:
        return {"configured": False}
    return {"configured": True, "username": r["username"], "port": r["port"],
            "auth_type": r["auth_type"], "t": _ms(r["updated"])}


@router.put("/assets/{asset_id}/ssh-credential", status_code=200)
def set_ssh_credential(asset_id: int, body: SshCredIn, u: dict = Depends(current_user)):
    _owned_asset(asset_id, u["id"])
    if sshscan.paramiko is None:
        raise HTTPException(503, "Máy chủ chưa cài paramiko (pip install paramiko).")
    if not crypto.available():
        raise HTTPException(503, "Máy chủ chưa cài cryptography (pip install cryptography).")
    now = time.time()
    secret_enc = crypto.encrypt(body.secret)
    pass_enc = crypto.encrypt(body.passphrase) if body.passphrase else None
    with db.conn() as c:
        c.execute(
            "INSERT INTO ssh_credentials(asset_id,port,username,auth_type,secret_enc,passphrase_enc,created,updated) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET "
            "port=excluded.port, username=excluded.username, auth_type=excluded.auth_type, "
            "secret_enc=excluded.secret_enc, passphrase_enc=excluded.passphrase_enc, updated=excluded.updated",
            (asset_id, body.port, body.username, body.auth_type, secret_enc, pass_enc, now, now))
    return {"configured": True}


@router.delete("/assets/{asset_id}/ssh-credential", status_code=204)
def delete_ssh_credential(asset_id: int, u: dict = Depends(current_user)):
    _owned_asset(asset_id, u["id"])
    with db.conn() as c:
        c.execute("DELETE FROM ssh_credentials WHERE asset_id=?", (asset_id,))


def _ssh_cred_for_scan(asset_id):
    """Giải mã credential để dùng ngay khi quét; KHÔNG bao giờ trả ra ngoài API."""
    r = db.one("SELECT * FROM ssh_credentials WHERE asset_id=?", (asset_id,))
    if not r:
        return None
    try:
        return {"username": r["username"], "port": r["port"], "auth_type": r["auth_type"],
                "secret": crypto.decrypt(r["secret_enc"]),
                "passphrase": crypto.decrypt(r["passphrase_enc"]) if r["passphrase_enc"] else ""}
    except crypto.InvalidToken:
        return None   # khóa mã hóa đã đổi/hỏng: coi như chưa cấu hình, không chặn quét mạng


MAX_BULK = 200


@router.post("/assets/bulk")
def add_assets_bulk(body: BulkAssetIn, u: dict = Depends(current_user)):
    """Thêm nhiều tài sản một lần. Có tên nhóm, hoặc thêm từ 2 mục trở lên, thì gộp vào một nhóm.
    Mục đã tồn tại và thuộc về bạn sẽ được chuyển vào nhóm (nếu có nhóm), không báo lỗi."""
    if not body.authorized:
        raise HTTPException(400, "Bạn phải xác nhận sở hữu hoặc được phép kiểm tra các tài sản này.")
    raw = list(dict.fromkeys(t for t in re.split(r"[\s,;]+", body.targets.strip()) if t))
    if not raw:
        raise HTTPException(422, "Chưa nhập tài sản nào.")
    if len(raw) > MAX_BULK:
        raise HTTPException(422, f"Tối đa {MAX_BULK} mục mỗi lần.")
    added, existing, skipped, seen = [], [], [], set()
    now = time.time()
    with db.conn() as c:
        for t in raw:
            try:
                kind, value = scanner.parse_target(t)
            except ValueError:
                skipped.append({"target": t[:60], "reason": "không đúng định dạng"})
                continue
            if value in seen:
                continue
            seen.add(value)
            try:
                cur = c.execute("INSERT INTO assets(name,kind,created,user_id) VALUES(?,?,?,?)",
                                (value, kind, now, u["id"]))
                added.append(cur.lastrowid)
            except sqlite3.IntegrityError:
                row = c.execute("SELECT id,user_id FROM assets WHERE name=?", (value,)).fetchone()
                if row and row["user_id"] == u["id"]:
                    existing.append(row["id"])
                else:
                    skipped.append({"target": value, "reason": "đã tồn tại"})
        members = added + existing
        gname = body.group.strip()
        if not gname and len(added) >= 2:
            gname = time.strftime("Nhóm %d/%m %H:%M")
        gid = None
        if gname and members:
            row = c.execute("SELECT id FROM asset_groups WHERE user_id=? AND name=?", (u["id"], gname)).fetchone()
            gid = row["id"] if row else c.execute(
                "INSERT INTO asset_groups(user_id,name,created) VALUES(?,?,?)", (u["id"], gname, now)).lastrowid
            c.executemany("UPDATE assets SET group_id=? WHERE id=?", [(gid, i) for i in members])
    return {"added": len(added), "moved": len(existing) if gid else 0, "skipped": skipped,
            "group_id": gid, "group": gname if gid else None}


# ---------- nhóm tài sản ----------
@router.get("/groups")
def list_groups(u: dict = Depends(current_user)):
    return [{"id": r["id"], "name": r["name"], "t": _ms(r["created"])}
            for r in db.rows("SELECT * FROM asset_groups WHERE user_id=? ORDER BY created DESC, id DESC", (u["id"],))]


@router.delete("/groups/{group_id}", status_code=204)
def delete_group(group_id: int, u: dict = Depends(current_user)):
    with db.conn() as c:
        c.execute("UPDATE assets SET group_id=NULL WHERE group_id=? AND user_id=?", (group_id, u["id"]))
        if c.execute("DELETE FROM asset_groups WHERE id=? AND user_id=?", (group_id, u["id"])).rowcount == 0:
            raise HTTPException(404, "Không tìm thấy nhóm.")


@router.put("/groups/{group_id}/ssh-credential")
def set_group_ssh_credential(group_id: int, body: SshCredIn, u: dict = Depends(current_user)):
    """Gán CÙNG một credential SSH cho mọi tài sản trong nhóm (vd danh sách server nội bộ
    dùng chung 1 tài khoản quét). Chỉ gán cho tài sản kind=ip hoặc cidr (domain thì không SSH được
    thẳng vào tên miền theo nghĩa quét hạ tầng, nên bỏ qua, không báo lỗi)."""
    if not db.one("SELECT id FROM asset_groups WHERE id=? AND user_id=?", (group_id, u["id"])):
        raise HTTPException(404, "Không tìm thấy nhóm.")
    if sshscan.paramiko is None:
        raise HTTPException(503, "Máy chủ chưa cài paramiko (pip install paramiko).")
    if not crypto.available():
        raise HTTPException(503, "Máy chủ chưa cài cryptography (pip install cryptography).")
    members = db.rows("SELECT id, kind FROM assets WHERE group_id=? AND user_id=? AND kind IN ('ip','cidr')",
                      (group_id, u["id"]))
    if not members:
        raise HTTPException(409, "Nhóm này không có tài sản dạng IP/dải IP nào.")
    now = time.time()
    secret_enc = crypto.encrypt(body.secret)
    pass_enc = crypto.encrypt(body.passphrase) if body.passphrase else None
    with db.conn() as c:
        for m in members:
            c.execute(
                "INSERT INTO ssh_credentials(asset_id,port,username,auth_type,secret_enc,passphrase_enc,created,updated) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET "
                "port=excluded.port, username=excluded.username, auth_type=excluded.auth_type, "
                "secret_enc=excluded.secret_enc, passphrase_enc=excluded.passphrase_enc, updated=excluded.updated",
                (m["id"], body.port, body.username, body.auth_type, secret_enc, pass_enc, now, now))
    return {"applied": len(members)}


def _finding_rows(uid):
    out = []
    for r in db.rows(
            "SELECT f.* FROM findings f JOIN assets a ON a.id=f.asset_id "
            "WHERE a.user_id=? ORDER BY f.created DESC LIMIT 2000", (uid,)):
        try:
            d = json.loads(r["detail"]) if r["detail"] else None
        except ValueError:
            d = None
        out.append({"id": r["id"], "aid": r["asset_id"], "host": r["host"], "title": r["title"],
                    "sev": r["sev"], "open": bool(r["open"]), "t": _ms(r["created"]),
                    "key": r["fkey"], "score": r["score"], "d": d})
    return out


@router.get("/findings")
def list_findings(u: dict = Depends(current_user)):
    return _finding_rows(u["id"])


def _subdomain_rows(uid):
    return [{"id": r["id"], "aid": r["asset_id"], "host": r["host"], "ip": r["ip"], "web": r["web"],
             "server": r["server"], "active": bool(r["active"]), "first": _ms(r["first_seen"]),
             "last": _ms(r["last_seen"]), "ports": r["ports"]}
            for r in db.rows(
                "SELECT h.*, (SELECT COUNT(*) FROM services s WHERE s.asset_id=h.asset_id "
                "AND s.host=h.host AND s.open=1) AS ports "
                "FROM asset_hosts h JOIN assets a ON a.id=h.asset_id WHERE a.user_id=? "
                "ORDER BY h.active DESC, h.host LIMIT 5000", (uid,))]


@router.get("/subdomains")
def list_subdomains(u: dict = Depends(current_user)):
    return _subdomain_rows(u["id"])


@router.post("/subdomains/delete")
def delete_subdomains(body: IdsIn, u: dict = Depends(current_user)):
    """Xóa các subdomain/host đã chọn (chỉ của user) cùng cổng và phát hiện của chính host đó.
    Lần quét sau nếu host vẫn tồn tại thì sẽ được phát hiện lại."""
    ids = list(dict.fromkeys(body.ids))
    marks = ",".join("?" * len(ids))
    with db.conn() as c:
        rows = c.execute(
            f"SELECT h.id, h.asset_id, h.host FROM asset_hosts h JOIN assets a ON a.id=h.asset_id "
            f"WHERE a.user_id=? AND h.id IN ({marks})", (u["id"], *ids)).fetchall()
        for r in rows:
            c.execute("DELETE FROM services WHERE asset_id=? AND host=?", (r["asset_id"], r["host"]))
            c.execute("DELETE FROM findings WHERE asset_id=? AND host=?", (r["asset_id"], r["host"]))
            c.execute("DELETE FROM asset_hosts WHERE id=?", (r["id"],))
    return {"deleted": len(rows)}


@router.post("/ports/delete")
def delete_ports(body: IdsIn, u: dict = Depends(current_user)):
    """Xóa các cổng đã chọn (chỉ của user) cùng phát hiện gắn với cổng đó (cổng rủi ro, CVE theo phiên bản)."""
    ids = list(dict.fromkeys(body.ids))
    marks = ",".join("?" * len(ids))
    with db.conn() as c:
        rows = c.execute(
            f"SELECT s.id, s.asset_id, s.host, s.port FROM services s JOIN assets a ON a.id=s.asset_id "
            f"WHERE a.user_id=? AND s.id IN ({marks})", (u["id"], *ids)).fetchall()
        for r in rows:
            c.execute("DELETE FROM findings WHERE asset_id=? AND host=? AND (fkey=? OR fkey LIKE ?)",
                      (r["asset_id"], r["host"], f"port:{r['port']}", f"cve:{r['port']}:%"))
            c.execute("DELETE FROM services WHERE id=?", (r["id"],))
    return {"deleted": len(rows)}


def _port_rows(uid):
    out = []
    for r in db.rows(
            "SELECT s.* FROM services s JOIN assets a ON a.id=s.asset_id WHERE a.user_id=? "
            "ORDER BY s.open DESC, s.host, s.port LIMIT 5000", (uid,)):
        risky = scanner.RISKY.get(r["port"])
        out.append({"id": r["id"], "aid": r["asset_id"], "host": r["host"], "port": r["port"],
                    "service": r["service"], "product": r["product"], "version": r["version"],
                    "open": bool(r["open"]), "first": _ms(r["first_seen"]), "last": _ms(r["last_seen"]),
                    "risk": {"name": risky[0], "sev": risky[1]} if risky else None})
    return out


@router.get("/ports")
def list_ports(u: dict = Depends(current_user)):
    return _port_rows(u["id"])


@router.patch("/findings/{finding_id}")
def patch_finding(finding_id: int, body: FindingPatch, u: dict = Depends(current_user)):
    with db.conn() as c:
        cur = c.execute(
            "UPDATE findings SET open=? WHERE id=? "
            "AND asset_id IN (SELECT id FROM assets WHERE user_id=?)",
            (int(body.open), finding_id, u["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "Không tìm thấy phát hiện.")
    return {"id": finding_id, "open": body.open}


@router.post("/findings/bulk")
def bulk_patch_findings(body: FindingBulkPatch, u: dict = Depends(current_user)):
    """Đổi trạng thái nhiều phát hiện cùng lúc (chỉ những phát hiện thuộc tài sản của user)."""
    ids = list(dict.fromkeys(body.ids))
    marks = ",".join("?" * len(ids))
    with db.conn() as c:
        cur = c.execute(
            f"UPDATE findings SET open=? WHERE id IN ({marks}) "
            "AND asset_id IN (SELECT id FROM assets WHERE user_id=?)",
            (int(body.open), *ids, u["id"]))
    return {"updated": cur.rowcount, "open": body.open}


@router.get("/events")
def list_events(u: dict = Depends(current_user)):
    rows = db.rows(
        "SELECT e.*, a.name AS asset_name FROM events e "
        "JOIN assets a ON a.id=e.asset_id WHERE a.user_id=? "
        "ORDER BY e.created DESC LIMIT 300", (u["id"],))
    return [{"id": r["id"], "aid": r["asset_id"], "asset": r["asset_name"],
             "kind": r["kind"], "host": r["host"], "t": _ms(r["created"])} for r in rows]


@router.get("/scans")
def list_scans(u: dict = Depends(current_user)):
    return [{"id": r["id"], "aid": r["asset_id"], "target": r["target"], "status": r["status"],
             "notes": r["notes"], "src": r["source"], "t": _ms(r["created"])}
            for r in db.rows(
                "SELECT s.* FROM scans s JOIN assets a ON a.id=s.asset_id "
                "WHERE a.user_id=? ORDER BY s.created DESC LIMIT 50", (u["id"],))]


def _diff_hosts(c, asset_id, hosts, now):
    """So với lần quét trước: host mới -> sự kiện new_host, host biến mất -> host_gone.
    Lần quét đầu tiên của một tài sản chỉ tạo đường cơ sở (baseline), không báo gì cả,
    vì nếu không thì mọi host sẽ bị coi là "mới" ngay lần quét đầu."""
    existing = {r["host"]: r for r in c.execute(
        "SELECT * FROM asset_hosts WHERE asset_id=?", (asset_id,))}
    is_first_scan = len(existing) == 0
    current = set(hosts)
    for h in current:
        if h in existing:
            c.execute("UPDATE asset_hosts SET last_seen=?, active=1 WHERE asset_id=? AND host=?",
                      (now, asset_id, h))
        else:
            c.execute("INSERT INTO asset_hosts(asset_id,host,first_seen,last_seen,active) VALUES(?,?,?,?,1)",
                      (asset_id, h, now, now))
            if not is_first_scan:
                c.execute("INSERT INTO events(asset_id,kind,host,created) VALUES(?,'new_host',?,?)",
                          (asset_id, h, now))
    for h, row in existing.items():
        if h not in current and row["active"]:
            c.execute("UPDATE asset_hosts SET active=0 WHERE id=?", (row["id"],))
            if not is_first_scan:
                c.execute("INSERT INTO events(asset_id,kind,host,created) VALUES(?,'host_gone',?,?)",
                          (asset_id, h, now))


def _save_hostinfo(c, asset_id, hostinfo):
    for h, i in hostinfo.items():
        c.execute("UPDATE asset_hosts SET ip=?, web=?, server=? WHERE asset_id=? AND host=?",
                  (i.get("ip", ""), i.get("web", ""), i.get("server", ""), asset_id, h))


def _save_services(c, asset_id, extra, now):
    """Lưu mọi cổng mở. Cổng mới mở / cổng không còn thấy nữa -> sự kiện (trừ lần quét cổng đầu tiên
    của tài sản, chỉ tạo đường cơ sở). Nếu nmap không chạy được thì không đụng gì, tránh coi cổng là đã đóng."""
    if not extra.get("ports_ok"):
        return
    existing = {(r["host"], r["port"]): r for r in c.execute("SELECT * FROM services WHERE asset_id=?", (asset_id,))}
    baseline = not existing
    seen = set()
    for sv in extra["services"]:
        key = (sv["host"], sv["port"])
        seen.add(key)
        r = existing.get(key)
        if r is None:
            c.execute("INSERT INTO services(asset_id,host,port,service,product,version,cpe,first_seen,last_seen,open) "
                      "VALUES(?,?,?,?,?,?,?,?,?,1)",
                      (asset_id, sv["host"], sv["port"], sv["service"], sv["product"], sv["version"], sv["cpe"], now, now))
            if not baseline:
                c.execute("INSERT INTO events(asset_id,kind,host,created) VALUES(?,'new_port',?,?)",
                          (asset_id, f"{sv['host']}:{sv['port']}", now))
        else:
            c.execute("UPDATE services SET service=?, product=?, version=?, cpe=?, last_seen=?, open=1 WHERE id=?",
                      (sv["service"], sv["product"], sv["version"], sv["cpe"], now, r["id"]))
            if not r["open"]:
                c.execute("INSERT INTO events(asset_id,kind,host,created) VALUES(?,'new_port',?,?)",
                          (asset_id, f"{sv['host']}:{sv['port']}", now))
    scanned = set(extra.get("port_hosts", []))
    for key, r in existing.items():
        if key not in seen and r["open"] and r["host"] in scanned:
            c.execute("UPDATE services SET open=0 WHERE id=?", (r["id"],))
            c.execute("INSERT INTO events(asset_id,kind,host,created) VALUES(?,'port_closed',?,?)",
                      (asset_id, f"{r['host']}:{r['port']}", now))


# scan_id -> threading.Event; bật lên khi người dùng bấm "Dừng quét"
_CANCEL = {}


def _cancel_event(scan_id):
    return _CANCEL.setdefault(scan_id, threading.Event())


def _mark_cancelled(scan_id):
    with db.conn() as c:
        c.execute("UPDATE scans SET status='cancelled', notes='Đã dừng bởi người dùng', finished=? "
                  "WHERE id=? AND status IN ('queued','running')", (time.time(), scan_id))


def _run_scan(scan_id, asset_id, kind, name):
    cancel = _cancel_event(scan_id)
    try:
        findings, hosts, notes, extra = scanner.scan_asset(kind, name, cancel)
        scanner._check(cancel)      # bấm dừng đúng lúc vừa quét xong: bỏ kết quả
        cred = _ssh_cred_for_scan(asset_id)
        if cred is not None:
            ssh_notes = []
            try:
                ssh_findings, ssh_hostinfo = sshscan.auth_scan(kind, name, cred, ssh_notes, cancel)
                findings += ssh_findings
                for h, info in ssh_hostinfo.items():
                    extra["hostinfo"].setdefault(h, {"ip": "", "web": "", "server": ""})
                    extra["hostinfo"][h]["os"] = info.get("os", "")
                    extra["hostinfo"][h]["kernel"] = info.get("kernel", "")
                    if h not in hosts:
                        hosts.append(h)
            except scanner.ScanCancelled:
                raise
            except Exception as e:  # noqa: BLE001  - lỗi SSH không được làm hỏng kết quả quét mạng đã có
                ssh_notes.append(f"SSH-auth lỗi: {str(e)[:200]}")
            if ssh_notes:
                notes = (notes + "; " if notes else "") + "; ".join(ssh_notes)
        scanner._check(cancel)
        now = time.time()
        with db.conn() as c:
            for f in findings:
                # Nếu lỗi cũ vẫn còn thì mở lại, không tạo bản trùng
                c.execute(
                    "INSERT INTO findings(asset_id,host,fkey,title,sev,open,created,score,detail) VALUES(?,?,?,?,?,1,?,?,?) "
                    "ON CONFLICT(asset_id,host,fkey) DO UPDATE SET open=1, title=excluded.title, sev=excluded.sev, "
                    "score=excluded.score, detail=excluded.detail",
                    (asset_id, f["host"], f["fkey"], f["title"], f["sev"], now,
                     f.get("score"), json.dumps(f["detail"]) if f.get("detail") else None))
            _diff_hosts(c, asset_id, hosts, now)
            _save_hostinfo(c, asset_id, extra["hostinfo"])
            _save_services(c, asset_id, extra, now)
            c.execute("UPDATE scans SET status='done', notes=?, finished=? WHERE id=?", (notes, now, scan_id))
    except scanner.ScanCancelled:
        _mark_cancelled(scan_id)
    except Exception as e:  # noqa: BLE001
        with db.conn() as c:
            c.execute("UPDATE scans SET status='failed', notes=?, finished=? WHERE id=?",
                      (str(e)[:300], time.time(), scan_id))
    finally:
        _CANCEL.pop(scan_id, None)


def _create_scan(a, source, status="running"):
    """Tạo bản ghi quét. Trả về scan_id, hoặc None nếu tài sản đang được quét hoặc đang chờ quét."""
    with db.conn() as c:
        if c.execute("SELECT 1 FROM scans WHERE asset_id=? AND status IN ('running','queued')", (a["id"],)).fetchone():
            return None
        cur = c.execute("INSERT INTO scans(asset_id,target,status,created,source) VALUES(?,?,?,?,?)",
                        (a["id"], a["name"], status, time.time(), source))
        return cur.lastrowid


def _run_queue(items):
    """Quét lần lượt từng tài sản trong nhóm (xong cái này mới tới cái kế tiếp)."""
    for scan_id, a in items:
        with db.conn() as c:
            started = c.execute("UPDATE scans SET status='running', created=? WHERE id=? AND status='queued'",
                                (time.time(), scan_id)).rowcount
        if started:
            _run_scan(scan_id, a["id"], a["kind"], a["name"])
        else:
            _CANCEL.pop(scan_id, None)      # đã bị dừng khi còn đang chờ


@router.post("/groups/{group_id}/scan", status_code=202)
def scan_group(group_id: int, bg: BackgroundTasks, u: dict = Depends(current_user)):
    if not db.one("SELECT id FROM asset_groups WHERE id=? AND user_id=?", (group_id, u["id"])):
        raise HTTPException(404, "Không tìm thấy nhóm.")
    members = db.rows("SELECT * FROM assets WHERE group_id=? AND user_id=? ORDER BY created, id", (group_id, u["id"]))
    items = []
    for a in members:
        sid = _create_scan(a, "manual", "queued")
        if sid is not None:
            items.append((sid, a))
    if not items:
        raise HTTPException(409, "Nhóm này đang được quét hoặc không có tài sản nào.")
    bg.add_task(_run_queue, items)
    return {"queued": len(items), "skipped": len(members) - len(items)}


@router.post("/scans", status_code=202)
def start_scan(body: ScanIn, bg: BackgroundTasks, u: dict = Depends(current_user)):
    a = db.one("SELECT * FROM assets WHERE id=? AND user_id=?", (body.asset_id, u["id"]))
    if not a:
        raise HTTPException(404, "Không tìm thấy tài sản.")
    scan_id = _create_scan(a, "manual")
    if scan_id is None:
        raise HTTPException(409, "Tài sản này đang được quét.")
    bg.add_task(_run_scan, scan_id, a["id"], a["kind"], a["name"])
    return {"id": scan_id, "status": "running"}


def _stop_scans(rows):
    """Dừng các lần quét đang chạy hoặc đang chờ. Trả về số lần quét đã dừng."""
    n = 0
    for r in rows:
        _cancel_event(r["id"]).set()                     # đang chạy: luồng quét sẽ tự dừng
        _mark_cancelled(r["id"])                         # đổi trạng thái ngay để giao diện cập nhật liền
        n += 1
    return n


@router.post("/scans/cancel")
def cancel_scan(body: ScanIn, u: dict = Depends(current_user)):
    rows = db.rows("SELECT s.id FROM scans s JOIN assets a ON a.id=s.asset_id "
                   "WHERE a.id=? AND a.user_id=? AND s.status IN ('running','queued')", (body.asset_id, u["id"]))
    if not rows:
        raise HTTPException(409, "Tài sản này hiện không được quét.")
    return {"stopped": _stop_scans(rows)}


@router.post("/scans/cancel-all")
def cancel_all_scans(u: dict = Depends(current_user)):
    """Dừng mọi lần quét đang chạy / đang chờ của người dùng (kể cả quét tự động theo lịch)."""
    rows = db.rows("SELECT s.id FROM scans s JOIN assets a ON a.id=s.asset_id "
                   "WHERE a.user_id=? AND s.status IN ('running','queued')", (u["id"],))
    if not rows:
        raise HTTPException(409, "Hiện không có lần quét nào đang chạy.")
    return {"stopped": _stop_scans(rows)}


@router.post("/groups/{group_id}/scan/cancel")
def cancel_group_scan(group_id: int, u: dict = Depends(current_user)):
    rows = db.rows("SELECT s.id FROM scans s JOIN assets a ON a.id=s.asset_id "
                   "WHERE a.group_id=? AND a.user_id=? AND s.status IN ('running','queued')", (group_id, u["id"]))
    if not rows:
        raise HTTPException(409, "Nhóm này hiện không được quét.")
    return {"stopped": _stop_scans(rows)}


# ---------- lịch quét tự động ----------
@router.get("/schedules")
def list_schedules(u: dict = Depends(current_user)):
    return [{"aid": r["aid"], "asset": r["name"], "interval_h": r["interval_h"],
             "at": f'{r["at_min"] // 60:02d}:{r["at_min"] % 60:02d}' if r["interval_h"] else None,
             "weekday": r["weekday"], "tz": r["tz"],
             "next": _ms(r["next_run"]) if r["interval_h"] else None, "last": _ms(r["last_run"])}
            for r in db.rows(
                "SELECT a.id AS aid, a.name, s.interval_h, s.next_run, s.last_run, s.at_min, s.weekday, s.tz "
                "FROM assets a LEFT JOIN schedules s ON s.asset_id=a.id "
                "WHERE a.user_id=? ORDER BY a.created DESC", (u["id"],))]


@router.put("/schedules/{asset_id}")
def set_schedule(asset_id: int, body: ScheduleIn, u: dict = Depends(current_user)):
    if body.interval_h not in INTERVALS:
        raise HTTPException(422, "Tần suất không hợp lệ.")
    if not db.one("SELECT id FROM assets WHERE id=? AND user_id=?", (asset_id, u["id"])):
        raise HTTPException(404, "Không tìm thấy tài sản.")
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", body.at):
        raise HTTPException(422, "Giờ không hợp lệ (định dạng HH:MM).")
    if not 0 <= body.weekday <= 6 or not -840 <= body.tz <= 840:
        raise HTTPException(422, "Thứ hoặc múi giờ không hợp lệ.")
    now = time.time()
    at_min = int(body.at[:2]) * 60 + int(body.at[3:])
    nxt = _next_run(body.interval_h, at_min, body.weekday, body.tz, now)
    with db.conn() as c:
        c.execute(
            "INSERT INTO schedules(asset_id,interval_h,next_run,created,at_min,weekday,tz) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(asset_id) DO UPDATE SET interval_h=excluded.interval_h, next_run=excluded.next_run, "
            "at_min=excluded.at_min, weekday=excluded.weekday, tz=excluded.tz",
            (asset_id, body.interval_h, nxt, now, at_min, body.weekday, body.tz))
    return {"aid": asset_id, "interval_h": body.interval_h, "next": _ms(nxt)}


@router.delete("/schedules/{asset_id}", status_code=204)
def delete_schedule(asset_id: int, u: dict = Depends(current_user)):
    with db.conn() as c:
        c.execute("DELETE FROM schedules WHERE asset_id=? AND asset_id IN (SELECT id FROM assets WHERE user_id=?)",
                  (asset_id, u["id"]))


def _tick():
    """Quét các tài sản đã đến giờ (kể cả lịch bị lỡ lúc máy/ứng dụng đang tắt: chạy bù ngay khi khởi động).
    Các tài sản đến hạn cùng lúc được xếp hàng và quét lần lượt trong một luồng nền, tránh mở hàng chục nmap một lúc."""
    now = time.time()
    due = db.rows(
        "SELECT s.id AS sid, s.interval_h, s.at_min, s.weekday, s.tz, s.next_run, a.id, a.name, a.kind FROM schedules s "
        "JOIN assets a ON a.id=s.asset_id WHERE s.next_run<=? ORDER BY s.next_run, s.id", (now,))
    items = []
    for d in due:
        nxt = _next_run(d["interval_h"], d["at_min"], d["weekday"], d["tz"], now)
        with db.conn() as c:   # "giành" lượt chạy: chỉ một tiến trình/luồng được phép xử lý mỗi mốc
            if c.execute("UPDATE schedules SET next_run=? WHERE id=? AND next_run=?",
                         (nxt, d["sid"], d["next_run"])).rowcount == 0:
                continue
        scan_id = _create_scan(d, "auto", "queued")
        if scan_id is None:      # đang quét dở (vd người dùng bấm tay), thử lại sau 1 phút
            with db.conn() as c:
                c.execute("UPDATE schedules SET next_run=? WHERE id=?", (now + 60, d["sid"]))
            continue
        with db.conn() as c:
            c.execute("UPDATE schedules SET last_run=? WHERE id=?", (now, d["sid"]))
        items.append((scan_id, d))
    if items:
        threading.Thread(target=_run_queue, args=(items,), daemon=True).start()


async def _scheduler():
    # Lưu ý: chỉ chạy 1 worker uvicorn, nếu không mỗi worker sẽ tự lập lịch một lần.
    while True:
        try:
            await asyncio.to_thread(_tick)
        except Exception as e:  # noqa: BLE001
            print("[scheduler]", e)
        await asyncio.sleep(30)


# ---------- xuất báo cáo ----------
@router.get("/reports/export")
def export_report(fmt: str = Query("html", alias="format"), asset_id: int | None = None,
                  group_id: int | None = None, include_closed: bool = False, u: dict = Depends(current_user)):
    fmt = fmt.lower()
    if fmt not in ("html", "csv", "json"):
        raise HTTPException(422, "Định dạng không hợp lệ (html, csv, json).")
    cond, args = "", [u["id"]]
    gname = None
    if group_id is not None:
        g = db.one("SELECT name FROM asset_groups WHERE id=? AND user_id=?", (group_id, u["id"]))
        if not g:
            raise HTTPException(404, "Không tìm thấy nhóm.")
        gname = "Nhóm: " + g["name"]
        cond += " AND a.group_id=?"
        args.append(group_id)
    if asset_id is not None:
        cond += " AND a.id=?"
        args.append(asset_id)
    assets = db.rows(
        "SELECT a.id, a.name, a.kind, a.created, "
        "(SELECT COUNT(*) FROM asset_hosts h WHERE h.asset_id=a.id AND h.active=1) AS hosts, "
        "(SELECT status FROM scans s WHERE s.asset_id=a.id ORDER BY s.created DESC, s.id DESC LIMIT 1) AS scan_status, "
        "(SELECT finished FROM scans s WHERE s.asset_id=a.id ORDER BY s.created DESC, s.id DESC LIMIT 1) AS scan_finished "
        "FROM assets a WHERE a.user_id=?" + cond + " ORDER BY a.name", args)
    if asset_id is not None and not assets:
        raise HTTPException(404, "Không tìm thấy tài sản.")
    findings = db.rows(
        "SELECT f.host, f.title, f.sev, f.open, f.created, a.name AS asset, a.id AS aid FROM findings f "
        "JOIN assets a ON a.id=f.asset_id WHERE a.user_id=?" + cond + ("" if include_closed else " AND f.open=1") +
        " ORDER BY CASE f.sev WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.created DESC",
        args)
    scope = assets[0]["name"] if asset_id is not None else (gname or "Tất cả tài sản")
    stamp = time.strftime("%Y%m%d-%H%M")
    if fmt == "csv":
        body, mt, attach = reports.to_csv(findings), "text/csv; charset=utf-8", True
    elif fmt == "json":
        body, mt, attach = reports.to_json(u, scope, assets, findings), "application/json; charset=utf-8", True
    else:
        body, mt, attach = reports.to_html(u, scope, assets, findings), "text/html; charset=utf-8", False
    headers = {"Content-Disposition": f'{"attachment" if attach else "inline"}; filename="lantern-report-{stamp}.{fmt}"'}
    return Response(body, media_type=mt, headers=headers)


app.include_router(router)


# ---------- trang giao diện ----------
# Khi đóng gói bằng PyInstaller, pages/ và static/ nằm trong thư mục giải nén (_MEIPASS)
ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
PAGES = ROOT / "pages"


def _page(name: str) -> FileResponse:
    return FileResponse(PAGES / name, media_type="text/html; charset=utf-8")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(ROOT / "static" / "favicon.ico", media_type="image/x-icon")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.url.path in ("/", "/login", "/register", "/verify", "/forgot", "/reset") or request.url.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/", include_in_schema=False)
def home(request: Request):
    if not auth.user_from_request(request):
        return RedirectResponse("/login", status_code=303)
    return _page("index.html")


@app.get("/login", include_in_schema=False)
def login_page(request: Request):
    if auth.user_from_request(request):
        return RedirectResponse("/", status_code=303)
    return _page("login.html")


@app.get("/register", include_in_schema=False)
def register_page(request: Request):
    if auth.user_from_request(request):
        return RedirectResponse("/", status_code=303)
    return _page("register.html")


@app.get("/verify", include_in_schema=False)
def verify_page(request: Request):
    if auth.user_from_request(request):
        return RedirectResponse("/", status_code=303)
    if not auth.pending_from_request(request):  # chưa đăng ký (hoặc đã hết hạn) thì về trang đăng ký
        return RedirectResponse("/register", status_code=303)
    return _page("verify.html")


@app.get("/forgot", include_in_schema=False)
def forgot_page(request: Request):
    if auth.user_from_request(request):
        return RedirectResponse("/", status_code=303)
    return _page("forgot.html")


@app.get("/reset", include_in_schema=False)
def reset_page(request: Request):
    if auth.user_from_request(request):
        return RedirectResponse("/", status_code=303)
    if not auth.reset_cookie_present(request):
        return RedirectResponse("/forgot", status_code=303)
    return _page("reset.html")


# Chỉ chứa file tĩnh công khai (auth.css). Các trang HTML nằm ở pages/ và đi qua route có kiểm tra đăng nhập.
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
