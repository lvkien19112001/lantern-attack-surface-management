"""Quét lỗ hổng mức mạng (kiểu Nessus): tra CVE theo phiên bản dịch vụ và kiểm tra TLS.

CHỈ dùng cho tài sản bạn sở hữu hoặc được phép kiểm tra bằng văn bản.

- Tra CVE: lấy CPE (tên + phiên bản phần mềm) do nmap -sV nhận diện rồi hỏi NVD (API 2.0).
  Chỉ gửi chuỗi CPE (vd apache:http_server:2.4.49) lên NVD, KHÔNG gửi tên miền hay IP của bạn.
  Kết quả khớp theo phiên bản nên có thể dương tính giả (bản Linux thường vá ngược lỗi mà không đổi số phiên bản).
- TLS: số ngày còn lại của chứng chỉ và giao thức lỗi thời (TLS 1.0/1.1). Chỉ thử bắt tay TLS, không khai thác gì.
"""
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

from . import db

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "Lantern-ASM/1.0"
CACHE_TTL = 7 * 86400          # giữ kết quả tra CVE 7 ngày để khỏi gọi lại NVD
PER_SERVICE = 10               # tối đa số CVE báo cho mỗi dịch vụ (lấy điểm cao nhất)


def _num(name, default, cast):
    try:
        return cast(os.getenv(name, "") or default)
    except ValueError:
        return cast(default)


def enabled() -> bool:
    return os.getenv("LANTERN_CVE_LOOKUP", "1") != "0"


def _cfg():
    key = os.getenv("LANTERN_NVD_API_KEY", "").strip()
    return {
        "key": key,
        "min_score": _num("LANTERN_CVE_MIN_SCORE", "7.0", float),
        "max_lookups": _num("LANTERN_CVE_MAX_LOOKUPS", "15", int),
        # NVD: 5 request/30s khi không có key, 50 request/30s khi có key
        "gap": 0.7 if key else 6.5,
    }


# ---------------------------------------------------------------- CVE

def cpe_to_23(cpe: str):
    """cpe:/a:apache:http_server:2.4.49 -> cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    Chỉ nhận phần mềm (a) có phiên bản; bỏ qua OS vì kết quả quá chung chung."""
    if not cpe.startswith("cpe:/a:"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) < 4 or not parts[3]:
        return None
    parts = [p or "*" for p in parts[:11]]
    parts += ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(parts)


def _score(cve: dict):
    metrics = cve.get("metrics") or {}
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(k)
        if m:
            try:
                return float(m[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def _fetch(cpe23: str, key: str):
    """Hỏi NVD. Trả về [{id, score}]. 404 = NVD không biết CPE này -> danh sách rỗng.
    Lỗi mạng / 403 / 429 được ném ra để dừng tra cứu."""
    q = urllib.parse.urlencode({"cpeName": cpe23, "isVulnerable": "", "noRejected": ""})
    q = q.replace("isVulnerable=", "isVulnerable").replace("noRejected=", "noRejected")
    headers = {"User-Agent": USER_AGENT}
    if key:
        headers["apiKey"] = key
    try:
        with urllib.request.urlopen(urllib.request.Request(f"{NVD_URL}?{q}", headers=headers), timeout=30) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            return []
        raise
    out = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        s = _score(cve)
        if cve.get("id") and s is not None:
            out.append({"id": cve["id"], "score": s})
    return out


def _cache_get(cpe23):
    r = db.one("SELECT data, fetched FROM cve_cache WHERE cpe=?", (cpe23,))
    if r and time.time() - r["fetched"] < CACHE_TTL:
        return json.loads(r["data"])
    return None


def _cache_put(cpe23, data):
    with db.conn() as c:
        c.execute("INSERT INTO cve_cache(cpe,data,fetched) VALUES(?,?,?) "
                  "ON CONFLICT(cpe) DO UPDATE SET data=excluded.data, fetched=excluded.fetched",
                  (cpe23, json.dumps(data), time.time()))


def cve_findings(services, notes, fetch=None):
    """services: [{host, port, product, version, cpe}] -> danh sách finding theo CVE."""
    if not enabled() or not services:
        return []
    cfg = _cfg()
    fetch = fetch or _fetch
    groups = {}
    for s in services:
        c23 = cpe_to_23(s.get("cpe", ""))
        if c23:
            groups.setdefault(c23, []).append(s)
    if not groups:
        return []

    cves, fetched, skipped, last = {}, 0, 0, 0.0
    for c23 in groups:
        data = _cache_get(c23)
        if data is None:
            if fetched >= cfg["max_lookups"]:
                skipped += 1
                continue
            time.sleep(max(0.0, cfg["gap"] - (time.time() - last)))
            try:
                data = fetch(c23, cfg["key"])
            except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as e:
                notes.append(f"không tra được CVE (NVD không phản hồi hoặc giới hạn tốc độ: {str(e)[:60]})")
                break
            last = time.time()
            fetched += 1
            _cache_put(c23, data)
        cves[c23] = data
    if skipped:
        notes.append(f"bỏ qua tra CVE cho {skipped} dịch vụ (vượt giới hạn {cfg['max_lookups']} lần tra mỗi lần quét)")

    out = []
    for c23, svcs in groups.items():
        hits = sorted((c for c in cves.get(c23, []) if c["score"] >= cfg["min_score"]),
                      key=lambda c: -c["score"])[:PER_SERVICE]
        for s in svcs:
            name = f"{s.get('product') or 'dịch vụ'} {s.get('version') or ''}".strip()
            for c in hits:
                out.append({
                    "host": s["host"], "fkey": f"cve:{s['port']}:{c['id']}",
                    "title": f"{c['id']} (CVSS {c['score']:.1f}) - {name} cổng {s['port']} ({s['host']}), khớp theo phiên bản, cần xác nhận",
                    "sev": "critical" if c["score"] >= 9.0 else "high",
                    "score": c["score"],
                    "detail": {"cve": c["id"], "port": s["port"], "product": s.get("product", ""),
                               "version": s.get("version", "")},
                })
    if out:
        notes.append(f"{len(out)} CVE khớp phiên bản dịch vụ")
    return out


# ---------------------------------------------------------------- TLS

def tls_days(host, port=443, ctx=None):
    """Số ngày còn lại của chứng chỉ (chỉ khi chứng chỉ hợp lệ), hoặc None."""
    ctx = ctx or ssl.create_default_context()
    try:
        with socket.create_connection((host, port), 6) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            na = (t.getpeercert() or {}).get("notAfter")
        return int((ssl.cert_time_to_seconds(na) - time.time()) // 86400) if na else None
    except (OSError, ssl.SSLError, ValueError):
        return None


_LEGACY = (("TLSv1", "TLS 1.0"), ("TLSv1_1", "TLS 1.1"))


def legacy_tls(host, port=443):
    """Giao thức lỗi thời mà máy chủ vẫn chấp nhận. Chỉ báo khi bắt tay thành công
    (nếu OpenSSL ở máy quét không thử được thì bỏ qua, không báo nhầm)."""
    found = []
    for attr, label in _LEGACY:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers("ALL:@SECLEVEL=0")
                v = getattr(ssl.TLSVersion, attr)
                ctx.minimum_version = ctx.maximum_version = v
                with socket.create_connection((host, port), 6) as s, ctx.wrap_socket(s, server_hostname=host):
                    found.append(label)
        except (OSError, ssl.SSLError, ValueError, AttributeError):
            pass
    return found
