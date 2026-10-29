"""Quét lỗ hổng tầng ứng dụng web (XSS, SQLi, lộ file nhạy cảm, misconfig...) qua OWASP ZAP.

CHỈ dùng cho tài sản bạn sở hữu hoặc được phép kiểm tra bằng văn bản.

Cách hoạt động:
- ZAP là công cụ ngoài, chạy sẵn ở chế độ nền (daemon), điều khiển qua REST API cục bộ
  (mặc định http://127.0.0.1:8090, đổi bằng LANTERN_ZAP_API). Phải tự khởi động ZAP
  daemon trước khi quét (zap.bat -daemon -port 8090 -config api.disablekey=true),
  giống cách subfinder/nmap là công cụ ngoài tùy chọn trong scanner.py — thiếu/không
  gọi được thì bỏ qua bước này, không làm hỏng phần còn lại của quy trình quét.
- Với mỗi URL: gọi Spider (dò toàn bộ trang) rồi đợi xong; mặc định CHỈ lấy kết quả
  Passive Scan (ZAP tự phân tích traffic khi spider chạy, không gửi payload khai thác).
  Active Scan (chủ động chèn payload dò XSS/SQLi...) xâm lấn hơn nhiều, tắt theo mặc
  định, bật qua LANTERN_ZAP_ACTIVE_SCAN=1 nếu được phép kiểm tra sâu trên tài sản này.
- Đọc cảnh báo (alerts) của từng URL qua API, lọc theo mức rủi ro, gộp thành finding
  cùng định dạng với scanner.py/vulns.py để main.py lưu thẳng vào bảng findings.
"""
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

ZAP_API = os.getenv("LANTERN_ZAP_API", "http://127.0.0.1:8090").rstrip("/")
MAX_URLS = int(os.getenv("LANTERN_ZAP_MAX_URLS", "20"))        # số host web tối đa đưa vào ZAP mỗi lần quét
SPIDER_TIMEOUT = int(os.getenv("LANTERN_ZAP_SPIDER_TIMEOUT_S", "180"))   # timeout dò toàn bộ trang (giây)
ASCAN_TIMEOUT = int(os.getenv("LANTERN_ZAP_ASCAN_TIMEOUT_S", "900"))     # timeout active scan (giây)
HTTP_TIMEOUT = 10                                               # timeout mỗi lần gọi API ZAP (giây)
POLL_EVERY = 2                                                  # giây giữa các lần hỏi tiến độ

RISK_ORDER = ("High", "Medium", "Low", "Informational")        # thứ tự rủi ro ZAP dùng
MIN_RISK = os.getenv("LANTERN_ZAP_MIN_RISK", "Low")             # bỏ qua Informational theo mặc định
RISK_TO_SEV = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "low"}


def enabled() -> bool:
    return os.getenv("LANTERN_WEBVULN", "1") != "0"


def web_urls(hostinfo: dict, limit=MAX_URLS):
    """hostinfo: {host: {web, ...}} từ scanner.probe(). Trả về danh sách URL gốc 'host có web'."""
    urls = [f"{i['web']}://{h}" for h, i in hostinfo.items() if i.get("web")]
    return urls[:limit]


def _risk_ok(risk: str) -> bool:
    try:
        return RISK_ORDER.index(risk) <= RISK_ORDER.index(MIN_RISK)
    except ValueError:
        return True


def _zap_get(path, params=None):
    """Gọi một endpoint JSON của ZAP, trả về dict đã parse hoặc None nếu lỗi."""
    qs = "?" + urllib.parse.urlencode(params) if params else ""
    try:
        with urllib.request.urlopen(ZAP_API + path + qs, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None


def _zap_alive() -> bool:
    return _zap_get("/JSON/core/view/version/") is not None


def _spider(url, notes):
    """Chạy spider trên url, đợi tới khi xong hoặc hết timeout. True nếu hoàn tất."""
    r = _zap_get("/JSON/spider/action/scan/", {"url": url, "recurse": "true"})
    if not r or "scan" not in r:
        notes.append(f"ZAP: không khởi động được spider cho {url}")
        return False
    scan_id = r["scan"]
    deadline = time.monotonic() + SPIDER_TIMEOUT
    while time.monotonic() < deadline:
        st = _zap_get("/JSON/spider/view/status/", {"scanId": scan_id})
        if st and int(st.get("status", 0)) >= 100:
            return True
        time.sleep(POLL_EVERY)
    notes.append(f"ZAP: spider {url} quá thời gian cho phép ({SPIDER_TIMEOUT}s), lấy kết quả đã có")
    return True  # vẫn đọc alert đã thu thập được tới lúc này


def _active_scan(url, notes):
    """Active scan (chủ động chèn payload): chỉ chạy khi LANTERN_ZAP_ACTIVE_SCAN=1."""
    r = _zap_get("/JSON/ascan/action/scan/", {"url": url, "recurse": "true", "inScopeOnly": "false"})
    if not r or "scan" not in r:
        notes.append(f"ZAP: không khởi động được active scan cho {url}")
        return
    scan_id = r["scan"]
    deadline = time.monotonic() + ASCAN_TIMEOUT
    while time.monotonic() < deadline:
        st = _zap_get("/JSON/ascan/view/status/", {"scanId": scan_id})
        if st and int(st.get("status", 0)) >= 100:
            return
        time.sleep(POLL_EVERY)
    notes.append(f"ZAP: active scan {url} quá thời gian cho phép ({ASCAN_TIMEOUT}s), lấy kết quả đã có")


def _alerts(url):
    r = _zap_get("/JSON/core/view/alerts/", {"baseurl": url})
    return (r or {}).get("alerts", [])


def web_findings(urls, notes):
    """Chạy ZAP trên danh sách URL, trả về list finding {host, fkey, title, sev, detail}.
    Không ném lỗi: ZAP không chạy / timeout / lỗi API đều ghi vào notes và bỏ qua, không
    làm hỏng phần còn lại của quy trình quét (giống cách port_scan/cve_findings xử lý lỗi)."""
    if not enabled():
        return []
    if not urls:
        notes.append("ZAP: không có host web nào đang hoạt động để quét")
        return []
    if not _zap_alive():
        notes.append(f"không gọi được ZAP daemon tại {ZAP_API}, bỏ qua quét lỗ hổng web (XSS/SQLi/OWASP)")
        return []

    active = os.getenv("LANTERN_ZAP_ACTIVE_SCAN", "0") == "1"
    out, seen, total_alerts = [], set(), 0
    for url in urls:
        if not _spider(url, notes):
            continue
        if active:
            _active_scan(url, notes)
        for a in _alerts(url):
            total_alerts += 1
            risk = a.get("risk") or "Informational"
            if risk not in RISK_TO_SEV or not _risk_ok(risk):
                continue
            plugin_id = a.get("pluginId") or a.get("id") or "zap"
            host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            matched = a.get("url") or url
            key = (host, plugin_id, matched)
            if key in seen:
                continue
            seen.add(key)
            name = a.get("alert") or a.get("name") or f"ZAP #{plugin_id}"
            ref_lines = (a.get("reference") or "").splitlines()
            out.append({
                "host": host,
                "fkey": f"web:{plugin_id}",
                "title": f"{name} ({matched})",
                "sev": RISK_TO_SEV[risk],
                "detail": {
                    "plugin_id": plugin_id,
                    "matched_at": matched,
                    "risk": risk,
                    "confidence": a.get("confidence"),
                    "reference": ref_lines[0] if ref_lines else None,
                },
            })
    if total_alerts:
        notes.append(f"ZAP: {total_alerts} cảnh báo khớp, {len(out)} finding sau khi lọc mức độ")
    else:
        notes.append(f"ZAP: đã quét {len(urls)} host web, không có cảnh báo nào")
    return out
