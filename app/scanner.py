"""Quét bề mặt tấn công.

CHỈ dùng cho tài sản bạn sở hữu hoặc được phép kiểm tra bằng văn bản.
Các công cụ ngoài (subfinder, nmap) là tùy chọn: thiếu thì bỏ qua bước đó.
"""
import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from . import vulns

MAX_HOSTS = int(os.getenv("LANTERN_MAX_HOSTS", "50"))   # số subdomain tối đa mỗi lần quét
MAX_PORT_HOSTS = 20                                      # số host tối đa đưa vào nmap
MSG = "Nhập tên miền (example.com), IP (203.0.113.5) hoặc dải IP (10.0.0.0/24)."

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# cổng -> (dịch vụ, mức độ)
RISKY = {
    21: ("FTP", "high"), 22: ("SSH", "medium"), 23: ("Telnet", "critical"),
    445: ("SMB", "critical"), 3306: ("MySQL", "high"), 3389: ("RDP", "critical"),
    5432: ("PostgreSQL", "high"), 5900: ("VNC", "high"), 6379: ("Redis", "critical"),
    9200: ("Elasticsearch", "high"), 27017: ("MongoDB", "critical"),
}


def parse_target(raw: str):
    """Trả về (kind, giá trị chuẩn hóa) hoặc ném ValueError."""
    s = raw.strip().lower()
    if DOMAIN_RE.match(s):
        return "domain", s
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            raise ValueError(MSG)
        if net.num_addresses > 256:
            raise ValueError("Dải IP quá lớn, tối đa /24 (256 địa chỉ).")
        return "cidr", str(net)
    try:
        return "ip", str(ipaddress.ip_address(s))
    except ValueError:
        raise ValueError(MSG)


class ScanCancelled(Exception):
    """Người dùng bấm "Dừng quét"."""


def _check(cancel):
    if cancel is not None and cancel.is_set():
        raise ScanCancelled()


# Windows: chạy nền bằng pythonw.exe (không có console) thì mỗi tiến trình con kiểu console
# (nmap, subfinder) sẽ tự bật một cửa sổ cmd. CREATE_NO_WINDOW chặn việc đó.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}


def _run(cmd, timeout, cancel=None):
    """Chạy công cụ ngoài. Nếu cancel (threading.Event) được bật thì dừng ngay tiến trình đang chạy."""
    if cancel is None:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  stdin=subprocess.DEVNULL, **_NO_WINDOW).stdout
        except (subprocess.TimeoutExpired, OSError):
            return ""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, text=True, **_NO_WINDOW)
    except OSError:
        return ""
    end = time.monotonic() + timeout
    while True:
        try:
            return p.communicate(timeout=0.5)[0]
        except subprocess.TimeoutExpired:
            if cancel.is_set():
                p.kill()
                p.communicate()
                raise ScanCancelled()
            if time.monotonic() > end:
                p.kill()
                p.communicate()
                return ""


def find_subdomains(domain, notes, cancel=None):
    hosts = {domain}
    if shutil.which("subfinder"):
        for line in _run(["subfinder", "-d", domain, "-silent"], 300, cancel).splitlines():
            h = line.strip().lower()
            # Giữ đúng phạm vi: chỉ nhận host thuộc chính domain này
            if (h == domain or h.endswith("." + domain)) and DOMAIN_RE.match(h):
                hosts.add(h)
    else:
        notes.append("chưa cài subfinder, chỉ kiểm tra tên miền gốc")
    return ([domain] + sorted(hosts - {domain}))[:MAX_HOSTS]


def probe(host):
    """Thử HTTPS rồi HTTP, trả về scheme, header và cờ lỗi TLS."""
    out = {"scheme": None, "headers": {}, "tls_bad": False, "tls_msg": "", "tls_days": None, "legacy": [], "ip": ""}
    try:
        out["ip"] = socket.gethostbyname(host)
    except OSError:
        pass
    for scheme in ("https", "http"):
        for verify in ((True, False) if scheme == "https" else (True,)):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": "Lantern-ASM/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                    hdr = r.headers
            except urllib.error.HTTPError as e:      # 403/404... vẫn có header để kiểm tra
                hdr = e.headers
            except urllib.error.URLError as e:
                if verify and isinstance(e.reason, ssl.SSLCertVerificationError):
                    out["tls_bad"] = True
                    out["tls_msg"] = str(getattr(e.reason, "verify_message", "") or e.reason)
                    continue                          # thử lại không verify để lấy header
                break
            except Exception:
                break
            out["scheme"] = scheme
            out["headers"] = {k.lower(): v for k, v in hdr.items()}
            if scheme == "https":
                if verify:
                    out["tls_days"] = vulns.tls_days(host)
                out["legacy"] = vulns.legacy_tls(host)
            return out
    return out


def http_findings(host, p):
    if not p["scheme"]:
        return []
    f = []

    def add(key, title, sev):
        f.append({"host": host, "fkey": key, "title": f"{title} ({host})", "sev": sev})

    h = p["headers"]
    if p["scheme"] == "http":
        add("no-https", "Không hỗ trợ HTTPS", "medium")
    if p["tls_bad"]:
        msg = p.get("tls_msg", "").lower()
        if "expired" in msg:
            add("tls-expired", "Chứng chỉ TLS đã hết hạn", "high")
        elif "mismatch" in msg:
            add("tls-mismatch", "Chứng chỉ TLS không khớp tên miền", "medium")
        else:
            add("tls-cert", "Chứng chỉ TLS không hợp lệ hoặc tự ký", "medium")
    d = p.get("tls_days")
    if d is not None and d <= 30:
        add("tls-expiring", f"Chứng chỉ TLS còn {d} ngày là hết hạn", "high" if d <= 7 else "medium")
    if p.get("legacy"):
        add("tls-legacy", "Hỗ trợ giao thức lỗi thời: " + ", ".join(p["legacy"]), "medium")
    if p["scheme"] == "https" and "strict-transport-security" not in h:
        add("hsts", "Thiếu header HSTS", "low")
    csp = h.get("content-security-policy", "")
    if not csp:
        add("csp", "Thiếu Content-Security-Policy", "low")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        add("xfo", "Thiếu chống clickjacking", "low")
    srv = h.get("server", "")
    if re.search(r"\d+\.\d+", srv):
        add("server-ver", f"Lộ phiên bản máy chủ: {srv[:40]}", "low")
    return f


def port_scan(targets, notes, services=None, cancel=None):
    """Trả về (findings, ok). ok=False nếu nmap không chạy được (để không coi cổng cũ là đã đóng).
    services (nếu truyền vào) được thêm MỌI cổng mở: {host, port, service, product, version, cpe}."""
    if not shutil.which("nmap"):
        notes.append("chưa cài nmap, bỏ qua quét cổng")
        return [], False
    # -sT (TCP connect) không cần quyền root
    detect = services is not None
    cmd = ["nmap", "-Pn", "-sT", "-T3", "--top-ports", "100", "--open", "-oX", "-"]
    if detect:
        cmd[4:4] = ["-sV", "--version-light"]      # nhận diện phiên bản dịch vụ để tra CVE
    xml = _run(cmd + targets, 1800 if detect else 900, cancel)
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        notes.append("nmap không trả kết quả hợp lệ")
        return [], False
    out = []
    for h in root.iter("host"):
        hn = h.find("hostnames/hostname")
        addr = h.find("address")
        name = hn.get("name") if hn is not None else (addr.get("addr") if addr is not None else "?")
        for p in h.iter("port"):
            st = p.find("state")
            port = int(p.get("portid"))
            if detect and st is not None and st.get("state") == "open":
                sv = p.find("service")
                cpe = next((c.text for c in sv.findall("cpe") if c.text and c.text.startswith("cpe:/a:")), "") if sv is not None else ""
                services.append({"host": name, "port": port,
                                 "service": sv.get("name", "") if sv is not None else "",
                                 "product": sv.get("product", "") if sv is not None else "",
                                 "version": sv.get("version", "") if sv is not None else "", "cpe": cpe})
            if st is not None and st.get("state") == "open" and port in RISKY:
                svc, sev = RISKY[port]
                # "mở ra internet" chỉ chính xác khi IP là IP công khai; IP nội bộ (10/8, 172.16/12,
                # 192.168/16...) thì chỉ đúng là "mở, thấy được từ máy chạy Lantern" (có thể chỉ trong LAN).
                # Muốn biết có THỰC SỰ lộ ra Internet công cộng hay không vẫn cần quét từ một vị trí
                # bên ngoài mạng nội bộ (VPS ngoài, 4G...), Lantern không tự xác minh được điều đó.
                try:
                    scope = "nội bộ (LAN)" if ipaddress.ip_address(addr.get("addr")).is_private else "Internet"
                except (ValueError, AttributeError):
                    scope = "Internet"  # không xác định được IP -> giữ cảnh báo mức cao nhất (an toàn hơn)
                out.append({"host": name, "fkey": f"port:{port}",
                            "title": f"Cổng {port} ({svc}) mở, thấy được từ phạm vi {scope} ({name})", "sev": sev})
    return out, True


def scan_asset(kind, value, cancel=None):
    """Chạy toàn bộ quy trình quét. Trả về (findings, hosts, ghi chú, extra).

    hosts là danh sách host thực sự "thấy được" trong lần quét này
    (domain: subdomain do subfinder trả về; ip/cidr: chính nó),
    dùng để so sánh với lần quét trước ở main.py (tính năng Giám sát).
    extra: {"hostinfo": {host: {ip, web, server}}, "services": [mọi cổng mở],
            "ports_ok": nmap có chạy được không, "port_hosts": các host đã được quét cổng}.
    """
    notes, findings, hostinfo = [], [], {}
    _check(cancel)
    if kind == "domain":
        hosts = find_subdomains(value, notes, cancel)
        _check(cancel)

        def _probe(h):
            _check(cancel)
            return probe(h)
        with ThreadPoolExecutor(max_workers=8) as ex:
            probes = list(ex.map(_probe, hosts))
        live = 0
        for h, p in zip(hosts, probes):
            if p["scheme"]:
                live += 1
            findings += http_findings(h, p)
            hostinfo[h] = {"ip": p["ip"], "web": p["scheme"] or "", "server": p["headers"].get("server", "")[:80]}
        notes.insert(0, f"{len(hosts)} host, {live} có web")
        targets = hosts[:MAX_PORT_HOSTS]
    else:
        hosts = [value]
        targets = [value]
        if kind == "ip":
            p = probe(value)   # dò xem IP có chạy web không (HTTP/TLS/header)
            findings += http_findings(value, p)
            hostinfo[value] = {"ip": p["ip"] or value, "web": p["scheme"] or "", "server": p["headers"].get("server", "")[:80]}
        else:   # cidr: dải mạng, không dò web cho từng IP (chỉ quét cổng ở bước dưới)
            hostinfo[value] = {"ip": "", "web": "", "server": ""}
    _check(cancel)
    services = []
    port_findings, ports_ok = port_scan(targets, notes, services, cancel)
    findings += port_findings
    _check(cancel)

    def _fetch(*a, **k):
        _check(cancel)
        return vulns._fetch(*a, **k)
    findings += vulns.cve_findings([s for s in services if s["cpe"]], notes, fetch=_fetch)
    _check(cancel)
    extra = {"hostinfo": hostinfo, "services": services, "ports_ok": ports_ok, "port_hosts": targets}
    return findings, hosts, "; ".join(notes), extra
