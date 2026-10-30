"""Quét có xác thực (authenticated/credentialed scan) qua SSH.

CHỈ dùng cho tài sản bạn sở hữu hoặc được phép kiểm tra bằng văn bản, với tài khoản
được cấp riêng cho mục đích quét (khuyến nghị: quyền đọc, không phải root).

Khác với quét không xác thực (scanner.py: dò cổng/HTTP từ bên ngoài), ở đây Lantern
SSH thẳng vào máy bằng credential người dùng cung cấp và chỉ chạy các lệnh ĐỌC
(không sửa/xóa gì) để lấy: bản phân phối OS, kernel, danh sách gói cài đặt (so khớp
CVE như dịch vụ mạng), cấu hình sshd hiện hành, và vài kiểm tra cấu hình rủi ro cao
(root login, tài khoản UID 0 ngoài root, mật khẩu trống).

Lưu ý bảo mật: dùng AutoAddPolicy (tự tin cậy host key lần đầu, giống cách Nessus/
OpenVAS mặc định làm khi quét nội bộ) vì mục tiêu là quét nhiều máy nội bộ không có
known_hosts sẵn. Nếu cần chống MITM nghiêm ngặt hơn, nạp known_hosts cố định thay vì
AutoAddPolicy.
"""
import ipaddress
import os
import re
import shlex
from concurrent.futures import ThreadPoolExecutor

from . import vulns

SSH_WORKERS = int(os.getenv("LANTERN_SSH_WORKERS", "5"))   # số kết nối SSH song song khi quét cả dải

try:
    import paramiko
except ImportError:  # thư viện tùy chọn, như nmap/subfinder
    paramiko = None

CONNECT_TIMEOUT = 10
CMD_TIMEOUT = 20
# Số IP tối đa quét SSH mỗi lần với 1 dải CIDR (mặc định 20 để tránh 1 lần quét kéo quá lâu khi
# nhiều host không ssh được phải chờ hết CONNECT_TIMEOUT từng cái). Dải /24 đủ server dùng chung
# 1 credential thì có thể tăng qua biến môi trường, nhưng cân nhắc: kết nối chạy TUẦN TỰ từng host,
# không song song, nên 50 host x ~10s timeout (host chết/không SSH) có thể mất > 8 phút.
MAX_HOSTS = int(os.getenv("LANTERN_SSH_MAX_HOSTS", "20"))

# gói phần mềm hay bị CVE nặng -> (vendor, product) để dựng CPE tra NVD (tùy chọn, best-effort)
PKG_CPE = {
    "openssh-server": ("openbsd", "openssh"), "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"), "libssl1.1": ("openssl", "openssl"), "libssl3": ("openssl", "openssl"),
    "sudo": ("sudo_project", "sudo"), "bash": ("gnu", "bash"), "glibc": ("gnu", "glibc"),
    "nginx": ("nginx", "nginx"), "apache2": ("apache", "http_server"), "httpd": ("apache", "http_server"),
    "samba": ("samba", "samba"), "vsftpd": ("vsftpd_project", "vsftpd"),
}

_SSHD_RISKY = {
    "permitrootlogin": (lambda v: v not in ("no", "prohibit-password", "without-password"),
                         "sshd cho phép đăng nhập root qua SSH (PermitRootLogin {v})", "high"),
    "passwordauthentication": (lambda v: v == "yes",
                                "sshd cho phép xác thực bằng mật khẩu (nên chỉ dùng public key)", "medium"),
    "permitemptypasswords": (lambda v: v == "yes",
                              "sshd cho phép mật khẩu rỗng (PermitEmptyPasswords yes)", "critical"),
    "x11forwarding": (lambda v: v == "yes", "sshd bật X11Forwarding (không cần thiết, tăng bề mặt tấn công)", "low"),
}


class SshAuthError(Exception):
    """Sai username/mật khẩu/khóa, hoặc không kết nối được."""


def expand_targets(kind: str, value: str):
    """domain/ip -> [value]; cidr -> tối đa MAX_HOSTS IP đầu (bỏ network/broadcast)."""
    if kind != "cidr":
        return [value]
    net = ipaddress.ip_network(value, strict=False)
    hosts = [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    return hosts[:MAX_HOSTS]


def _connect(host, port, cred):
    if paramiko is None:
        raise SshAuthError("chưa cài thư viện paramiko (pip install paramiko)")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = dict(hostname=host, port=port, username=cred["username"],
                  timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT,
                  auth_timeout=CONNECT_TIMEOUT, allow_agent=False, look_for_keys=False)
    if cred["auth_type"] == "key":
        pkey = _load_private_key(cred["secret"], cred.get("passphrase") or None)
        kwargs["pkey"] = pkey
    else:
        kwargs["password"] = cred["secret"]
    try:
        client.connect(**kwargs)
    except paramiko.AuthenticationException as e:
        raise SshAuthError(f"sai thông tin đăng nhập: {e}") from e
    except (paramiko.SSHException, OSError) as e:
        raise SshAuthError(str(e)) from e
    return client


def _load_private_key(pem: str, passphrase: str):
    import io
    last = None
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(io.StringIO(pem), password=passphrase)
        except paramiko.SSHException as e:
            last = e
    raise SshAuthError(f"không đọc được private key ({last})")


def _exec(client, cmd, timeout=CMD_TIMEOUT):
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", "replace")
    except (OSError, EOFError, paramiko.SSHException):
        return ""


_KV_RE = re.compile(r'^([A-Za-z_]+)\s*=\s*"?([^"\n]*)"?\s*$')


def _parse_os_release(text):
    out = {}
    for line in text.splitlines():
        m = _KV_RE.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _sshd_effective_config(client):
    """sshd -T cần quyền đọc file config; nếu không chạy được thì đọc trực tiếp sshd_config (best-effort)."""
    out = _exec(client, "sshd -T 2>/dev/null")
    if not out.strip():
        out = _exec(client, "cat /etc/ssh/sshd_config 2>/dev/null")
    cfg = {}
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and not parts[0].startswith("#"):
            cfg.setdefault(parts[0].lower(), parts[1].strip())
    return cfg


def _packages(client):
    out = _exec(client,
                "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null || "
                "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null", timeout=30)
    pkgs = []
    for line in out.splitlines():
        if "\t" in line:
            name, ver = line.split("\t", 1)
            pkgs.append((name.strip(), ver.strip()))
    return pkgs


def scan_host(host, port, cred, cancel=None):
    """Quét SSH-auth một host. Trả về (findings_không_phải_cve, services_để_tra_cve, info)
    hoặc ném SshAuthError. Không tự tra CVE ở đây để auth_scan() gộp tra 1 lần cho cả dải
    (tránh gọi NVD trùng khi nhiều host chạy cùng version gói, và tránh đua nhau rate-limit
    khi nhiều host chạy song song)."""
    client = _connect(host, port, cred)
    try:
        osr = _parse_os_release(_exec(client, "cat /etc/os-release 2>/dev/null"))
        kernel = _exec(client, "uname -srm 2>/dev/null").strip()
        info = {"os": osr.get("PRETTY_NAME", ""), "kernel": kernel}

        findings = []

        def add(key, title, sev):
            findings.append({"host": host, "fkey": f"ssh:{key}", "title": f"{title} ({host})", "sev": sev})

        # --- cấu hình sshd ---
        cfg = _sshd_effective_config(client)
        for key, (bad, msg_tpl, sev) in _SSHD_RISKY.items():
            v = cfg.get(key)
            if v is not None and bad(v):
                add(f"cfg:{key}", msg_tpl.format(v=v), sev)

        # --- tài khoản UID 0 ngoài root ---
        extra_root = [u for u in _exec(client, "awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null")
                      .split() if u and u != "root"]
        if extra_root:
            add("uid0", f"Có tài khoản khác ngoài root cũng có UID 0: {', '.join(extra_root[:10])}", "critical")

        # --- tài khoản mật khẩu trống (cần đủ quyền đọc /etc/shadow, thường cần sudo) ---
        empty_pw = [u for u in _exec(client, "awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null")
                    .split() if u]
        if empty_pw:
            add("emptypw", f"Tài khoản không có mật khẩu: {', '.join(empty_pw[:10])}", "critical")

        # --- gói phần mềm -> dựng CPE để tra CVE sau (tái dùng app/vulns.py, giống nmap -sV) ---
        pkgs = _packages(client)
        info["pkg_count"] = len(pkgs)
        services = []
        for name, ver in pkgs:
            key = name.lower()
            if key in PKG_CPE and ver:
                vendor, product = PKG_CPE[key]
                v = re.match(r"^[\w.+~-]+", ver)
                v = v.group(0) if v else ver
                services.append({"host": host, "port": port, "service": "ssh-pkg",
                                 "product": product, "version": v,
                                 "cpe": f"cpe:/a:{vendor}:{product}:{v}"})

        return findings, services, info
    finally:
        client.close()


def auth_scan(kind, value, cred, notes, cancel=None):
    """Quét SSH-auth cho một asset (ip/domain: 1 host; cidr: tối đa MAX_HOSTS host đầu của dải).
    Kết nối song song (LANTERN_SSH_WORKERS, mặc định 5) để quét cả dải /24 không bị quá lâu.
    Trả về (findings, hostinfo). Lỗi ở TỪNG host (sai mật khẩu, không ssh được...) không làm hỏng
    kết quả các host khác hay kết quả quét mạng đã chạy trước đó, chỉ gộp vào notes."""
    from . import scanner  # tránh import vòng
    targets = expand_targets(kind, value)
    port = cred.get("port", 22)

    def _one(host):
        scanner._check(cancel)
        try:
            return host, scan_host(host, port, cred, cancel), None
        except SshAuthError as e:
            return host, None, str(e)

    with ThreadPoolExecutor(max_workers=min(SSH_WORKERS, len(targets)) or 1) as ex:
        results = list(ex.map(_one, targets))   # ScanCancelled (nếu có) sẽ nổi lên ở đây

    findings, hostinfo, errors, all_services = [], {}, [], []
    for host, res, err in results:
        if err is not None:
            errors.append(f"{host}: {err}")
            continue
        f, services, info = res
        findings += f
        all_services += services
        hostinfo[host] = info

    findings += vulns.cve_findings(all_services, notes)   # tra CVE 1 lần gộp cho cả dải

    if errors:
        notes.append(f"SSH-auth lỗi {len(errors)}/{len(targets)} host: " + "; ".join(errors[:5]))
    if hostinfo:
        notes.append(f"SSH-auth thành công {len(hostinfo)}/{len(targets)} host")
    return findings, hostinfo
