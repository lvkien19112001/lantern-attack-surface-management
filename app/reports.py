"""Xuất báo cáo: CSV (mở bằng Excel), HTML (xem / in / lưu PDF) và JSON."""
import csv
import html
import io
import json
import time

NAME = {"critical": "Nghiêm trọng", "high": "Cao", "medium": "Trung bình", "low": "Thấp"}
COL = {"critical": "#c81e4d", "high": "#e0662a", "medium": "#c9971a", "low": "#2f78c4"}
ORDER = ["critical", "high", "medium", "low"]
W = {"critical": 10, "high": 5, "medium": 2, "low": 0.5}
KIND = {"domain": "Tên miền", "ip": "Địa chỉ IP", "cidr": "Dải IP"}
SCAN = {"running": "Đang quét", "done": "Hoàn tất", "failed": "Thất bại"}


def fmt(ts):
    return time.strftime("%d/%m/%Y %H:%M", time.localtime(ts)) if ts else "—"


def score(findings):
    """Cùng công thức với điểm ở trang Tổng quan: chỉ tính phát hiện đang mở."""
    total = sum(W.get(f["sev"], 0) for f in findings if f["open"])
    return max(0, round(100 - total * 1.2))


def _csv_cell(v):
    """Chống CSV injection: ô bắt đầu bằng = + - @ sẽ bị Excel hiểu là công thức."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(findings):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Tài sản", "Host", "Mức độ", "Phát hiện", "Trạng thái", "Phát hiện lúc"])
    for f in findings:
        w.writerow([_csv_cell(f["asset"]), _csv_cell(f["host"]), NAME.get(f["sev"], f["sev"]),
                    _csv_cell(f["title"]), "Đang mở" if f["open"] else "Đã xử lý", fmt(f["created"])])
    return "\ufeff" + buf.getvalue()   # BOM để Excel đọc đúng tiếng Việt


def to_json(user, scope, assets, findings):
    return json.dumps({
        "generated_at": fmt(time.time()),
        "generated_by": user["username"],
        "scope": scope,
        "score": score(findings),
        "assets": [{"name": a["name"], "kind": a["kind"], "hosts": a["hosts"],
                    "last_scan_status": a["scan_status"], "last_scan_finished": fmt(a["scan_finished"])}
                   for a in assets],
        "findings": [{"asset": f["asset"], "host": f["host"], "severity": f["sev"], "title": f["title"],
                      "open": bool(f["open"]), "found_at": fmt(f["created"])} for f in findings],
    }, ensure_ascii=False, indent=2)


_CSS = """
:root{--ink:#12263a;--mute:#5c7084;--line:#cfd9e1;--acc:#0f766e}
*{box-sizing:border-box}
body{margin:0;padding:32px;color:var(--ink);background:#fff;font:14px/1.5 Manrope,system-ui,-apple-system,"Segoe UI",sans-serif}
.doc{max-width:960px;margin:0 auto}
h1{margin:0 0 4px;font-size:26px}h2{margin:32px 0 10px;font-size:17px}
.meta{color:var(--mute);margin:0 0 24px}
.sum{display:flex;gap:28px;flex-wrap:wrap;align-items:flex-end;margin:0 0 8px}
.big{font-size:56px;font-weight:800;line-height:1}.big small{font-size:16px;font-weight:500;color:var(--mute)}
.sev{border-left:3px solid var(--c);padding-left:10px}.sev b{display:block;font-size:22px}.sev span{color:var(--mute);font-size:12px}
table{width:100%;border-collapse:collapse;margin:0 0 8px}
th{text-align:left;color:var(--mute);font-weight:500;font-size:12px;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
td.sv{font-weight:700;white-space:nowrap;color:var(--c)}
tr.done td{opacity:.55;text-decoration:line-through}
.empty{color:var(--mute);padding:10px 0}
.note{margin-top:32px;padding:10px 14px;border-left:3px solid var(--acc);background:#eef7f6;font-size:13px}
button.print{float:right;border:1px solid var(--line);background:#fff;padding:8px 14px;border-radius:8px;cursor:pointer;font:inherit;font-weight:700}
@media print{button.print{display:none}body{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _e(v):
    return html.escape(str(v), quote=True)


def to_html(user, scope, assets, findings):
    open_f = [f for f in findings if f["open"]]
    cnt = {s: sum(1 for f in open_f if f["sev"] == s) for s in ORDER}

    def worst(aid):
        mine = [f for f in open_f if f["aid"] == aid]
        for s in ORDER:
            if any(f["sev"] == s for f in mine):
                return f'<td class="sv" style="--c:{COL[s]}">{NAME[s]}</td>'
        return '<td class="sv" style="--c:#1b8a5a">Sạch</td>'

    arows = "".join(
        f'<tr><td><b>{_e(a["name"])}</b></td><td>{KIND.get(a["kind"], _e(a["kind"]))}</td><td>{a["hosts"]}</td>'
        f'<td>{sum(1 for f in open_f if f["aid"] == a["id"])}</td>{worst(a["id"])}'
        f'<td>{SCAN.get(a["scan_status"], "Chưa quét")}'
        f'{" · " + fmt(a["scan_finished"]) if a["scan_finished"] else ""}</td></tr>'
        for a in assets) or '<tr><td colspan="6" class="empty">Không có tài sản.</td></tr>'

    sections = ""
    for a in assets:
        mine = [f for f in findings if f["aid"] == a["id"]]
        if not mine:
            continue
        rows = "".join(
            f'<tr class="{"" if f["open"] else "done"}"><td class="sv" style="--c:{COL.get(f["sev"], "#000")}">'
            f'{NAME.get(f["sev"], _e(f["sev"]))}</td><td>{_e(f["title"])}</td><td>{_e(f["host"])}</td>'
            f'<td>{fmt(f["created"])}</td><td>{"Đang mở" if f["open"] else "Đã xử lý"}</td></tr>'
            for f in mine)
        sections += (f'<h2>Phát hiện: {_e(a["name"])}</h2><table><tr><th>Mức độ</th><th>Phát hiện</th>'
                     f'<th>Host</th><th>Thời gian</th><th>Trạng thái</th></tr>{rows}</table>')
    if not sections:
        sections = '<h2>Phát hiện</h2><p class="empty">Không có phát hiện nào trong phạm vi báo cáo.</p>'

    sevs = "".join(f'<div class="sev" style="--c:{COL[s]}"><b>{cnt[s]}</b><span>{NAME[s]}</span></div>' for s in ORDER)
    return f"""<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Báo cáo Lantern - {_e(scope)}</title><style>{_CSS}</style></head>
<body><div class="doc">
<button class="print" onclick="window.print()">In / Lưu PDF</button>
<h1>Báo cáo bề mặt tấn công</h1>
<p class="meta">Phạm vi: <b>{_e(scope)}</b> · Tạo lúc {fmt(time.time())} · Người xuất: {_e(user["username"])}</p>
<div class="sum"><div class="big">{score(findings)}<small> /100</small></div>{sevs}</div>
<p class="meta">{len(open_f)} phát hiện đang mở trên {len(assets)} tài sản.</p>
<h2>Tài sản</h2>
<table><tr><th>Tài sản</th><th>Loại</th><th>Host đang thấy</th><th>Phát hiện mở</th><th>Mức cao nhất</th><th>Lần quét gần nhất</th></tr>{arows}</table>
{sections}
<div class="note">Chỉ quét tài sản bạn sở hữu hoặc được phép kiểm tra bằng văn bản.</div>
</div></body></html>"""
