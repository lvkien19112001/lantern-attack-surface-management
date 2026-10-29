r"""Chạy Lantern ở chế độ nền (không cửa sổ console) - dùng cho tự khởi động cùng Windows.

    .venv\Scripts\pythonw.exe serve.py        (không hiện cửa sổ)
    .venv\Scripts\python.exe  serve.py        (xem log ngay trên màn hình)

Server (kèm bộ lập lịch quét) chạy liên tục ở nền; mở trình duyệt vào http://127.0.0.1:8000 bất cứ lúc nào
để xem kết quả các lần quét tự động đã chạy. Log ghi vào lantern.log cạnh file này.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# pythonw.exe không có stdout/stderr -> chuyển hết vào file log (và cắt bớt khi quá lớn)
if sys.stdout is None or sys.stderr is None or not sys.stdout.isatty():
    log = ROOT / "lantern.log"
    if log.exists() and log.stat().st_size > 5 * 1024 * 1024:
        log.write_text("", encoding="utf-8")
    sys.stdout = sys.stderr = open(log, "a", buffering=1, encoding="utf-8")

import uvicorn  # noqa: E402

if __name__ == "__main__":
    # Chỉ 1 worker (bộ lập lịch nằm trong tiến trình server), không dùng --reload
    uvicorn.run("app.main:app", host=os.getenv("LANTERN_HOST", "127.0.0.1"),
                port=int(os.getenv("LANTERN_PORT", "8000")), log_level="info", use_colors=False)
