"""
f8_bridge.py
============
Side-channel dùng chung để mang thông tin "số dòng dữ liệu thực sự bị ảnh hưởng"
(rows affected — lấy từ cur.rowcount có sẵn của psycopg2, KHÔNG cần parse gì thêm)
từ nơi THỰC THI câu lệnh ghi sang nơi ĐỌC LOG pgAudit để tính đặc trưng f8.

TẠI SAO CẦN FILE RIÊNG NÀY (không chỉ dùng 1 dict trong bộ nhớ)?
-----------------------------------------------------------------
Có 2 cặp (bên ghi <-> bên đọc) trong project, và chúng KHÔNG chạy cùng 1 kiểu:

  1. attack_scenarios.py <-> realtime_engine.py
     Cả 2 chạy CHUNG 1 tiến trình Python (Streamlit), khác thread.
     -> 1 dict trong bộ nhớ + threading.Lock là đủ.

  2. warmup_generator.py <-> log_parser.py
     Theo README, đây LÀ 2 tiến trình Python HOÀN TOÀN KHÁC NHAU, chạy ở 2
     terminal riêng biệt (xem RETRAIN_HUONG_DAN.md bước 2). Một dict trong bộ
     nhớ của tiến trình A sẽ KHÔNG bao giờ nhìn thấy được từ tiến trình B.

Để không phải viết 2 cơ chế IPC khác nhau cho 2 trường hợp trên, ta dùng CHUNG
một cách đơn giản và đã quen thuộc với project này: một **file JSONL append-only**
làm hàng đợi, và bên đọc **tail** file này giống hệt cách log_parser.py /
realtime_engine.py đã tail file log pgAudit (bao gồm cả xử lý inode/rotation).
Cách này hoạt động đúng dù 2 bên là 2 thread hay 2 tiến trình hệ điều hành khác nhau.

LUỒNG HOẠT ĐỘNG
----------------
1. Ngay sau mỗi `cur.execute(...)` GHI (UPDATE/DELETE/INSERT), bên ghi gọi
   `record_rowcount(user, cur.rowcount, table=...)` — ghi 1 dòng JSON vào file.
   (Gọi TRƯỚC khi commit/rollback — `cur.rowcount` vẫn đúng dù sau đó rollback,
   vì thuộc tính này phản ánh kết quả của lệnh vừa chạy, không phụ thuộc việc
   transaction có được giữ lại hay không.)
2. Bên đọc log, khi merge được 1 sự kiện AUDIT có action cuối cùng là WRITE/DDL,
   gọi `tailer.consume(user, event_timestamp)` để lấy rowcount tương ứng, dùng
   kiểu HÀNG ĐỢI FIFO theo từng user riêng (không dùng "khớp gần nhất theo thời
   gian") — vì các câu lệnh ghi của CÙNG 1 user luôn thực thi tuần tự trên cùng
   1 kết nối trong toàn bộ code hiện tại (attack_scenarios.py, warmup_generator.py
   đều mở 1 connection rồi execute() lần lượt), nên thứ tự ghi rowcount và thứ tự
   audit-log xuất hiện luôn khớp nhau theo đúng thứ tự — FIFO là lựa chọn AN TOÀN
   NHẤT, tránh việc "khớp theo khoảng cách thời gian gần nhất" có thể gán nhầm
   rowcount giữa 2 lệnh ghi liên tiếp cách nhau rất gần (vd 30 UPDATE của KB4,
   mỗi lệnh cách nhau 0.1s).
"""

import json
import os
import time

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
ROWCOUNT_FILE = os.path.join(_MODULE_DIR, "rowcount_events.jsonl")

# Entry chờ khớp quá lâu (vd bên đọc chưa khởi động, hoặc bị lệch đồng bộ do lỗi
# nào đó) sẽ bị dọn bỏ sau ngần này giây, tránh phình bộ nhớ vô hạn.
MAX_PENDING_AGE = 30.0


def record_rowcount(user, rowcount, table=None):
    """Gọi NGAY SAU mỗi cur.execute() của một câu lệnh GHI (UPDATE/DELETE/INSERT).

    rowcount: lấy trực tiếp từ cur.rowcount (built-in của psycopg2) — số dòng
    THẬT bị ảnh hưởng bởi câu lệnh, không phải ước lượng.
    """
    entry = {"ts": time.time(), "user": user, "rowcount": int(rowcount), "table": table}
    try:
        with open(ROWCOUNT_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # Side-channel là tính năng "cộng thêm" (f8) — nếu ghi lỗi (vd hết dung
        # lượng đĩa), KHÔNG được làm crash luồng ghi dữ liệu thật vào PostgreSQL.
        pass


class RowcountTailer:
    """Tail file rowcount_events.jsonl để lấy rowcount khớp với 1 sự kiện WRITE
    vừa đọc được từ log pgAudit.

    MỖI bên đọc (log_parser.py, realtime_engine.py) PHẢI tạo RIÊNG 1 instance —
    mỗi instance giữ 1 con trỏ đọc (offset) độc lập, giống hệt cách mỗi bên tự
    tail file log pgAudit của riêng mình. Dùng chung 1 instance giữa 2 tiến
    trình là KHÔNG THỂ (mỗi tiến trình có bộ nhớ riêng) — đây là điều file này
    được thiết kế để không cần tới.
    """

    def __init__(self):
        self._pending = {}  # user -> list[{"ts", "rowcount", "table"}], FIFO theo từng user
        self._fh = None
        self._inode = None

    def _ensure_open(self):
        if not os.path.exists(ROWCOUNT_FILE):
            return False
        try:
            current_inode = os.stat(ROWCOUNT_FILE).st_ino
        except FileNotFoundError:
            return False

        if self._fh is None:
            self._fh = open(ROWCOUNT_FILE, "r")
            # CHỦ Ý KHÔNG seek(0, SEEK_END) ở đây (khác với cách log_parser /
            # realtime_engine mở file log pgAudit) — đã từng thử và phát hiện bug
            # qua mô phỏng: consume() (và do đó _ensure_open() lần đầu) chỉ được
            # gọi khi gặp sự kiện WRITE ĐẦU TIÊN, tức là SAU KHI record_rowcount()
            # đã ghi entry vào file. Nếu seek-to-end lúc mở lần đầu, entry đó nằm
            # TRƯỚC con trỏ -> bị bỏ lỡ vĩnh viễn (rows_affected=0 sai). Đọc từ đầu
            # file, dựa vào lọc theo tuổi (MAX_PENDING_AGE, xem poll()) để loại
            # entry rác cũ từ các lần demo trước — an toàn hơn seek-to-end.
            self._inode = current_inode
        elif current_inode != self._inode:
            # File bị xóa/tạo lại (vd dọn dẹp thủ công) -> mở lại từ đầu tiến trình mới.
            self._fh.close()
            self._fh = open(ROWCOUNT_FILE, "r")
            self._inode = current_inode
        return True

    def poll(self):
        """Đọc mọi dòng mới xuất hiện kể từ lần poll() trước, đẩy vào hàng đợi
        theo user. Nên gọi hàm này thường xuyên trong vòng lặp tail chính."""
        if not self._ensure_open():
            return
        while True:
            line = self._fh.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            user = entry.get("user", "unknown")
            self._pending.setdefault(user, []).append(entry)

        # Dọn entry chờ quá lâu chưa được khớp (tránh rò rỉ bộ nhớ nếu số lượng
        # audit-line WRITE và số lần record_rowcount() bị lệch nhau vì lý do gì đó).
        now = time.time()
        for user in list(self._pending.keys()):
            self._pending[user] = [e for e in self._pending[user] if now - e["ts"] < MAX_PENDING_AGE]
            if not self._pending[user]:
                del self._pending[user]

    def consume(self, user, event_time=None):
        """Lấy (và loại khỏi hàng đợi) rowcount CŨ NHẤT đang chờ của user này —
        FIFO. Trả về 0 nếu không có entry nào đang chờ (vd baseline cũ chưa ghi
        rowcount, hoặc log_parser/realtime_engine khởi động sau khi ghi đã xảy ra
        quá MAX_PENDING_AGE giây)."""
        self.poll()
        queue = self._pending.get(user)
        if not queue:
            return 0
        entry = queue.pop(0)
        if not queue:
            del self._pending[user]
        return entry["rowcount"]
