"""
realtime_engine.py
===================
Cầu nối THẬT giữa pgAudit log <-> Feature Engineering (giai đoạn 2) <-> AI Model (giai đoạn 3).

Trước đây app.py dùng generate_live_data() sinh vector ngẫu nhiên (np.random) -> đó là lý do
biểu đồ "nhảy tùm lum" không liên quan gì tới việc bấm nút tấn công.

Module này:
  1. Tự tìm file log pgAudit đang active trong /var/log/postgresql/
  2. Tail log theo thời gian thực (giống log_parser.py giai đoạn 2)
  3. Với MỖI dòng AUDIT thật, tính vector 7 đặc trưng (f1->f7) bằng đúng công thức đã dùng lúc train
  4. Chạy model.decision_function() TRÊN CHÍNH sự kiện đó ngay lập tức
  5. Lưu kết quả vào một hàng đợi thread-safe để Streamlit (app.py) đọc và vẽ

Vì đây chạy trên 1 thread nền độc lập với vòng lặp render của Streamlit, dữ liệu được
bảo vệ bằng threading.Lock — không dùng st.session_state trong thread nền (không an toàn).
"""

import csv
import glob
import io
import math
import os
import re
import sys
import threading
import time
from collections import deque
from datetime import datetime

import numpy as np

# Cho phép import f8_bridge.py ở thư mục gốc project (ML_POSTGRE_DEMO/).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from f8_bridge import RowcountTailer  # noqa: E402

# ------------------------------------------------------------------
# Cấu hình
# ------------------------------------------------------------------
LOG_DIR = "/var/log/postgresql"
LOG_GLOB_PATTERNS = ["postgresql-*-main.log", "postgresql-*.log", "*.log"]
SLIDING_WINDOW_SECONDS = 120
MAX_HISTORY = 50          # số điểm giữ lại cho biểu đồ
MAX_ALERTS = 20           # số dòng giữ lại cho bảng cảnh báo

FEATURE_COLUMNS = [
    "f1_time_sin", "f2_time_cos", "f3_q60", "f4_q120",
    "f5_tables", "f6_write_ratio", "f7_speed_diff", "f8_rows_affected",
]

# ------------------------------------------------------------------
# Rule-based override cho VÙNG DỮ LIỆU THƯA (f3 <= 2 sự kiện/60s).
# LÝ DO: Isolation Forest không phản ứng đơn điệu (monotonic) khi cửa sổ trượt
# chỉ có 1-2 sự kiện — đã xác nhận qua test thật: xóa NHIỀU dòng hơn (KB3b, vd
# 130 dòng) lại ra điểm THẤP HƠN xóa ÍT dòng (KB3a, 5 dòng), dù về bản chất
# nguy hiểm hơn. Đây là giới hạn cấu trúc của model ở vùng thưa, không phải bug
# feature engineering. Giải pháp: khi sự kiện quá thưa để tin score model, dùng
# trực tiếp f8 (quy mô dữ liệu THẬT bị ảnh hưởng) làm luật quyết định thay thế.
# Ngưỡng lấy nhất quán với REF_F8_NORMAL trong app.py (f8=2.0 ~ 6 dòng).
SPARSE_F3_MAX = 2            # f3 <= ngưỡng này coi là "cửa sổ thưa"
SPARSE_WARNING_CAP_F8 = 2.0  # f8 <= ngưỡng này (~6 dòng) -> cap về WARNING dù model nói Critical
SPARSE_CRITICAL_FLOOR_F8 = 3.5  # f8 >= ngưỡng này (~32 dòng) -> ép về CRITICAL dù model nói thấp hơn


def find_log_file():
    """Tự động tìm file log pgAudit đang được ghi mới nhất (không hardcode version PG)."""
    for pattern in LOG_GLOB_PATTERNS:
        candidates = glob.glob(os.path.join(LOG_DIR, pattern))
        if candidates:
            # Lấy file được ghi/sửa gần đây nhất -> chắc chắn là log đang active
            return max(candidates, key=os.path.getmtime)
    return None


def parse_audit_line(line):
    """Bóc tách một dòng log pgAudit. Trả về None nếu không phải dòng AUDIT.

    Format chuẩn pgAudit (sau khi bỏ AUDIT_TYPE="SESSION," ở đầu):
        STATEMENT_ID, SUBSTATEMENT_ID, CLASS, COMMAND, OBJECT_TYPE,
        OBJECT_NAME, STATEMENT, PARAMETER
    (Tham khảo: https://github.com/pgaudit/pgaudit)

    QUAN TRỌNG: STATEMENT là field được trích dẫn bằng dấu " " và có thể chứa
    dấu phẩy bên trong câu SQL (vd: "SELECT name, email FROM customer").
    Dùng .split(",") thô sẽ làm lệch toàn bộ vị trí cột phía sau -> lấy sai
    action/table (đây chính là bug cũ khiến bảng luôn hiện "unknown" hoặc
    match nhầm). Ở đây dùng module csv để tách đúng, tôn trọng dấu ngoặc kép.
    """
    if "AUDIT: SESSION" not in line:
        return None
    try:
        pid_user_match = re.search(r"\[(\d+)\] (\w+)@", line)
        pid = pid_user_match.group(1) if pid_user_match else "0"
        user = pid_user_match.group(2) if pid_user_match else "unknown"

        raw_fields = line.split("AUDIT: SESSION,", 1)[1].rstrip("\n")
        # csv.reader tách đúng theo chuẩn CSV, không bị vỡ bởi dấu phẩy trong STATEMENT
        parts = next(csv.reader(io.StringIO(raw_fields)))

        if len(parts) < 6:
            return None

        statement_id = parts[0].strip()    # STATEMENT_ID: pgAudit có thể ghi NHIỀU dòng
                                             # audit cho CÙNG 1 statement_id khi statement đó
                                             # đụng tới nhiều class quyền khác nhau — ví dụ
                                             # UPDATE customer SET ... WHERE id = (SELECT ...)
                                             # sinh ra 2 dòng: 1 dòng WRITE/UPDATE (ghi bảng)
                                             # và 1 dòng READ/SELECT (đọc bảng để đánh giá
                                             # subquery trong WHERE) — CẢ HAI CÙNG statement_id.
                                             # Nếu đếm cả 2 dòng, 1 hành động ghi DUY NHẤT sẽ
                                             # bị tính thành 2 sự kiện (1 WRITE + 1 READ giả),
                                             # làm méo f3/f6 — đây là nguyên nhân KB3a bị đẩy
                                             # Critical sai và KB4 bị pha loãng f6 xuống ~50%.
                                             # -> việc gộp theo statement_id được xử lý ở tầng
                                             # ingest (nơi gọi hàm này), không phải ở đây.

        action = parts[2].strip()          # CLASS: READ, WRITE, DDL, ROLE, ...
        query_type = parts[3].strip()      # COMMAND: SELECT, UPDATE, DELETE, ...
        object_type = parts[4].strip()     # TABLE, VIEW, ...
        object_name = parts[5].strip()     # tên bảng đầy đủ, vd public.salary

        table_name = "unknown"
        if object_name:
            # Bỏ tiền tố schema (vd "public.salary" -> "salary")
            table_name = object_name.split(".")[-1]
        elif len(parts) > 6:
            # Fallback: một số câu lệnh (DO block, VALUES...) không có OBJECT_NAME,
            # thử regex trên STATEMENT gốc như phương án dự phòng.
            statement_text = parts[6]
            table_match = re.search(
                r"FROM (\w+)|UPDATE (\w+)|INTO (\w+)|TABLE (\w+)", statement_text, re.IGNORECASE
            )
            if table_match:
                table_name = next((g for g in table_match.groups() if g is not None), "unknown")

        return {
            "timestamp": time.time(),
            "user": user,
            "action": action,
            "query_type": query_type,
            "object_type": object_type,
            "table": table_name,
            "statement_id": statement_id,
            "session_id": pid,  # PID backend -> định danh session, tránh gộp nhầm statement_id
                                 # trùng giữa CÁC SESSION KHÁC NHAU của cùng 1 user (statement_id
                                 # chỉ đếm trong phạm vi 1 session, reset về 1 mỗi connection mới).
            "rows_affected": 0,  # sẽ được điền qua f8_bridge nếu action là WRITE/DDL
        }
    except Exception:
        return None


class RealtimeEngine:
    """Chạy nền: tail log thật -> feature engineering thật -> inference thật."""

    def __init__(self, model, thresholds):
        self.model = model
        self.warning_th = thresholds["warning"]
        self.critical_th = thresholds["critical"]

        self._lock = threading.Lock()
        self._sliding_window = deque()          # log sự kiện gần đây (mọi user)
        self._last_statement = {}               # user -> (statement_id, event_ref) — dùng
                                                 # để gộp các dòng audit trùng statement_id
                                                 # (xem giải thích trong parse_audit_line)
        self._rowcount_tailer = RowcountTailer()  # đọc side-channel rowcount_events.jsonl
                                                    # cho f8 — xem f8_bridge.py
        self.history_scores = deque(maxlen=MAX_HISTORY)
        self.alerts = deque(maxlen=MAX_ALERTS)   # cảnh báo Warning/Critical gần nhất
        self.last_event = None                   # sự kiện + điểm số gần nhất (mọi mức)

        self.status_message = "Đang khởi động..."
        self._started = False
        self._thread = None

    # ---------------- Feature engineering (đúng công thức giai đoạn 2) ----------------
    def _extract_features(self, current_time, user):
        while self._sliding_window and self._sliding_window[0]["timestamp"] < current_time - SLIDING_WINDOW_SECONDS:
            self._sliding_window.popleft()

        user_events = [e for e in self._sliding_window if e["user"] == user]
        events_60s = [e for e in user_events if e["timestamp"] >= current_time - 60]
        events_prev_60s = [e for e in user_events if e["timestamp"] < current_time - 60]

        now = datetime.now()
        hour_decimal = now.hour + now.minute / 60.0 + now.second / 3600.0
        f1 = math.sin(2 * math.pi * hour_decimal / 24.0)
        f2 = math.cos(2 * math.pi * hour_decimal / 24.0)

        f3 = len(events_60s)
        f4 = len(user_events)
        f5 = len({e["table"] for e in events_60s if e["table"] != "unknown"})
        writes_60s = sum(1 for e in events_60s if e["action"] in ["WRITE", "DDL"])
        f6 = writes_60s / (f3 + 1)
        f7 = f3 - len(events_prev_60s)

        # f8: quy mô dữ liệu THẬT bị ảnh hưởng bởi các lệnh ghi trong 60s gần nhất
        # (rows_affected lấy từ cur.rowcount qua side-channel f8_bridge, vì pgAudit
        # không ghi rowcount trong log). log1p() để nén giá trị lớn, cùng thang đo
        # với các đặc trưng khác — xem giải thích chi tiết trong log_parser.py.
        rows_60s = sum(e.get("rows_affected", 0) for e in events_60s if e["action"] in ["WRITE", "DDL"])
        f8 = math.log1p(rows_60s)

        return [f1, f2, f3, f4, f5, f6, f7, f8]

    def _attach_rowcount_if_write(self, event):
        """Nếu sự kiện là WRITE/DDL và chưa có rows_affected, lấy rowcount THẬT
        từ side-channel (khớp FIFO theo user). PHẢI gọi trong lúc đang giữ self._lock
        (xem các lời gọi trong _tail_loop)."""
        if event["action"] in ("WRITE", "DDL") and event["rows_affected"] == 0:
            event["rows_affected"] = self._rowcount_tailer.consume(event["user"], event["timestamp"])

    # ---------------- Vòng lặp tail log nền ----------------
    def _tail_loop(self):
        log_path = find_log_file()
        if not log_path:
            with self._lock:
                self.status_message = f"❌ Không tìm thấy file log trong {LOG_DIR}. Kiểm tra pgAudit đã cấu hình ghi log chưa."
            return

        with self._lock:
            self.status_message = f"🟢 Đang theo dõi log thật: {log_path}"

        f = open(log_path, "r")
        f.seek(0, os.SEEK_END)
        inode = os.stat(log_path).st_ino

        while True:
            # Phát hiện xoay vòng log (log rotation) của PostgreSQL
            try:
                if os.stat(log_path).st_ino != inode:
                    f.close()
                    f = open(log_path, "r")
                    inode = os.stat(log_path).st_ino
            except FileNotFoundError:
                new_path = find_log_file()
                if new_path and new_path != log_path:
                    log_path = new_path
                    f.close()
                    f = open(log_path, "r")
                    inode = os.stat(log_path).st_ino
                time.sleep(0.5)
                continue

            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            parsed = parse_audit_line(line)
            if not parsed:
                continue

            with self._lock:
                user = parsed["user"]
                stid = parsed["statement_id"]
                sid = parsed["session_id"]
                prev = self._last_statement.get(user)

                if prev is not None and prev[0] == (sid, stid):
                    # Cùng statement_id với dòng audit ngay trước đó của user này ->
                    # đây là 2 dòng log cho CÙNG 1 câu SQL (vd WRITE + READ subquery).
                    # Không thêm sự kiện mới, không tính điểm/record mới -> tránh vừa
                    # đếm trùng vừa hiện 2 dòng cảnh báo cho 1 hành động thực tế.
                    # Chỉ nâng cấp phân loại lên WRITE/DDL nếu dòng mới cho biết
                    # statement này thực chất là ghi (phòng trường hợp thứ tự log
                    # đảo ngược so với thực tế đã quan sát WRITE luôn tới trước).
                    existing_event = prev[1]
                    if parsed["action"] in ("WRITE", "DDL") and existing_event["action"] not in ("WRITE", "DDL"):
                        existing_event["action"] = parsed["action"]
                        self._attach_rowcount_if_write(existing_event)  # vừa nâng cấp lên WRITE -> lấy rowcount ngay
                    continue

                self._sliding_window.append(parsed)
                self._last_statement[user] = ((sid, stid), parsed)
                self._attach_rowcount_if_write(parsed)  # nếu sự kiện MỚI đã là WRITE/DDL ngay từ đầu
                features = self._extract_features(parsed["timestamp"], user)

                raw_score = self.model.decision_function([features])[0]
                anomaly_score = float(-raw_score)  # càng cao càng bất thường

                if anomaly_score >= self.critical_th:
                    status, color = "🔴 CRITICAL RISK", "red"
                elif anomaly_score >= self.warning_th:
                    status, color = "🟠 WARNING", "orange"
                else:
                    status, color = "🟢 NORMAL", "green"

                # --- Rule-based override cho vùng dữ liệu thưa (xem giải thích ở đầu file) ---
                f3_cur, f8_cur = features[2], features[7]
                is_write_event = parsed["action"] in ("WRITE", "DDL")
                if is_write_event and f3_cur <= SPARSE_F3_MAX:
                    if f8_cur <= SPARSE_WARNING_CAP_F8 and status == "🔴 CRITICAL RISK":
                        status, color = "🟠 WARNING", "orange"
                        anomaly_score = min(anomaly_score, self.critical_th - 1e-4)
                    elif f8_cur >= SPARSE_CRITICAL_FLOOR_F8 and status != "🔴 CRITICAL RISK":
                        status, color = "🔴 CRITICAL RISK", "red"
                        anomaly_score = max(anomaly_score, self.critical_th)

                record = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "user": parsed["user"],
                    "action": f"{parsed['query_type']} trên bảng {parsed['table']}",
                    "score": round(anomaly_score, 4),
                    "status": status,
                    "color": color,
                    "features": features,
                }

                self.last_event = record
                self.history_scores.append(anomaly_score)
                if anomaly_score >= self.warning_th:
                    self.alerts.appendleft(record)

    def start(self):
        if self._started:
            return
        self._started = True
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()

    def snapshot(self):
        """Đọc trạng thái hiện tại một cách an toàn cho luồng UI (Streamlit)."""
        with self._lock:
            return {
                "status_message": self.status_message,
                "last_event": dict(self.last_event) if self.last_event else None,
                "history_scores": list(self.history_scores),
                "alerts": [dict(a) for a in self.alerts],
            }

    def reset_window(self, user=None):
        """Xóa sạch sliding window (và lịch sử hiển thị) để bắt đầu 1 kịch bản demo
        hoàn toàn sạch, không bị cộng dồn sự kiện từ kịch bản chạy trước đó.
        Nếu user=None thì xóa toàn bộ; nếu chỉ định user thì chỉ xóa sự kiện của user đó."""
        with self._lock:
            if user is None:
                self._sliding_window.clear()
                self.history_scores.clear()
                self.alerts.clear()
                self.last_event = None
                self._last_statement.clear()
                self._rowcount_tailer._pending.clear()
            else:
                self._sliding_window = deque(e for e in self._sliding_window if e["user"] != user)
                self._last_statement.pop(user, None)
                self._rowcount_tailer._pending.pop(user, None)


# Singleton dùng chung cho cả process (Streamlit re-run script nhiều lần,
# nhưng module chỉ được import 1 lần -> biến global này chỉ khởi tạo 1 lần)
_engine_instance = None
_engine_lock = threading.Lock()


def get_engine(model, thresholds):
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = RealtimeEngine(model, thresholds)
            _engine_instance.start()
        return _engine_instance
