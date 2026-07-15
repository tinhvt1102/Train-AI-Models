import time
import re
import os
import sys
import csv
import io
import math
from datetime import datetime
from collections import deque

# Cho phép import f8_bridge.py ở thư mục gốc project (ML_POSTGRE_DEMO/), bất kể
# script này được chạy từ đâu (script luôn biết vị trí thật của chính nó qua __file__).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from f8_bridge import RowcountTailer  # noqa: E402

# Đường dẫn mặc định của file log PostgreSQL
LOG_FILE = "/var/log/postgresql/postgresql-18-main.log"
BASELINE_CSV = "baseline_features.csv"

# Cửa sổ trượt lưu trữ log trong tối đa 120 giây
sliding_window = deque()

# user -> (statement_id, event_ref) — gộp các dòng audit trùng statement_id
# (xem giải thích trong parse_audit_line)
_last_statement = {}

# Tailer riêng cho tiến trình này — đọc file side-channel rowcount_events.jsonl
# để lấy f8 (số dòng dữ liệu THẬT bị ảnh hưởng bởi mỗi câu lệnh ghi). Xem
# f8_bridge.py để biết vì sao cần cơ chế file thay vì dict trong bộ nhớ (script
# này và warmup_generator.py chạy ở 2 TIẾN TRÌNH riêng biệt).
_rowcount_tailer = RowcountTailer()


def parse_audit_line(line):
    """Hàm bóc tách dữ liệu từ một dòng log của pgAudit.

    Format chuẩn pgAudit (sau AUDIT_TYPE="SESSION,"):
        STATEMENT_ID, SUBSTATEMENT_ID, CLASS, COMMAND, OBJECT_TYPE,
        OBJECT_NAME, STATEMENT, PARAMETER
    (https://github.com/pgaudit/pgaudit)

    LƯU Ý: STATEMENT được trích dẫn bằng dấu " " và có thể chứa dấu phẩy bên
    trong câu SQL (vd "SELECT name, email FROM customer"). Dùng .split(",")
    thô sẽ làm lệch toàn bộ cột phía sau -> lấy sai action/table (đây là bug
    cũ khiến toàn bộ baseline_features.csv bị sai, đặc biệt f6_write_ratio
    luôn = 0 dù có UPDATE/DELETE thật). Dùng module csv để tách đúng chuẩn.
    """
    if "AUDIT: SESSION" not in line:
        return None

    try:
        pid_user_match = re.search(r'\[(\d+)\] (\w+)@', line)
        pid = pid_user_match.group(1) if pid_user_match else "0"
        user = pid_user_match.group(2) if pid_user_match else "unknown"

        raw_fields = line.split("AUDIT: SESSION,", 1)[1].rstrip("\n")
        parts = next(csv.reader(io.StringIO(raw_fields)))
        if len(parts) < 6:
            return None

        statement_id = parts[0].strip()  # STATEMENT_ID: pgAudit có thể ghi NHIỀU dòng
                                          # audit cho CÙNG 1 statement khi nó đụng nhiều
                                          # class quyền (vd UPDATE ... WHERE id = (SELECT
                                          # ...) sinh 2 dòng: WRITE/UPDATE + READ/SELECT,
                                          # cùng statement_id) -> việc gộp theo statement_id
                                          # được xử lý ở tail_log_file (nơi gọi hàm này).
        action = parts[2].strip()        # CLASS: READ, WRITE, DDL, ...
        query_type = parts[3].strip()    # COMMAND: SELECT, UPDATE, DELETE...
        object_name = parts[5].strip()   # tên bảng đầy đủ, vd public.salary

        table_name = "unknown"
        if object_name:
            table_name = object_name.split(".")[-1]
        elif len(parts) > 6:
            table_match = re.search(r'FROM (\w+)|UPDATE (\w+)|INTO (\w+)|TABLE (\w+)', parts[6], re.IGNORECASE)
            if table_match:
                table_name = next((g for g in table_match.groups() if g is not None), "unknown")

        return {
            "timestamp": time.time(), # Gắn nhãn thời gian hiện tại lúc log sinh ra
            "user": user,
            "action": action,
            "query_type": query_type,
            "table": table_name,
            "statement_id": statement_id,
            "session_id": pid,  # PID của backend process -> định danh session, dùng để
                                 # tránh gộp nhầm statement_id trùng giữa CÁC SESSION KHÁC
                                 # NHAU (statement_id chỉ đếm trong phạm vi 1 session, nên
                                 # nếu user mở connection mới cho mỗi câu lệnh, MỌI câu đều
                                 # có statement_id=1 -> gộp theo user+stid không đủ).
            "rows_affected": 0,  # sẽ được điền qua f8_bridge nếu action là WRITE/DDL
        }
    except Exception as e:
        return None


def _attach_rowcount_if_write(event):
    """Nếu sự kiện (mới tạo hoặc vừa được nâng cấp) là WRITE/DDL và chưa có
    rows_affected, lấy rowcount THẬT từ side-channel (f8_bridge) — khớp FIFO
    theo user. Gọi đúng 1 lần cho mỗi sự kiện WRITE (xem lời gọi ở tail_log_file)."""
    if event["action"] in ("WRITE", "DDL") and event["rows_affected"] == 0:
        event["rows_affected"] = _rowcount_tailer.consume(event["user"], event["timestamp"])


def extract_features(current_time, user):
    """Tính toán 8 đặc trưng số học (f1 -> f8) dựa trên Sliding Window 120s"""

    # 1. Dọn dẹp Cửa sổ trượt: Bỏ đi những log đã cũ hơn 120 giây
    while sliding_window and sliding_window[0]['timestamp'] < current_time - 120:
        sliding_window.popleft()

    # Lọc các log thuộc về user hiện tại
    user_events = [e for e in sliding_window if e['user'] == user]

    # Chia sự kiện theo cửa sổ thời gian
    events_60s = [e for e in user_events if e['timestamp'] >= current_time - 60]
    events_120s = user_events
    events_prev_60s = [e for e in user_events if e['timestamp'] < current_time - 60]

    # Tính toán đặc trưng thời gian (f1, f2)
    now = datetime.now()
    hour_decimal = now.hour + now.minute / 60.0 + now.second / 3600.0
    f1 = math.sin(2 * math.pi * hour_decimal / 24.0)
    f2 = math.cos(2 * math.pi * hour_decimal / 24.0)

    # Tính toán tần suất và hành vi (f3, f4, f5)
    f3 = len(events_60s)
    f4 = len(events_120s)

    unique_tables = set(e['table'] for e in events_60s if e['table'] != 'unknown')
    f5 = len(unique_tables)

    # Tỷ lệ ghi (f6)
    writes_60s = sum(1 for e in events_60s if e['action'] in ['WRITE', 'DDL'])
    f6 = writes_60s / (f3 + 1) # Cộng 1 để tránh lỗi chia cho 0

    # Chênh lệch tốc độ truy vấn (f7)
    f7 = f3 - len(events_prev_60s)

    # f8: quy mô dữ liệu THẬT bị ảnh hưởng bởi các lệnh ghi trong 60s gần nhất.
    # Đây là đặc trưng KHÔNG có trong 7 chiều cũ — bù cho việc log pgAudit không
    # ghi rowcount, khiến model cũ không phân biệt được "xóa 5 dòng có điều kiện"
    # (KB3a) với "xóa toàn bộ bảng" (KB3b) khi số SỰ KIỆN trong cửa sổ giống nhau.
    # Dùng log1p() để nén giá trị lớn (vd xóa hàng trăm dòng) lại gần thang đo
    # của các đặc trưng khác, tránh 1 lệnh xóa cực lớn làm méo toàn bộ vector.
    rows_60s = sum(e.get('rows_affected', 0) for e in events_60s if e['action'] in ['WRITE', 'DDL'])
    f8 = math.log1p(rows_60s)

    return [f1, f2, f3, f4, f5, f6, f7, f8]


def tail_log_file(filepath):
    """Đọc file log theo thời gian thực và trích xuất vector đặc trưng.

    Có phát hiện log rotation: nếu PostgreSQL restart hoặc log bị xoay vòng
    (file bị đổi tên/tạo mới), file handle cũ sẽ không còn nhận dòng mới ->
    chương trình "đứng yên" mãi mãi mà không báo lỗi. Ở đây kiểm tra inode
    định kỳ để tự mở lại file mới khi phát hiện rotation.
    """
    if not os.path.exists(filepath):
        return print(f"[LỖI] Không tìm thấy file log tại: {filepath}")

    print(f"[*] Đang theo dõi trực tiếp file log: {filepath}")
    print("[*] Đang tính toán Feature Engineering (f1 -> f8)...")
    print("-" * 75)

    f = open(filepath, 'r')
    f.seek(0, os.SEEK_END)
    inode = os.stat(filepath).st_ino
    last_check = time.time()

    while True:
        # Mỗi ~2s kiểm tra xem file có bị rotate không (đổi inode, hoặc bị xóa)
        now = time.time()
        if now - last_check > 2:
            last_check = now
            try:
                current_inode = os.stat(filepath).st_ino
                if current_inode != inode:
                    print(f"\n[⚠️ ] Phát hiện log rotation / PostgreSQL restart -> đang mở lại file mới: {filepath}\n")
                    f.close()
                    f = open(filepath, 'r')
                    inode = current_inode
            except FileNotFoundError:
                print(f"\n[⚠️ ] File log tạm thời biến mất (đang rotate?), thử lại sau 1s...\n")
                time.sleep(1)
                continue

        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue

        parsed_data = parse_audit_line(line)
        if parsed_data:
            user = parsed_data['user']
            stid = parsed_data['statement_id']
            sid = parsed_data['session_id']
            prev = _last_statement.get(user)

            if prev is not None and prev[0] == (sid, stid):
                # Trùng statement_id với dòng ngay trước -> cùng 1 câu SQL, chỉ nâng cấp
                # phân loại lên WRITE/DDL nếu cần, KHÔNG thêm sự kiện/ghi CSV lần nữa.
                existing_event = prev[1]
                if parsed_data['action'] in ('WRITE', 'DDL') and existing_event['action'] not in ('WRITE', 'DDL'):
                    existing_event['action'] = parsed_data['action']
                    _attach_rowcount_if_write(existing_event)  # vừa nâng cấp lên WRITE -> lấy rowcount ngay
                continue

            # Đưa log mới vào cửa sổ trượt
            sliding_window.append(parsed_data)
            _last_statement[user] = ((sid, stid), parsed_data)
            _attach_rowcount_if_write(parsed_data)  # nếu sự kiện MỚI đã là WRITE/DDL ngay từ đầu

            # Tính toán ngay 8 đặc trưng
            features = extract_features(parsed_data['timestamp'], parsed_data['user'])

            # In ra màn hình ma trận Vector
            f_str = ", ".join([f"{val:.2f}" for val in features])
            print(f"[VECTOR] User: {parsed_data['user'].ljust(12)} | Đặc trưng (f1->f8): [{f_str}]")

            # Lưu ra file CSV làm Baseline cho Mô hình ML (Giai đoạn 3)
            with open(BASELINE_CSV, 'a') as csv_file:
                csv_file.write(f"{parsed_data['user']},{','.join(map(str, features))}\n")

if __name__ == "__main__":
    print("=== KHỞI ĐỘNG HỆ THỐNG FEATURE ENGINEERING ===")
    print("Nhấn Ctrl+C để thoát.\n")
    try:
        # Tạo file CSV với Header nếu chưa có
        if not os.path.exists(BASELINE_CSV):
            with open(BASELINE_CSV, 'w') as f:
                f.write("user,f1_time_sin,f2_time_cos,f3_q60,f4_q120,f5_tables,f6_write_ratio,f7_speed_diff,f8_rows_affected\n")
        tail_log_file(LOG_FILE)
    except KeyboardInterrupt:
        print("\n=== ĐÃ DỪNG HỆ THỐNG ===")
