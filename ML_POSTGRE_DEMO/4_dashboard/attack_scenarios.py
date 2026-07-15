"""
attack_scenarios.py
====================
Phiên bản nâng cấp theo góp ý của giảng viên:

  KB1 (cũ): chỉ SELECT * lặp lại -> nhìn giống backup bình thường, "đâu phải kịch bản".
  KB1 (mới): làm rõ RANH GIỚI NGHIỆP VỤ bị vi phạm — svc_backup chỉ được phép đọc
             một số bảng cố định (baseline), kịch bản này cho nó đọc thẳng vào
             các bảng TUYỆT ĐỐI không nằm trong phạm vi cho phép (salary, hr_notes...).

  KB2 (cũ): 2 bước dồn cục, không thấy rõ "chuỗi hành động".
  KB2 (mới): tách thành 4 giai đoạn kill-chain có nhãn rõ ràng, mỗi giai đoạn cập nhật
             trạng thái để Dashboard hiển thị: Trinh sát -> Brute-force -> Truy cập
             -> Bùng nổ trích xuất. Người xem thấy được TẦN SUẤT/MẬT ĐỘ tăng dần
             qua từng bước, khớp với f3 (tần suất 60s) và f7 (độ tăng tốc) trên AI.

  KB3 (cũ): 3 câu DELETE có mức độ ngang nhau -> không phân biệt được nguy hiểm hay cảnh báo.
  KB3 (mới): tách thành 2 kịch bản RIÊNG BIỆT:
       - 3a "Xóa hợp lệ" : có điều kiện WHERE rõ ràng, phạm vi nhỏ (giống một tác vụ
         dọn dẹp log cũ hợp pháp) -> kỳ vọng AI chỉ ở mức WARNING.
       - 3b "Xóa hàng loạt": không giới hạn phạm vi, xóa toàn bộ nhiều bảng cùng lúc
         -> kỳ vọng AI đẩy thẳng lên CRITICAL (f6 write-ratio ~1.0 + f5 nhiều bảng).

  KB4: giữ nguyên ý tưởng Ransomware nhưng thêm nhãn tiến trình từng bước.

Mỗi hàm cập nhật trạng thái qua set_status() để app.py hiển thị "đang ở bước nào"
ngay trên sidebar theo thời gian thực -- đây là phần "làm nổi bật quy trình xác định"
mà giảng viên yêu cầu.
"""

import os
import random
import sys
import threading
import time

import psycopg2

# Cho phép import f8_bridge.py ở thư mục gốc project (ML_POSTGRE_DEMO/).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from f8_bridge import record_rowcount  # noqa: E402

DB_CONFIG = {
    "dbname": "ml_postgre_demo",
    "host": "127.0.0.1",
    "port": "5432",
}

# ------------------------------------------------------------------
# Trạng thái tiến trình (thread-safe) để Dashboard hiển thị real-time
# ------------------------------------------------------------------
_status_lock = threading.Lock()
_status = {}


def set_status(key, text):
    with _status_lock:
        _status[key] = text


def get_status(key):
    with _status_lock:
        return _status.get(key, "")


# ------------------------------------------------------------------
# KB1 — svc_backup vi phạm ranh giới nghiệp vụ
# ------------------------------------------------------------------
# Phạm vi HỢP LỆ của svc_backup theo baseline: chỉ backup dữ liệu vận hành,
# không bao giờ đụng tới dữ liệu lương/nhân sự nhạy cảm.
ALLOWED_TABLES_SVC_BACKUP = ["employee", "customer", "session_logs"]
FORBIDDEN_TABLES_SVC_BACKUP = ["salary", "hr_notes", "contract"]


def run_scenario_1():
    """svc_backup đọc thẳng vào các bảng NGOÀI phạm vi cho phép — vi phạm rõ ràng,
    không phải một biến thể của hành vi backup bình thường."""
    set_status("kb1", "▶️ Bắt đầu: svc_backup cố truy cập bảng NGOÀI phạm vi cho phép...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="svc_backup", password="password123")
        conn.autocommit = True
        cur = conn.cursor()
        for round_i in range(6):
            for table in FORBIDDEN_TABLES_SVC_BACKUP:
                set_status(
                    "kb1",
                    f"🚫 [Vòng {round_i+1}/6] svc_backup SELECT * FROM {table} "
                    f"— bảng KHÔNG thuộc baseline cho phép của user này",
                )
                cur.execute(f"SELECT * FROM {table}")
                time.sleep(0.2)
        conn.close()
        set_status(
            "kb1",
            "✅ Hoàn tất. svc_backup đã đọc toàn bộ bảng nhạy cảm ngoài phạm vi "
            "→ vi phạm ranh giới nghiệp vụ, kỳ vọng AI cảnh báo do f5 (số bảng lạ) tăng.",
        )
    except Exception as e:
        set_status("kb1", f"❌ Lỗi: {e}")


# ------------------------------------------------------------------
# KB2 — Kill-chain 4 giai đoạn: Trinh sát -> Brute-force -> Truy cập -> Trích xuất
# ------------------------------------------------------------------
def run_scenario_2():
    # Giai đoạn 1: Trinh sát schema
    set_status("kb2", "[1/4] 🔍 Trinh sát: liệt kê danh sách bảng trong schema...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_02", password="password123")
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
        cur.fetchall()
        conn.close()
    except Exception:
        pass
    time.sleep(0.6)

    # Giai đoạn 2: Brute-force
    set_status("kb2", "[2/4] 🔑 Dò mật khẩu (brute-force) 5 lần liên tiếp...")
    for i in range(5):
        try:
            psycopg2.connect(**DB_CONFIG, user="staff_02", password=f"wrongpass{random.randint(1,99)}")
        except Exception:
            pass
        set_status("kb2", f"[2/4] 🔑 Dò mật khẩu... lần thử {i+1}/5")
        time.sleep(0.2)

    # Giai đoạn 3: Truy cập thành công, thăm dò nhẹ
    set_status("kb2", "[3/4] 🔓 Đăng nhập thành công! Đang truy vấn thăm dò ban đầu...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_02", password="password123")
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT name, email FROM customer LIMIT 5")
        time.sleep(0.6)

        # Giai đoạn 4: Bùng nổ trích xuất — tần suất/mật độ tăng vọt
        set_status("kb2", "[4/4] 💥 Bùng nổ trích xuất: 50 truy vấn liên tiếp trong vài giây...")
        for i in range(50):
            cur.execute("SELECT name, email FROM customer LIMIT 5")
            if i % 10 == 0:
                set_status("kb2", f"[4/4] 💥 Đang trích xuất... {i}/50 truy vấn (mật độ tăng nhanh)")
        conn.close()
        set_status(
            "kb2",
            "✅ Hoàn tất chuỗi tấn công: Trinh sát → Brute-force → Truy cập → Trích xuất ồ ạt. "
            "Kỳ vọng AI thấy f3/f7 (tần suất & độ tăng tốc) tăng dần qua từng giai đoạn.",
        )
    except Exception as e:
        set_status("kb2", f"❌ Lỗi: {e}")


# ------------------------------------------------------------------
# KB3a — Xóa HỢP LỆ (mục tiêu: WARNING, không phải CRITICAL)
# ------------------------------------------------------------------
def run_scenario_3a():
    """Thao tác dọn dẹp có điều kiện WHERE rõ ràng, phạm vi nhỏ — giống việc một
    nhân viên dọn log lỗi cũ theo đúng quy trình. Đây là hành vi CÓ THỂ LÝ GIẢI ĐƯỢC,
    chỉ nên ở mức cảnh báo nhẹ, không phải nguy hiểm.

    LƯU Ý: dùng transaction + ROLLBACK thay vì COMMIT. pgAudit vẫn ghi log đầy đủ
    câu lệnh dù transaction bị rollback (hành vi đã được xác nhận trong tài liệu
    chính thức của pgAudit) -> AI vẫn "thấy" đúng hành vi, nhưng dữ liệu KHÔNG bị
    xóa thật -> demo chạy lại bao nhiêu lần cũng không cần seed lại DB."""
    set_status("kb3a", "▶️ Bắt đầu: dọn dẹp log cũ hợp lệ (có điều kiện, phạm vi giới hạn)...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_03", password="password123")
        cur = conn.cursor()
        set_status("kb3a", "🟡 DELETE FROM session_logs WHERE status='FAILED' AND cũ hơn 90 ngày (giới hạn 5 dòng)")
        cur.execute(
            """
            DELETE FROM session_logs
            WHERE ctid IN (
                SELECT ctid FROM session_logs
                WHERE status = 'FAILED' AND login_time < NOW() - INTERVAL '90 days'
                LIMIT 5
            )
            """
        )
        # rowcount THẬT (built-in psycopg2) — lấy NGAY sau execute(), TRƯỚC rollback().
        # Đây chính là f8: số dòng dữ liệu thực sự bị ảnh hưởng, thứ mà log pgAudit
        # KHÔNG hề ghi lại -> phải lấy qua side-channel này (xem f8_bridge.py).
        record_rowcount("staff_03", cur.rowcount, table="session_logs")
        conn.rollback()  # log đã được pgAudit ghi nhận, nhưng dữ liệu được khôi phục
        conn.close()
        set_status(
            "kb3a",
            "✅ Hoàn tất. Xóa có điều kiện, phạm vi nhỏ, có lý do nghiệp vụ rõ ràng "
            "→ kỳ vọng AI chỉ ở mức WARNING (không phải Critical). ",
        )
    except Exception as e:
        set_status("kb3a", f"❌ Lỗi: {e}")


# ------------------------------------------------------------------
# KB3b — Xóa HÀNG LOẠT (mục tiêu: CRITICAL rõ ràng)
# ------------------------------------------------------------------
def run_scenario_3b():
    """Xóa KHÔNG có điều kiện giới hạn, trên nhiều bảng cùng lúc — không thể lý giải
    bằng nghiệp vụ thông thường. Đây phải là tín hiệu CRITICAL rõ ràng.

    Cũng dùng transaction + ROLLBACK: pgAudit vẫn ghi log "DELETE FROM ... không WHERE"
    y hệt như khi commit thật, nên AI vẫn đánh giá đúng mức độ nguy hiểm, nhưng bảng
    session_logs/contract không bị xóa vĩnh viễn."""
    set_status("kb3b", "▶️ 🔥 Bắt đầu XÓA HÀNG LOẠT: không giới hạn phạm vi, nhiều bảng...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_03", password="password123")
        cur = conn.cursor()
        tables_to_wipe = ["session_logs", "contract"]
        for t in tables_to_wipe:
            set_status("kb3b", f"🔥 DELETE FROM {t} — KHÔNG có điều kiện WHERE, xóa toàn bộ bảng")
            cur.execute(f"DELETE FROM {t}")
            # f8: rowcount THẬT của từng bảng bị xóa toàn bộ — thường LỚN HƠN NHIỀU
            # so với KB3a (xóa có LIMIT 5), đây chính là tín hiệu mà f1-f7 cũ không có.
            record_rowcount("staff_03", cur.rowcount, table=t)
            time.sleep(0.3)
        conn.rollback()
        conn.close()
        set_status(
            "kb3b",
            "✅ Hoàn tất. Xóa không giới hạn trên nhiều bảng cùng lúc "
            "→ kỳ vọng AI đẩy thẳng lên CRITICAL (f6 write-ratio cao + f5 nhiều bảng). ",
        )
    except Exception as e:
        set_status("kb3b", f"❌ Lỗi: {e}")


# ------------------------------------------------------------------
# KB4 — Ransomware (giữ ý tưởng gốc, thêm nhãn tiến trình)
# ------------------------------------------------------------------
def run_scenario_4():
    set_status("kb4", "▶️ ☢️ Bắt đầu RANSOMWARE: ghi đè dữ liệu khách hàng...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_02", password="password123")
        cur = conn.cursor()
        for i in range(30):
            cur.execute(
                "UPDATE customer SET email = md5(random()::text) "
                "WHERE id = (SELECT id FROM customer ORDER BY random() LIMIT 1)"
            )
            # f8: mỗi UPDATE ghi đè đúng 1 dòng, nhưng CỘNG DỒN qua 30 lệnh trong
            # cửa sổ 60s -> f8 vẫn phản ánh đúng quy mô tổng thể của đợt tấn công.
            record_rowcount("staff_02", cur.rowcount, table="customer")
            set_status("kb4", f"☢️ Đang ghi đè dữ liệu... ({i+1}/30) — tốc độ 0.1s/lệnh")
            time.sleep(0.1)
        conn.rollback()  # pgAudit đã log đủ 30 lệnh UPDATE; dữ liệu khách hàng được khôi phục
        conn.close()
        set_status(
            "kb4",
            "✅ Hoàn tất. 30 bản ghi bị ghi đè cực nhanh "
            "→ kỳ vọng AI CRITICAL rõ rệt (f6≈1.0 toàn bộ là WRITE, f3 cao, f7 tăng vọt). ",
        )
    except Exception as e:
        set_status("kb4", f"❌ Lỗi: {e}")
