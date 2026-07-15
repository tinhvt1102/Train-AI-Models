import os
import sys
import psycopg2
import random
import time
from datetime import datetime

# Cho phép import f8_bridge.py ở thư mục gốc project (ML_POSTGRE_DEMO/).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
from f8_bridge import record_rowcount  # noqa: E402

# Cấu hình kết nối DB (Chạy trực tiếp trên Kali localhost)
DB_CONFIG = {
    "dbname": "ml_postgre_demo",
    "host": "localhost",
    "port": "5432"
}

def execute_query(user, password, query, is_write=False):
    """Hàm phụ trợ để thực thi SQL dưới quyền một user cụ thể.

    is_write=True: sau khi execute(), ghi rowcount THẬT (cur.rowcount) ra
    side-channel f8_bridge để log_parser.py (chạy ở TIẾN TRÌNH khác) đọc được
    khi tính f8. Nếu không làm bước này, baseline sẽ toàn f8=0 dù có UPDATE/
    INSERT thật -> model sẽ coi MỌI f8 > 0 là cực đoan/bất thường, kể cả những
    lệnh ghi bình thường trong lúc làm việc (xem RETRAIN_HUONG_DAN.md).
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG, user=user, password=password)
        cur = conn.cursor()
        cur.execute(query)
        if is_write:
            record_rowcount(user, cur.rowcount)
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        # Trong thực tế có thể in ra lỗi, nhưng lúc warm-up ta có thể bỏ qua
        pass 

def simulate_backup():
    """Giả lập svc_backup: Chỉ đọc dữ liệu để sao lưu"""
    tables = ['employee', 'customer', 'contract', 'salary', 'hr_notes', 'session_logs']
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [svc_backup] Đang chạy cronjob quét sao lưu...")
    
    # Quét lần lượt các bảng như thói quen 
    for table in tables:
        execute_query("svc_backup", "password123", f"SELECT * FROM {table};")
        time.sleep(0.5)

def simulate_staff():
    """Giả lập staff_02, staff_03: Làm việc văn phòng từ tốn.

    QUAN TRỌNG: nhân viên văn phòng bình thường ĐỌC rất nhiều, GHI rất ít
    (thường chỉ 5-15% thao tác là UPDATE/INSERT). Bản cũ chọn đều 50/50 giữa
    đọc và ghi -> khiến AI học nhầm rằng "ghi nhiều" là chuyện bình thường,
    làm mất khả năng phân biệt Warning/Critical khi có ghi bất thường thật sự.
    """
    users = [("staff_02", "password123"), ("staff_03", "password123")]
    user, pwd = random.choice(users)

    read_queries = [
        "SELECT * FROM customer WHERE id = 1 LIMIT 1;",
        "SELECT name, department FROM employee WHERE department = 'IT';",
        "SELECT * FROM session_logs WHERE status = 'SUCCESS' LIMIT 5;",
        "SELECT name FROM customer LIMIT 3;",
    ]
    write_queries = [
        "UPDATE customer SET email = 'updated@email.com' WHERE id = 1;",
        "INSERT INTO session_logs (user_id, login_time, status) VALUES (2, NOW(), 'SUCCESS');",
    ]

    # 90% đọc, 10% ghi -> phản ánh đúng nhịp làm việc văn phòng thật
    if random.random() < 0.90:
        query = random.choice(read_queries)
        is_write = False
    else:
        query = random.choice(write_queries)
        is_write = True

    print(f"[{datetime.now().strftime('%H:%M:%S')}] [{user}] Đang làm việc: {query}")
    execute_query(user, pwd, query, is_write=is_write)

if __name__ == "__main__":
    print("=== BẮT ĐẦU GIẢ LẬP DỮ LIỆU BASELINE (WARM-UP) ===")
    print("Nhấn Ctrl+C để dừng.\n")
    try:
        while True:
            # Tỉ lệ: 15% là backup chạy, 85% là nhân viên làm việc
            if random.random() < 0.15:
                simulate_backup()
            else:
                simulate_staff()
            
            # Nghỉ ngẫu nhiên 2 - 5 giây giữa các thao tác để giống người thật
            time.sleep(random.randint(2, 5))
            
    except KeyboardInterrupt:
        print("\n=== ĐÃ DỪNG GIẢ LẬP ===")
