import psycopg2
import time
import random

# Cấu hình kết nối chung
DB_CONFIG = {
    "dbname": "ml_postgre_demo",
    "host": "127.0.0.1",
    "port": "5432"
}

def attack_scenario_1():
    """Kịch bản 1: svc_backup trích xuất dữ liệu lệch giờ, lệch bảng"""
    print("\n[💀 KỊCH BẢN 1] Kích hoạt: svc_backup đang trích xuất dữ liệu nhạy cảm...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="svc_backup", password="password123")
        conn.autocommit = True
        cur = conn.cursor()
        
        # Đọc dồn dập các bảng không thuộc thẩm quyền vào giờ hành chính
        tables = ['salary', 'hr_notes', 'contract', 'employee', 'customer']
        for table in tables:
            print(f"[*] svc_backup đang càn quét bảng: {table}")
            cur.execute(f"SELECT * FROM {table}")
            time.sleep(0.5) # Độ trễ ngắn để tạo log
            
        cur.close()
        conn.close()
        print("[+] Hoàn tất Kịch bản 1. Hãy nhìn Dashboard!")
    except Exception as e:
        print(f"[!] Lỗi: {e}")

def attack_scenario_2():
    """Kịch bản 2: staff_02 dò pass -> trinh sát -> bùng nổ SELECT"""
    print("\n[💀 KỊCH BẢN 2] Kích hoạt: staff_02 dò password và bùng nổ truy vấn...")
    
    # Giai đoạn 1: Dò password (Tạo log Failed Login nếu có bắt log kết nối)
    print("[*] Đang Brute-force mật khẩu...")
    for _ in range(5):
        try:
            psycopg2.connect(**DB_CONFIG, user="staff_02", password=f"wrongpass{random.randint(1,99)}")
        except:
            pass
        time.sleep(0.2)
        
    # Giai đoạn 2: Bùng nổ SELECT (Đẩy f3, f4 lên cực cao)
    print("[*] Đăng nhập thành công! Bắt đầu bùng nổ SELECT (Data Exfiltration)...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_02", password="password123")
        conn.autocommit = True
        cur = conn.cursor()
        
        for i in range(50): # 50 truy vấn trong vài giây
            cur.execute("SELECT name, email FROM customer LIMIT 5")
            
        cur.close()
        conn.close()
        print("[+] Hoàn tất Kịch bản 2. Biểu đồ chắc chắn đang giật lên Cam/Đỏ!")
    except Exception as e:
        print(f"[!] Lỗi: {e}")

def attack_scenario_3():
    """Kịch bản 3: staff_03 xoá dữ liệu với điều kiện WHERE nguy hiểm"""
    print("\n[💀 KỊCH BẢN 3] Kích hoạt: staff_03 thực hiện truy vấn DELETE phá hoại...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_03", password="password123")
        conn.autocommit = True
        cur = conn.cursor()
        
        queries = [
            "DELETE FROM session_logs WHERE user_id = 3",
            "DELETE FROM session_logs WHERE status = 'FAILED'",
            "DELETE FROM session_logs WHERE login_time < NOW() - INTERVAL '1 day'"
        ]
        
        for q in queries:
            print(f"[*] Thực thi: {q}")
            cur.execute(q)
            time.sleep(1)
            
        cur.close()
        conn.close()
        print("[+] Hoàn tất Kịch bản 3. Nhịp độ hành vi đang bị AI soi xét!")
    except Exception as e:
        print(f"[!] Lỗi: {e}")

def attack_scenario_4():
    """Kịch bản 4: Ransomware UPDATE ghi đè mã hoá dữ liệu"""
    print("\n[💀 KỊCH BẢN 4 - RANSOMWARE] Kích hoạt: UPDATE ghi đè mã MD5 tốc độ cao...")
    try:
        conn = psycopg2.connect(**DB_CONFIG, user="staff_02", password="password123")
        conn.autocommit = True
        cur = conn.cursor()
        
        # Vòng lặp bắn UPDATE liên tục để đánh lừa tỷ lệ Read/Write (f6)
        for i in range(30):
            cur.execute("UPDATE customer SET email = md5(random()::text) WHERE id = (SELECT id FROM customer ORDER BY random() LIMIT 1)")
            print(f"[*] Đang mã hoá dữ liệu khách hàng (Bản ghi {i+1}/30)...")
            time.sleep(0.1) # Tốc độ cực nhanh
            
        cur.close()
        conn.close()
        print("[+] Hoàn tất Kịch bản 4 (Ransomware). Cú gãy khúc Critical đỏ chót đang xuất hiện!")
    except Exception as e:
        print(f"[!] Lỗi: {e}")

if __name__ == "__main__":
    print("=== TRUNG TÂM ĐIỀU KHIỂN KỊCH BẢN DEMO ===")
    print("1. Kịch bản 1: svc_backup trích xuất lệch giờ/bảng")
    print("2. Kịch bản 2: staff_02 dò pass và bùng nổ SELECT")
    print("3. Kịch bản 3: staff_03 xoá dữ liệu (DELETE)")
    print("4. Kịch bản 4: Ransomware mã hoá dữ liệu (UPDATE)")
    print("0. Thoát")
    
    while True:
        choice = input("\n[?] Chọn kịch bản để 'bóp cò' (0-4): ")
        if choice == '1':
            attack_scenario_1()
        elif choice == '2':
            attack_scenario_2()
        elif choice == '3':
            attack_scenario_3()
        elif choice == '4':
            attack_scenario_4()
        elif choice == '0':
            print("Đã thoát trình giả lập.")
            break
        else:
            print("Lựa chọn không hợp lệ!")
