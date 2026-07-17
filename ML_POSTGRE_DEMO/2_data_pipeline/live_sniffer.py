import time
import numpy as np
import pandas as pd
import joblib
import json
from scapy.all import sniff, IP, TCP
# Nhập hàm gửi mail (chúng ta sẽ định nghĩa ở Phần 2)
# from realtime_engine import send_gmail_alert 

# 1. Tải bộ não AI và Ngưỡng quyết định
MODEL_PATH = "3_ml_model/isolation_forest.pkl"
THRESHOLDS_PATH = "3_ml_model/thresholds.json"

model = joblib.load(MODEL_PATH)
with open(THRESHOLDS_PATH, "r") as f:
    thresholds = json.load(f)
critical_th = thresholds["anomaly_threshold"]

# Bộ nhớ tạm để tính toán các đặc trưng trong sliding window (2 giây)
packet_window = []

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Lấy thông tin thời gian, độ dài và cờ lỗi
        timestamp = packet.time
        src_bytes = len(packet[IP].payload)
        dst_bytes = len(packet) # Ước lượng tổng dung lượng gói tin
        is_syn = 1 if packet[TCP].flags == "S" else 0
        is_rst = 1 if packet[TCP].flags == "R" else 0
        
        packet_window.append({
            'time': timestamp,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'is_syn': is_syn,
            'is_rst': is_rst,
            'ip_dst': packet[IP].dst
        })

def analyze_traffic_realtime():
    global packet_window
    print("[*] AI Live Sniffer đang hoạt động... Hãy dùng Kali Linux tấn công thử!")
    
    while True:
        # Bắt gói tin liên tục trong vòng 2 giây
        sniff(filter="tcp", prn=process_packet, timeout=2, store=0)
        
        if len(packet_window) == 0:
            continue
            
        # --- TRÍCH XUẤT 8 ĐẶC TRƯNG MẠNG CHO AI ---
        duration = 2.0 # Chu kỳ window cố định là 2s
        total_src_bytes = sum([p['src_bytes'] for p in packet_window])
        total_dst_bytes = sum([p['dst_bytes'] for p in packet_window])
        count = len(packet_window) # Tổng số kết nối đến hệ thống trong 2s
        
        # Đếm số kết nối đến cùng một server/mục tiêu (srv_count)
        dst_counts = {}
        for p in packet_window:
            dst_counts[p['ip_dst']] = dst_counts.get(p['ip_dst'], 0) + 1
        srv_count = max(dst_counts.values()) if dst_counts else 0
        
        # Tính toán tỷ lệ lỗi kết nối
        serror_rate = sum([p['is_syn'] for p in packet_window]) / count
        rerror_rate = sum([p['is_rst'] for p in packet_window]) / count
        same_srv_rate = srv_count / count
        
        # Gom cụm thành mảng đúng thứ tự 8 đặc trưng mô hình yêu cầu
        features = np.array([[duration, total_src_bytes, total_dst_bytes, count, srv_count, serror_rate, rerror_rate, same_srv_rate]])
        
        # --- ĐƯA VÀO AI CHẤM ĐIỂM ---
        score = model.decision_function(features)[0]
        
        print(f"[➔] Traffic Window: Gói tin={count} | Score={score:.4f}")
        
        # --- KIỂM TRA NGƯỠNG ĐỂ PHÁT HIỆN TẤN CÔNG & GỬI GMAIL ---
        if score < critical_th:
            print(f"🚨 [AI DETECTED] PHÁT HIỆN HÀNH VI BẤT THƯỜNG MẠNH! Score: {score:.4f}")
            details = (f"- Số lượng gói tin/2s (count): {count}\n"
                       f"- Dung lượng gửi (src_bytes): {total_src_bytes} bytes\n"
                       f"- Tỷ lệ lỗi SYN (serror_rate): {serror_rate*100:.1f}%")
            # Bạn có thể bỏ comment dòng dưới sau khi hoàn thành phần 2
            # send_gmail_alert(score, "NGUY HIỂM (CRITICAL)", details)
            
        # Reset cửa sổ bộ nhớ đệm cho chu kỳ 2 giây tiếp theo
        packet_window = []

if __name__ == "__main__":
    analyze_traffic_realtime()