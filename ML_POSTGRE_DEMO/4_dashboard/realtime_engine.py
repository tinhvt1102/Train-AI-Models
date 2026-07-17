"""
realtime_engine.py
===================
Cầu nối THẬT giữa Live Network Traffic <-> Feature Engineering <-> AI Model (Isolation Forest).

Module này:
  1. Hỗ trợ hứng traffic mạng, cập nhật liên tục sliding window.
  2. Tính toán vector 8 đặc trưng của bộ NSL-KDD bằng đúng công thức đã dùng lúc train.
  3. Chạy model.decision_function() trên chu kỳ dữ liệu ngay lập tức.
  4. Tự động gửi Gmail thông báo nếu điểm bất thường vượt ngưỡng nguy hiểm.
  5. Lưu kết quả vào một hàng đợi thread-safe để Streamlit (app.py) đọc và vẽ.
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
import smtplib
from collections import deque
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import numpy as np

# Cho phép import các module ở thư mục gốc project nếu cần
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ------------------------------------------------------------------
# Cấu hình
# ------------------------------------------------------------------
SLIDING_WINDOW_SECONDS = 120
MAX_HISTORY = 50          # Số điểm giữ lại cho biểu đồ
MAX_ALERTS = 20           # Số dòng giữ lại cho bảng cảnh báo

FEATURE_COLUMNS = [
    "duration", "src_bytes", "dst_bytes", "count", 
    "srv_count", "serror_rate", "rerror_rate", "same_srv_rate"
]


# ------------------------------------------------------------------
# Hàm gửi Gmail Cảnh báo tự động
# ------------------------------------------------------------------
def send_gmail_alert(anomaly_score, status_level, details=""):
    """Gửi email cảnh báo qua giao thức SMTP của Gmail khi AI phát hiện nguy hiểm."""
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    
    # Kế hoạch thực tế: Thay thế bằng thông tin Gmail và App Password của bạn
    SENDER_EMAIL = "tritinh11022004@gmail.com"      
    SENDER_PASSWORD = "gvbb xkur yvsm jhjn"     
    RECEIVER_EMAIL = "tritinh11022004@gmail.com"  

    subject = f"🚨 [AI ALERT] Phát hiện mối đe dọa mạng: {status_level}!"
    body = f"""
    Hệ thống AI Monitor phát hiện traffic mạng bất thường vượt ngưỡng an toàn:
    - Anomaly Score: {anomaly_score:.4f}
    - Mức độ rủi ro: {status_level}
    
    Chi tiết phân tích các đặc trưng mạng từ AI:
    {details}
    
    Vui lòng kiểm tra lại hệ thống và máy ảo Kali Linux ngay lập tức!
    """

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # Kích hoạt mã hóa TLS bảo mật
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("[+] Đã gửi mail cảnh báo qua Gmail thành công!")
    except Exception as e:
        print(f"[-] Thất bại khi gửi email cảnh báo: {e}")


class RealtimeEngine:
    """Chạy nền: Giám sát traffic mạng -> Feature engineering -> Inference & Gmail Alert."""

    def __init__(self, model, thresholds):
        self.model = model
        # Cập nhật lấy chính xác cấu trúc key mới của Isolation Forest NSL-KDD
        self.critical_th = thresholds["anomaly_threshold"]
        self.warning_th = self.critical_th + 0.05

        self._lock = threading.Lock()
        self._sliding_window = deque()          
        self.history_scores = deque(maxlen=MAX_HISTORY)
        self.alerts = deque(maxlen=MAX_ALERTS)   
        self.last_event = None                   

        self.status_message = "🟢 Hệ thống AI Engine (NSL-KDD) đang sẵn sàng..."
        self._started = False
        self._thread = None

    # ---------------- Feature engineering chuẩn bộ NSL-KDD ----------------
    def _extract_features(self, current_time, user_ip):
        """Gom cụm và tính toán 8 chỉ số mạng dựa trên sliding window dữ liệu."""
        while self._sliding_window and self._sliding_window[0]["timestamp"] < current_time - SLIDING_WINDOW_SECONDS:
            self._sliding_window.popleft()

        # Lọc lưu lượng liên quan đến IP/Thiết bị này
        ip_events = [e for e in self._sliding_window if e["user"] == user_ip]
        events_2s = [e for e in ip_events if e["timestamp"] >= current_time - 2]

        # 1. duration
        duration = 2.0
        # 2 & 3. src_bytes & dst_bytes
        src_bytes = sum([e.get("src_bytes", 0) for e in events_2s])
        dst_bytes = sum([e.get("dst_bytes", 0) for e in events_2s])
        # 4. count (Tổng số kết nối đến cùng host trong 2 giây qua)
        count = len(events_2s) if len(events_2s) > 0 else 1

        # 5. srv_count (Số kết nối đến cùng dịch vụ)
        srv_count = sum(1 for e in events_2s if e.get("is_same_srv", False))
        
        # 6 & 7 & 8. Các tỷ lệ lỗi mạng
        serror_rate = sum(1 for e in events_2s if e.get("is_syn_error", False)) / count
        rerror_rate = sum(1 for e in events_2s if e.get("is_rst_error", False)) / count
        same_srv_rate = srv_count / count

        return [duration, src_bytes, dst_bytes, count, srv_count, serror_rate, rerror_rate, same_srv_rate]

    # ---------------- Vòng lặp nhận và xử lý sự kiện mạng ----------------
    def inject_live_packet(self, packet_data):
        """Hàm nhận gói tin mạng thật từ Sniffer ngoài đẩy vào (Ví dụ từ Kali Linux)"""
        with self._lock:
            current_time = time.time()
            packet_data["timestamp"] = current_time
            user_ip = packet_data.get("user", "unknown_ip")

            self._sliding_window.append(packet_data)
            features = self._extract_features(current_time, user_ip)

            # Mô hình chấm điểm bất thường (Isolation Forest)
            raw_score = self.model.decision_function([features])[0]
            anomaly_score = float(-raw_score)  # Đảo dấu: Điểm càng cao càng nguy hiểm

            # Phân cấp mức độ an toàn dựa trên ngưỡng thresholds.json
            if anomaly_score >= self.critical_th:
                status, color = "🔴 CRITICAL RISK", "red"
            elif anomaly_score >= self.warning_th:
                status, color = "🟠 WARNING", "orange"
            else:
                status, color = "🟢 NORMAL", "green"

            record = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "user": user_ip,
                "action": f"Traffic: {packet_data.get('packet_count', 1)} gói tin mạng",
                "score": round(anomaly_score, 4),
                "status": status,
                "color": color,
                "features": features,
            }

            self.last_event = record
            self.history_scores.append(anomaly_score)

            # Nếu phát hiện đòn tấn công thực sự nguy hiểm -> Kích hoạt gửi Gmail
            if status == "🔴 CRITICAL RISK":
                self.alerts.appendleft(record)
                
                # Tạo chuỗi chi tiết phân tích để đính kèm vào email
                details = (
                    f"- Tổng số kết nối / 2s (count): {features[3]}\n"
                    f"- Tổng lượng dữ liệu gửi đi (src_bytes): {features[1]} bytes\n"
                    f"- Tỷ lệ lỗi kết nối SYN (serror_rate): {features[5] * 100:.1f}%\n"
                    f"- Tỷ lệ kết nối cùng dịch vụ (same_srv_rate): {features[7] * 100:.1f}%"
                )
                
                # Tạo một luồng (thread) gửi mail phụ để tránh làm nghẽn/lag đồ thị UI của Streamlit
                threading.Thread(
                    target=send_gmail_alert, 
                    args=(anomaly_score, status, details), 
                    daemon=True
                ).start()
            
            elif anomaly_score >= self.warning_th:
                self.alerts.appendleft(record)

    def start(self):
        """Hàm duy trì tương thích cấu trúc gọi từ app.py"""
        if self._started:
            return
        self._started = True
        print("[+] AI Network Engine đã kích hoạt luồng xử lý ngầm thành công.")

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
        """Xóa sạch sliding window để chuẩn bị chạy đợt demo/test tấn công mới."""
        with self._lock:
            if user is None:
                self._sliding_window.clear()
                self.history_scores.clear()
                self.alerts.clear()
                self.last_event = None
            else:
                self._sliding_window = deque(e for e in self._sliding_window if e["user"] != user)


# Singleton sử dụng chung cho toàn bộ tiến trình Streamlit
_engine_instance = None
_engine_lock = threading.Lock()


def get_engine(model, thresholds):
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = RealtimeEngine(model, thresholds)
            _engine_instance.start()
        return _engine_instance