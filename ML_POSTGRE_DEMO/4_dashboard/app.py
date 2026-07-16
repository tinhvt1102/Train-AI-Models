import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import time
import threading

from realtime_engine import get_engine
import attack_scenarios as atk

# --- CẤU HÌNH TRANG ---
st.set_page_config(page_title="AI Network Threat Monitor", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Powered Network Threat Detection")
st.markdown("Hệ thống giám sát thời gian thực sử dụng Isolation Forest phân tích bộ dữ liệu chuẩn NSL-KDD.")
st.caption("Dữ liệu hiển thị được trích xuất trực tiếp từ traffic mạng để phát hiện các hành vi bất thường.")

# ==========================================
# 💀 BẢNG ĐIỀU KHIỂN TẤN CÔNG (CONTROL PANEL)
# ==========================================
st.sidebar.markdown("---")
st.sidebar.header("💀 KỊCH BẢN MÔ PHỎNG")
st.sidebar.caption("Kích hoạt các kịch bản mô phỏng traffic mạng kết nối hệ thống:")

st.sidebar.markdown("**1. Vi phạm ranh giới nghiệp vụ (Mô phỏng)**")
if st.sidebar.button("🚫 Chạy KB1", use_container_width=True, key="btn_kb1"):
    threading.Thread(target=atk.run_scenario_1, daemon=True).start()
kb1_status = st.sidebar.empty()

st.sidebar.markdown("**2. Chuỗi tấn công Kill-chain (Mô phỏng)**")
if st.sidebar.button("🔎 Chạy KB2", use_container_width=True, key="btn_kb2"):
    threading.Thread(target=atk.run_scenario_2, daemon=True).start()
kb2_status = st.sidebar.empty()

st.sidebar.markdown("**3. Xóa dữ liệu / Đột biến kết nối (Mô phỏng)**")
col3a, col3b = st.sidebar.columns(2)
if col3a.button("🟡 3a Hợp lệ", use_container_width=True, key="btn_kb3a"):
    threading.Thread(target=atk.run_scenario_3a, daemon=True).start()
if col3b.button("🔴 3b Hàng loạt", use_container_width=True, key="btn_kb3b"):
    threading.Thread(target=atk.run_scenario_3b, daemon=True).start()
kb3_status = st.sidebar.empty()

st.sidebar.markdown("**4. Ransomware / Tấn công mã độc (Mô phỏng)**")
if st.sidebar.button("☢️ Chạy KB4", use_container_width=True, key="btn_kb4", type="primary"):
    threading.Thread(target=atk.run_scenario_4, daemon=True).start()
kb4_status = st.sidebar.empty()

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Reset bộ nhớ đệm (sliding window)", use_container_width=True):
    st.session_state["_pending_reset"] = True
st.sidebar.markdown("---")

MODEL_PATH = "3_ml_model/isolation_forest.pkl"
THRESHOLDS_PATH = "3_ml_model/thresholds.json"


@st.cache_resource
def load_ai_brain():
    try:
        model = joblib.load(MODEL_PATH)
        with open(THRESHOLDS_PATH, "r") as f:
            thresholds = json.load(f)
        return model, thresholds
    except Exception as e:
        st.error(f"❌ Không thể tải AI Model! Vui lòng chạy lại Giai đoạn 3. Lỗi: {e}")
        st.stop()


model, thresholds = load_ai_brain()

# Cấu hình lại lấy đúng ngưỡng quyết định mới từ Isolation Forest
critical_th = thresholds["anomaly_threshold"]
warning_th = critical_th + 0.05  # Ngưỡng cảnh báo nhẹ trước khi chạm mức chặn độc hại

# Khởi động engine tail-log CHỈ MỘT LẦN cho cả process
engine = get_engine(model, thresholds)

if st.session_state.get("_pending_reset"):
    engine.reset_window()
    st.session_state["_pending_reset"] = False
    st.sidebar.success("✅ Đã reset sliding window — sẵn sàng demo kịch bản tiếp theo sạch sẽ.")

# --- BỐ CỤC GIAO DIỆN (UI LAYOUT) ---
engine_status_box = st.empty()

col1, col2, col3 = st.columns(3)
metric_score = col1.empty()
metric_status = col2.empty()
metric_action = col3.empty()

st.subheader("🧠 AI đang phân tích")
st.caption("Diễn giải ngắn gọn: đặc trưng lưu lượng mạng nào đang khiến điểm bất thường thay đổi.")
ai_reasoning_box = st.empty()

st.subheader("📈 Biểu đồ Anomaly Score (Real-time, phân tích traffic NSL-KDD)")
chart_placeholder = st.empty()

st.subheader("🚨 Nhật ký Cảnh báo Gần đây")
alert_table = st.empty()

# Các giá trị tham chiếu trung bình của bộ NSL-KDD (chỉ dùng để mô tả trực quan trên UI)
REF_DURATION = 0.0
REF_SRC_BYTES = 150.0
REF_COUNT = 5.0
REF_SERROR_RATE = 0.05


def build_reasoning(features, status):
    # Khớp đúng thứ tự 8 cột đặc trưng dạng số đã huấn luyện với mô hình
    duration, src_bytes, dst_bytes, count, srv_count, serror_rate, rerror_rate, same_srv_rate = features
    lines = []

    if duration > REF_DURATION:
        lines.append(f"⏳ **Thời gian kết nối (duration)**: {duration} giây — kết nối kéo dài bất thường.")
    else:
        lines.append(f"⏳ **Thời gian kết nối (duration)**: {duration} giây — kết nối tức thời, bình thường.")

    if src_bytes > REF_SRC_BYTES:
        ratio = src_bytes / max(REF_SRC_BYTES, 1)
        lines.append(f"📦 **Lượng dữ liệu gửi đi (src_bytes)**: {src_bytes:.0f} bytes — cao gấp ~{ratio:.1f} lần mức cơ sở.")
    else:
        lines.append(f"📦 **Lượng dữ liệu gửi đi (src_bytes)**: {src_bytes:.0f} bytes — quy mô gói tin nhỏ.")

    if count > REF_COUNT:
        lines.append(f"📡 **Tần suất kết nối (count)**: {count:.0f} yêu cầu đến cùng Host trong 2 giây qua — dấu hiệu quét (scanning) hoặc dồn dập.")
    else:
        lines.append(f"📡 **Tần suất kết nối (count)**: {count:.0f} yêu cầu — mật độ kết nối an toàn.")

    if serror_rate > REF_SERROR_RATE:
        lines.append(f"❌ **Tỷ lệ lỗi kết nối SYN (serror_rate)**: {serror_rate*100:.1f}% — xuất hiện dấu hiệu tấn công từ chối dịch vụ (DoS).")
    else:
        lines.append(f"❌ **Tỷ lệ lỗi kết nối SYN (serror_rate)**: {serror_rate*100:.1f}% — các kết nối phản hồi bình thường.")

    return "  \n".join(lines)


# --- VÒNG LẶP THỜI GIAN THỰC ---
for _ in range(300):
    # Cập nhật trạng thái tiến trình từng kịch bản
    kb1_status.caption(atk.get_status("kb1"))
    kb2_status.caption(atk.get_status("kb2"))
    kb3_text = atk.get_status("kb3b") or atk.get_status("kb3a")
    kb3_status.caption(kb3_text)
    kb4_status.caption(atk.get_status("kb4"))

    snap = engine.snapshot()
    engine_status_box.caption(snap["status_message"])

    last_event = snap["last_event"]
    if last_event is not None:
        metric_score.metric(label="Anomaly Score Hiện tại", value=f"{last_event['score']:.4f}")
        metric_status.markdown(
            f"<h2 style='color: {last_event['color']};'>{last_event['status']}</h2>",
            unsafe_allow_html=True,
        )
        metric_action.metric(label="User / Thiết bị kết nối", value=last_event["user"])
        ai_reasoning_box.markdown(build_reasoning(last_event["features"], last_event["status"]))
    else:
        metric_score.metric(label="Anomaly Score Hiện tại", value="--")
        metric_status.markdown("<h2 style='color: gray;'>⏳ Chưa có sự kiện</h2>", unsafe_allow_html=True)
        metric_action.metric(label="User / Thiết bị kết nối", value="--")
        ai_reasoning_box.info("Đang chờ gói tin mạng đầu tiên từ hệ thống...")

    history = snap["history_scores"]
    if history:
        chart_placeholder.line_chart(history)
    else:
        chart_placeholder.info("Đang chờ dòng traffic mạng... hãy để bộ phân tích chạy nền hoặc bấm một kịch bản giả lập ở sidebar.")

    if snap["alerts"]:
        df = pd.DataFrame(
            [
                {
                    "Thời gian": a["time"],
                    "User/IP": a["user"],
                    "Hành vi": a["action"],
                    "Điểm rủi ro": a["score"],
                    "Mức độ": a["status"],
                }
                for a in snap["alerts"]
            ]
        )
        alert_table.dataframe(df, use_container_width=True, hide_index=True)
    else:
        alert_table.info("Chưa có cảnh báo nào — hệ thống đang ở trạng thái an toàn.")

    time.sleep(1)