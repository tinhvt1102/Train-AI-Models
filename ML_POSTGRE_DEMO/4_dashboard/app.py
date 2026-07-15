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
st.set_page_config(page_title="PostgreSQL AI Monitor", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Powered PostgreSQL Threat Detection")
st.markdown("Hệ thống giám sát thời gian thực sử dụng Isolation Forest để phát hiện hành vi bất thường.")
st.caption("Dữ liệu hiển thị được đọc TRỰC TIẾP từ log pgAudit thật — không phải dữ liệu giả lập.")

# ==========================================
# 💀 BẢNG ĐIỀU KHIỂN TẤN CÔNG (CONTROL PANEL)
# ==========================================
st.sidebar.markdown("---")
st.sidebar.header("💀 KỊCH BẢN TẤN CÔNG")
st.sidebar.caption("Mỗi kịch bản mô phỏng MỘT KIỂU vi phạm khác nhau, chạy SQL thật vào DB thật:")

st.sidebar.markdown("**1. svc_backup — Vi phạm ranh giới nghiệp vụ**")
st.sidebar.caption("Đọc thẳng vào bảng lương/nhân sự — ngoài phạm vi cho phép của tài khoản backup.")
if st.sidebar.button("🚫 Chạy KB1", use_container_width=True, key="btn_kb1"):
    threading.Thread(target=atk.run_scenario_1, daemon=True).start()
kb1_status = st.sidebar.empty()

st.sidebar.markdown("**2. staff_02 — Chuỗi tấn công (Kill-chain)**")
st.sidebar.caption("Trinh sát → Brute-force → Truy cập → Bùng nổ trích xuất (4 giai đoạn).")
if st.sidebar.button("🔎 Chạy KB2", use_container_width=True, key="btn_kb2"):
    threading.Thread(target=atk.run_scenario_2, daemon=True).start()
kb2_status = st.sidebar.empty()

st.sidebar.markdown("**3. staff_03 — Xóa dữ liệu (2 mức độ)**")
st.sidebar.caption("So sánh trực tiếp: xóa có lý do vs xóa hàng loạt vô căn cứ.")
col3a, col3b = st.sidebar.columns(2)
if col3a.button("🟡 3a Hợp lệ", use_container_width=True, key="btn_kb3a"):
    threading.Thread(target=atk.run_scenario_3a, daemon=True).start()
if col3b.button("🔴 3b Hàng loạt", use_container_width=True, key="btn_kb3b"):
    threading.Thread(target=atk.run_scenario_3b, daemon=True).start()
kb3_status = st.sidebar.empty()

st.sidebar.markdown("**4. Ransomware**")
st.sidebar.caption("Ghi đè dữ liệu khách hàng tốc độ cao.")
if st.sidebar.button("☢️ Chạy KB4", use_container_width=True, key="btn_kb4", type="primary"):
    threading.Thread(target=atk.run_scenario_4, daemon=True).start()
kb4_status = st.sidebar.empty()

st.sidebar.markdown("---")
st.sidebar.caption(
    "⚠️ KB2+KB4 dùng chung user `staff_02`, KB3a+KB3b dùng chung `staff_03`. "
    "Nếu bấm liên tiếp trong <2 phút, sự kiện cũ vẫn còn trong sliding window "
    "và sẽ cộng dồn vào kịch bản sau. Bấm Reset bên dưới để so sánh công bằng."
)
if st.sidebar.button("🔄 Reset bộ nhớ đệm (sliding window)", use_container_width=True):
    # Sẽ gọi engine.reset_window() sau khi engine được khởi tạo bên dưới — đặt cờ tạm.
    st.session_state["_pending_reset"] = True
st.sidebar.markdown("---")
MODEL_PATH = "../3_ml_model/isolation_forest.pkl"
THRESHOLDS_PATH = "../3_ml_model/thresholds.json"


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
warning_th = thresholds["warning"]
critical_th = thresholds["critical"]

# Khởi động engine tail-log-thật CHỈ MỘT LẦN cho cả process
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
st.caption("Diễn giải ngắn gọn: đặc trưng nào đang khiến điểm bất thường tăng.")
ai_reasoning_box = st.empty()

st.subheader("📈 Biểu đồ Anomaly Score (Real-time, dữ liệu THẬT từ pgAudit)")
chart_placeholder = st.empty()

st.subheader("🚨 Nhật ký Cảnh báo Gần đây")
alert_table = st.empty()

# Tham chiếu "bình thường" (rút ra từ baseline_features.csv) — chỉ dùng để DIỄN GIẢI
# bằng lời cho người xem demo hiểu, không ảnh hưởng tới logic của model.
REF_F3_NORMAL = 10      # tần suất 60s bình thường thường dưới mức này
REF_F5_NORMAL = 1       # số bảng khác nhau truy cập bình thường
REF_F6_NORMAL = 0.1     # tỉ lệ ghi/xóa bình thường gần như bằng 0
REF_F8_NORMAL = 2.0     # log1p(rows) bình thường (~1-6 dòng UPDATE/INSERT lẻ tẻ)


def build_reasoning(features, status):
    f3, f5, f6 = features[2], features[4], features[5]
    f8 = features[7] if len(features) > 7 else 0.0
    lines = []

    if f3 > REF_F3_NORMAL:
        ratio = f3 / max(REF_F3_NORMAL, 1)
        lines.append(f"📊 **Tần suất truy vấn (f3)**: {f3:.0f} lệnh/60s — cao gấp ~{ratio:.1f} lần mức bình thường (~{REF_F3_NORMAL}).")
    else:
        lines.append(f"📊 **Tần suất truy vấn (f3)**: {f3:.0f} lệnh/60s — trong ngưỡng bình thường.")

    if f6 > REF_F6_NORMAL:
        lines.append(f"✍️ **Tỉ lệ ghi/xóa (f6)**: {f6*100:.0f}% các lệnh gần đây là WRITE/DDL — bình thường tỉ lệ này gần như 0%.")
    else:
        lines.append(f"✍️ **Tỉ lệ ghi/xóa (f6)**: {f6*100:.0f}% — chủ yếu là đọc dữ liệu (READ), không đáng lo.")

    if f5 > REF_F5_NORMAL:
        lines.append(f"🗂️ **Số bảng truy cập cùng lúc (f5)**: {f5:.0f} bảng trong 60s — rộng hơn phạm vi thường thấy ({REF_F5_NORMAL} bảng).")
    else:
        lines.append(f"🗂️ **Số bảng truy cập cùng lúc (f5)**: {f5:.0f} bảng — phạm vi bình thường.")

    # f8: ước lượng ngược log1p() ra số dòng gần đúng để dễ hiểu hơn với người xem demo
    approx_rows = round(np.expm1(f8)) if f8 > 0 else 0
    if f8 > REF_F8_NORMAL:
        lines.append(
            f"🧮 **Số dòng dữ liệu bị ảnh hưởng (f8)**: ~{approx_rows} dòng trong 60s gần nhất "
            f"— vượt mức bình thường (~1-6 dòng). Đây là đặc trưng đo TRỰC TIẾP quy mô dữ liệu bị "
            f"ghi/xóa, khác với f6 (chỉ đo TỈ LỆ số lệnh ghi, không biết mỗi lệnh xóa bao nhiêu dòng)."
        )
    else:
        lines.append(f"🧮 **Số dòng dữ liệu bị ảnh hưởng (f8)**: ~{approx_rows} dòng — quy mô nhỏ, bình thường.")

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
        metric_action.metric(label="User Đang truy cập", value=last_event["user"])
        ai_reasoning_box.markdown(build_reasoning(last_event["features"], last_event["status"]))
    else:
        metric_score.metric(label="Anomaly Score Hiện tại", value="--")
        metric_status.markdown("<h2 style='color: gray;'>⏳ Chưa có sự kiện</h2>", unsafe_allow_html=True)
        metric_action.metric(label="User Đang truy cập", value="--")
        ai_reasoning_box.info("Đang chờ sự kiện đầu tiên từ log thật...")

    history = snap["history_scores"]
    if history:
        chart_placeholder.line_chart(history)
    else:
        chart_placeholder.info("Đang chờ log thật từ PostgreSQL... hãy để warmup_generator.py chạy nền, hoặc bấm một kịch bản tấn công.")

    if snap["alerts"]:
        df = pd.DataFrame(
            [
                {
                    "Thời gian": a["time"],
                    "User": a["user"],
                    "Hành vi": a["action"],
                    "Điểm rủi ro": a["score"],
                    "Mức độ": a["status"],
                }
                for a in snap["alerts"]
            ]
        )
        alert_table.dataframe(df, use_container_width=True, hide_index=True)
    else:
        alert_table.info("Chưa có cảnh báo nào — hệ thống đang ở trạng thái bình thường.")

    time.sleep(1)
