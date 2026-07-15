import pandas as pd
import numpy as np
import json
from sklearn.ensemble import IsolationForest
import joblib

# Cấu hình đường dẫn
BASELINE_CSV = "../2_data_pipeline/baseline_features.csv"
MODEL_OUTPUT = "isolation_forest.pkl"
THRESHOLDS_OUTPUT = "thresholds.json"

def train_and_export_model():
    print("=== BẮT ĐẦU HUẤN LUYỆN MÔ HÌNH ISOLATION FOREST ===")
    
    # 1. Đọc dữ liệu Baseline
    try:
        df = pd.read_csv(BASELINE_CSV)
        print(f"[*] Đã tải thành công {len(df)} dòng dữ liệu từ {BASELINE_CSV}")
    except FileNotFoundError:
        print(f"[LỖI] Không tìm thấy file {BASELINE_CSV}. Hãy chắc chắn Giai đoạn 2 đã chạy và sinh ra file này.")
        return

    # Lọc lấy 8 cột đặc trưng (f1 đến f8), bỏ cột 'user'.
    # f8_rows_affected là đặc trưng MỚI (log1p của tổng số dòng dữ liệu thật bị
    # UPDATE/DELETE/INSERT trong cửa sổ 60s, lấy qua side-channel f8_bridge.py vì
    # pgAudit không ghi rowcount) — BẮT BUỘC baseline_features.csv phải được sinh
    # lại bằng log_parser.py bản MỚI (có cột f8_rows_affected) trước khi train,
    # nếu không sẽ lỗi thiếu cột hoặc train sai trên dữ liệu cũ không tương thích.
    feature_columns = [
        'f1_time_sin', 'f2_time_cos', 'f3_q60', 'f4_q120',
        'f5_tables', 'f6_write_ratio', 'f7_speed_diff', 'f8_rows_affected',
    ]
    missing = [c for c in feature_columns if c not in df.columns]
    if missing:
        print(f"[LỖI] baseline_features.csv thiếu cột {missing}.")
        print("      File này được sinh bởi log_parser.py bản CŨ (7 chiều, chưa có f8).")
        print("      Hãy xóa baseline_features.csv cũ và chạy lại warmup_generator.py")
        print("      + log_parser.py (bản mới) để sinh baseline 8 chiều trước khi train.")
        return
    X_train = df[feature_columns]

    # 2. Khởi tạo và Huấn luyện (Train Model)
    # contamination = 'auto' cho phép mô hình tự ước lượng tỷ lệ nhiễu trong baseline
    print("[*] Đang huấn luyện AI học phân phối 'bình thường'...")
    model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
    model.fit(X_train)
    
    # 3. Tính toán Anomaly Score trên chính tập Baseline
    # Scikit-learn trả về điểm âm cho bất thường. Ta sẽ đảo ngược (nhân -1) để:
    # Điểm càng CAO -> Càng BẤT THƯỜNG
    raw_scores = -model.decision_function(X_train)
    
    # 4. Thiết lập Ngưỡng (Thresholds) bằng Toán học (Percentile)
    # Dùng phân vị 90% và 99.5% (thay vì 95/99 cũ) để tạo VÙNG ĐỆM Warning rõ ràng hơn.
    # Baseline nhỏ (~500 dòng) và có độ nhiễu nhất định, nên nếu để 2 ngưỡng quá sát nhau
    # (như 95/99 cũ) thì mọi độ lệch nhỏ đều nhảy thẳng qua cả Warning lẫn Critical cùng lúc.
    warning_threshold = np.percentile(raw_scores, 90)
    critical_threshold = np.percentile(raw_scores, 99.5)

    # An toàn: đảm bảo khoảng cách tối thiểu giữa 2 ngưỡng (ít nhất gấp đôi warning),
    # phòng trường hợp baseline quá đồng nhất khiến percentile co cụm lại gần nhau.
    min_gap = max(warning_threshold * 1.0, 1e-6)
    if critical_threshold - warning_threshold < min_gap:
        critical_threshold = warning_threshold + min_gap

    thresholds = {
        "warning": float(warning_threshold),
        "critical": float(critical_threshold)
    }
    
    print("-" * 50)
    print("📊 KẾT QUẢ TÍNH TOÁN NGƯỠNG (THRESHOLDS):")
    print(f"   - Vùng AN TOÀN (Low)       : < {warning_threshold:.4f}")
    print(f"   - Vùng CẢNH BÁO (Warning)  : {warning_threshold:.4f} -> {critical_threshold:.4f}")
    print(f"   - Vùng NGUY HIỂM (Critical): > {critical_threshold:.4f}")
    print("-" * 50)

    # 5. Lưu "Não bộ" (Export Model & Thresholds)
    joblib.dump(model, MODEL_OUTPUT)
    with open(THRESHOLDS_OUTPUT, 'w') as f:
        json.dump(thresholds, f)
        
    print(f"[+] Đã xuất mô hình thành công ra file: {MODEL_OUTPUT}")
    print(f"[+] Đã xuất file cấu hình ngưỡng ra file: {THRESHOLDS_OUTPUT}")
    print("=== HOÀN TẤT GIAI ĐOẠN 3 ===")

if __name__ == "__main__":
    train_and_export_model()
