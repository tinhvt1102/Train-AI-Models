import os
import json
import pandas as pd
import pickle
from sklearn.ensemble import IsolationForest

def train_new_model(data_path, model_path, threshold_path):
    print(f"[*] Đang nạp dữ liệu từ {data_path} để huấn luyện...")
    
    # 1. Đọc dữ liệu đặc trưng đã được parser chuẩn bị
    if not os.path.exists(data_path):
        print(f"[!] Lỗi: Không tìm thấy file {data_path}. Hãy chạy log_parser.py trước!")
        return
    
    df = pd.read_csv(data_path)
    
    # 2. Khởi tạo mô hình Isolation Forest
    # Tham số contamination quy định tỷ lệ dữ liệu bất thường ước tính (ví dụ: 5%)
    print("[*] Đang huấn luyện mô hình Isolation Forest...")
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(df)
    
    # 3. Tính toán Threshold (Ngưỡng quyết định) mới
    # Isolation Forest tính toán scores: điểm càng thấp càng có nguy cơ là bất thường
    scores = model.decision_function(df)
    
    # Lấy ngưỡng dựa trên tỷ lệ contamination (phân vị thứ 5)
    # Các bản ghi có score thấp hơn ngưỡng này sẽ bị coi là cuộc tấn công
    import numpy as np
    new_threshold = np.percentile(scores, 5) 
    
    # 4. Lưu mô hình (.pkl) và ngưỡng mới (.json)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
        
    threshold_data = {
        "anomaly_threshold": float(new_threshold),
        "features_used": list(df.columns)
    }
    
    with open(threshold_path, 'w') as f:
        json.dump(threshold_data, f, indent=4)
        
    print(f"[+] Huấn luyện hoàn tất!")
    print(f"[+] Đã lưu mô hình mới tại: {model_path}")
    print(f"[+] Ngưỡng quyết định mới ({new_threshold:.4f}) đã ghi vào: {threshold_path}")

if __name__ == "__main__":
    DATA_PATH = "2_data_pipeline/baseline_features.csv"
    MODEL_PATH = "3_ml_model/isolation_forest.pkl"
    THRESHOLD_PATH = "3_ml_model/thresholds.json"
    
    train_new_model(DATA_PATH, MODEL_PATH, THRESHOLD_PATH)