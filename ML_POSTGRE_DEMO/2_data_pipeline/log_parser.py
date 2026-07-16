import os
import pandas as pd

def parse_nsl_kdd(input_path, output_path):
    print(f"[*] Đang đọc dữ liệu NSL-KDD từ: {input_path}...")
    
    # Định nghĩa đầy đủ 43 cột của bộ dữ liệu NSL-KDD gốc 
    # (bao gồm 41 đặc trưng, 1 cột nhãn 'label' và 1 cột độ khó 'difficulty')
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
    ]
    
    # 1. Đọc file dữ liệu thô sử dụng thư viện pandas
    try:
        df = pd.read_csv(input_path, names=columns, header=None)
    except FileNotFoundError:
        print(f"[!] Lỗi: Không tìm thấy file tại đường dẫn: {input_path}")
        return
        
    # 2. Lọc ra các đặc trưng (features) dạng SỐ cốt lõi để đưa vào mô hình Isolation Forest
    # Thuật toán này rất mạnh khi làm việc với các chỉ số đo lường dạng số (Numeric)
    selected_features = [
        'duration', 
        'src_bytes', 
        'dst_bytes', 
        'count', 
        'srv_count', 
        'serror_rate', 
        'rerror_rate', 
        'same_srv_rate'
    ]
    
    # Trích xuất tập dữ liệu mới chỉ gồm các cột đã chọn
    baseline_df = df[selected_features]
    
    # 3. Ghi đè dữ liệu mới này vào file baseline_features.csv của dự án
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    baseline_df.to_csv(output_path, index=False)
    
    print(f"[+] Hoàn thành! Đã trích xuất {len(baseline_df)} bản ghi với {len(selected_features)} đặc trưng.")
    print(f"[+] Dữ liệu chuẩn hóa đã lưu tại: {output_path}")

if __name__ == "__main__":
    INPUT_DATASET = "2_data_pipeline/dataset/KDDTrain+.txt" 
    OUTPUT_BASELINE = "2_data_pipeline/baseline_features.csv"
    
    parse_nsl_kdd(INPUT_DATASET, OUTPUT_BASELINE)