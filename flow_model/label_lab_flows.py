import pandas as pd
import glob
import os

rows = []

# Xử lý các file bình thường (benign)
for f in glob.glob("lab_flow_raw/benign_*.csv"):
    print(f"Đang xử lý file bình thường: {f}")
    df = pd.read_csv(f, low_memory=False)
    df["Label"] = "BENIGN"
    rows.append(df)

# Xử lý các file tấn công từ Lab (attack_arpspoof)
for f in glob.glob("lab_flow_raw/attack_arpspoof_*.csv"):
    print(f"Đang xử lý file tấn công Lab: {f}")
    df = pd.read_csv(f, low_memory=False)
    # Gán nhãn riêng, KHÔNG trùng với các nhãn của CICIDS2017
    df["Label"] = "ARP_MITM_LAB"
    rows.append(df)

# Xử lý thêm file ARP tải từ GitHub (public_arpspoof.pcap_Flow.csv)
# Mặc dù tài liệu không ghi rõ vòng lặp cho file public, nhưng nó RẤT quan trọng để tăng dữ liệu huấn luyện
public_arp_file = "lab_flow_raw/public_arpspoof.pcap_Flow.csv"
if os.path.exists(public_arp_file):
    print(f"Đang xử lý file tấn công Public (GitHub): {public_arp_file}")
    df = pd.read_csv(public_arp_file, low_memory=False)
    df["Label"] = "ARP_MITM_LAB"
    rows.append(df)

# Gộp tất cả lại thành một DataFrame duy nhất
if len(rows) == 0:
    print("LỖI: Không tìm thấy file CSV nào trong lab_flow_raw/")
    exit()

lab_df = pd.concat(rows, ignore_index=True)

# Dọn dẹp lỗi định dạng
lab_df.columns = lab_df.columns.str.strip()
lab_df = lab_df.replace([float("inf"), float("-inf")], pd.NA).dropna()

print("\n--- SỐ LƯỢNG MẪU LAB ĐÃ ĐƯỢC GÁN NHÃN ---")
print(lab_df["Label"].value_counts())

# Xuất ra file CSV tổng hợp
lab_df.to_csv("lab_flow_labeled.csv", index=False)
print("\nĐã lưu kết quả ra file: lab_flow_labeled.csv")
