import pandas as pd
import glob

files = glob.glob("cicids2017_raw/*.csv")
df = pd.concat([pd.read_csv(f, low_memory=False) for f in files], ignore_index=True)

# Dọn lỗi định dạng thường gặp của CICIDS2017
df.columns = df.columns.str.strip()
df = df.replace([float("inf"), float("-inf")], pd.NA).dropna()
df = df[df["Label"] != "Label"]

print("--- CÁC NHÃN THẬT CÓ TRONG FILE GỐC ---")
print(df["Label"].value_counts())

# Lọc đúng nhãn proxy đã chọn ở mục 2.1
proxy_labels = [
    "BENIGN",
    "FTP-Patator", "SSH-Patator",
    "Heartbleed",
    "PortScan",
    "DDoS",
    "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest",
]
df_filtered = df[df["Label"].isin(proxy_labels)]

# Loại cột định danh để tránh data leakage
leak_cols = ["Flow ID", "Source IP", "Source Port", "Destination IP",
             "Destination Port", "Timestamp"]
df_filtered = df_filtered.drop(columns=[c for c in leak_cols if c in df_filtered.columns])

df_filtered.to_csv("cicids2017_filtered.csv", index=False)
print("\n--- SAU KHI LỌC ---")
print(df_filtered["Label"].value_counts())
