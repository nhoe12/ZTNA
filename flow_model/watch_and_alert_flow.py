import subprocess, time, json, glob, os, requests, joblib
import pandas as pd
# --- CẤU HÌNH HỆ THỐNG ---
INTERFACE = "ens33"       # Đảm bảo đúng tên card mạng của bạn
CAPTURE_SECONDS = 15
WORK_DIR = os.path.expanduser("~/flow-automation")
WEBHOOK_URL = "http://localhost:5678/webhook/anomaly-alert"

print("Đang nạp mô hình và cấu hình...")
model = joblib.load(os.path.join(WORK_DIR, "anomaly_model_flow.joblib"))
with open(os.path.join(WORK_DIR, "common_columns.json")) as f:
    feature_cols = json.load(f)

def severity_of_label(label):
    if label == "ARP_MITM_LAB":
        return "critical"
    if label == "BENIGN":
        return None  # Không cảnh báo mạng bình thường
    return "medium"

os.makedirs(f"{WORK_DIR}/live_capture", exist_ok=True)
os.makedirs(f"{WORK_DIR}/live_flow_csv", exist_ok=True)

print(f"Bắt đầu giám sát luồng mạng trên {INTERFACE}...")

while True:
    ts = int(time.time())
    pcap_path = f"{WORK_DIR}/live_capture/{ts}.pcap"
    csv_dir = f"{WORK_DIR}/live_flow_csv/{ts}"
    os.makedirs(csv_dir, exist_ok=True)

    # 1. Bắt gói tin 15 giây
    print(f"[{ts}] Đang bắt gói tin {CAPTURE_SECONDS} giây...")
    try:
        subprocess.run(
            ["tcpdump", "-U", "-i", INTERFACE, "not port 22", "-w", pcap_path, "-G", str(CAPTURE_SECONDS), "-W", "1"],
            timeout=CAPTURE_SECONDS + 5,
            stderr=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        pass

    # 2. Trích xuất đặc trưng bằng CICFlowMeter (ĐÃ VÁ LỖI CWD)
    CICFLOWMETER_CMD = [
        "java",
        "-Djava.library.path=/home/toan/flow-automation/CICFlowMeter/build/install/CICFlowMeter/lib/native",
        "-cp",
        "/home/toan/flow-automation/CICFlowMeter/build/install/CICFlowMeter/lib/*",
        "cic.cs.unb.ca.ifm.Cmd",
        pcap_path,
        csv_dir
    ]
    try:
        r = subprocess.run(
            CICFLOWMETER_CMD,
            cwd=f"{WORK_DIR}/CICFlowMeter",
            capture_output=True,
            text=True,
            timeout=60
        )

        # Đếm số lượng file CSV sinh ra
        csv_files = glob.glob(f"{csv_dir}/*.csv")
        print(f"[{ts}] CICFlowMeter exit={r.returncode}, số CSV={len(csv_files)}")

        if len(csv_files) == 0:
            print(f"[{ts}] CẢNH BÁO: Không có file CSV nào được tạo. Log lỗi CICFlowMeter:")
            print(r.stderr)

    except Exception as e:
        print(f"[{ts}] LỖI CRASH khi chạy CICFlowMeter:", repr(e))
        time.sleep(2)
        continue

    # 3. Phân tích CSV
    csv_files = sorted(glob.glob(f"{csv_dir}/*.csv"))
    if not csv_files:
        print(f"[{ts}] Không có dữ liệu luồng mạng.")
        continue

    df = pd.read_csv(csv_files[-1], low_memory=False)
    df.columns = df.columns.str.strip()

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        print(f"[{ts}] CẢNH BÁO: Dữ liệu thiếu cột:", missing)
        continue

    X_live = df[feature_cols].replace([float("inf"), float("-inf")], pd.NA).dropna()
    if X_live.empty:
        continue

    # 4. Mô hình AI dự đoán
    preds = model.predict(X_live)
    alert_triggered = False
    
    for label in set(preds):
        sev = severity_of_label(label)
        if sev is None:
            continue

        alert_triggered = True
        payload = {
            "model_source": "flow",
            "predicted_label": label,
            "severity": sev,
            "source": "cicflowmeter-live",
            "event_rate": len(df),
        }
        try:
            requests.post(WEBHOOK_URL, json=payload, timeout=5)
            print(f"[{ts}] PHÁT HIỆN TẤN CÔNG: {label} ({sev.upper()}) -> Đã gửi Webhook")
        except requests.RequestException as e:
            print(f"[{ts}] Lỗi gửi webhook:", e)

    if not alert_triggered:
        print(f"[{ts}] Mạng an toàn.")

    time.sleep(1)
