# ZTNA AI Automation: mô hình Flow chạy dữ liệu thật

Chứa mã nguồn, mô hình đã huấn luyện và cấu hình để chạy giám sát luồng mạng
bằng CICFlowMeter + Random Forest, gửi cảnh báo qua n8n.
Dữ liệu (pcap, CSV, CICIDS2017) không đưa lên repo.

## Cấu trúc
- flow_model/    script, common_columns.json, anomaly_model_flow.joblib
- CICFlowMeter/  bản đã build (nguồn gốc: system-config/cicflowmeter-version.txt)
- system-config/ service systemd, pip freeze, phiên bản Java/OS, quyền tcpdump
- n8n/           workflow cảnh báo
- docs/          tài liệu hướng dẫn

## Chạy lại
sudo apt install -y openjdk-11-jdk libpcap-dev tcpdump
python3 -m venv ~/flow-automation/venv && source ~/flow-automation/venv/bin/activate
pip install -r system-config/requirements-flow.txt
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which tcpdump))
Đặt flow_model/* và CICFlowMeter/ vào ~/flow-automation/, sửa INTERFACE và
đường dẫn trong watch_and_alert_flow.py, rồi tạo service theo
system-config/anomaly-watcher-flow.service.txt.
