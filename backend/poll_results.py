import requests, json

targets = {
    "TC1": "091c4c37d3666c0d82ea58d536b96bc4fbf5c2d4be99116139fe5bd5eced479c",
    "TC2": "docinstall.top",
    "TC3": "8.8.8.8",
}

print("Polling results...")
for label, target in targets.items():
    r = requests.get("http://127.0.0.1:8000/result", params={"target": target})
    data = r.json()
    status = data.get("status", "unknown")
    risk = data.get("risk_score", "")
    conflict = data.get("integrity_conflict", "")
    report = data.get("report_file", "")
    siem = data.get("siem_file", "")
    soar = data.get("soar_file", "")
    integrity = data.get("integrity_file", "")
    print(f"{label} ({target[:30]}): status={status} risk={risk} conflict={conflict}")
    if status == "completed":
        print(f"  report={report} siem={siem} soar={soar} integrity={integrity}")
    elif status == "error":
        print(f"  ERROR: {data.get('message', '')}")
