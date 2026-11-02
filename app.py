
import streamlit as st
import os
import json
import hashlib
import pandas as pd
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

st.set_page_config(
    page_title="File Integrity Monitor",
    page_icon="🛡️",
    layout="wide"
)

MONITORED_FOLDER = "monitored_files"
BASELINE_FILE = "baseline.json"
HISTORY_FILE = "scan_history.json"


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_files():
    current_files = {}

    for root, dirs, files in os.walk(MONITORED_FOLDER):
        for filename in files:
            full_path = os.path.join(root, filename)
            relative_path = os.path.relpath(
                full_path, MONITORED_FOLDER
            )
            current_files[relative_path] = calculate_hash(full_path)

    return current_files


def create_baseline():
    files = scan_files()

    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(files, file, indent=4)

    return len(files)


def check_integrity():
    if not os.path.exists(BASELINE_FILE):
        return None

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    current = scan_files()
    alerts = []

    for path, old_hash in baseline.items():
        if path not in current:
            alerts.append({
                "File": path,
                "Status": "Deleted",
                "Severity": "High"
            })
        elif current[path] != old_hash:
            alerts.append({
                "File": path,
                "Status": "Modified",
                "Severity": "High"
            })

    for path in current:
        if path not in baseline:
            alerts.append({
                "File": path,
                "Status": "New File",
                "Severity": "Medium"
            })

    return alerts


def save_scan_history(alerts):
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            history = json.load(file)
    else:
        history = []

    entry = {
        "Scan Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Total Alerts": len(alerts),
        "Result": "Changes Detected" if alerts else "No Changes"
    }

    history.append(entry)

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=4)



os.makedirs(MONITORED_FOLDER, exist_ok=True)

st.subheader("Upload a File to Monitor")

uploaded_file = st.file_uploader(
    "Choose a file",
    key="file_upload"
)

if uploaded_file is not None:
    save_path = os.path.join(
        MONITORED_FOLDER,
        os.path.basename(uploaded_file.name)
    )

    if st.button("Save Uploaded File"):
        with open(save_path, "wb") as file:
            file.write(uploaded_file.getvalue())

        st.success(
            f"{uploaded_file.name} saved successfully. "
            "Create or update the baseline to record it."
        )

st_autorefresh(
    interval=10000,
    limit=None,
    key="automatic_refresh"
)
if "alerts" not in st.session_state:
    st.session_state["alerts"] = None

if "scan_time" not in st.session_state:
    st.session_state["scan_time"] = None

st.title("🛡️ File Integrity Monitoring System")

st.success("🟢 Automatic Monitoring Enabled — scanning every 10 seconds")

st.caption("Monitor file changes using SHA-256 cryptographic hashes.")

st.divider()

col1, col2 = st.columns(2)

with col1:
    if st.button("Create / Update Baseline", use_container_width=True):
        count = create_baseline()
        st.success(f"Baseline saved successfully! Files recorded: {count}")

with col2:
    
    if st.button("Scan File Integrity", use_container_width=True):
        st.session_state["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st.session_state["alerts"] = check_integrity()

    if st.session_state["alerts"] is not None:
        save_scan_history(st.session_state["alerts"])

        

# Automatic file integrity scan
if "last_auto_scan" not in st.session_state:
    st.session_state["last_auto_scan"] = datetime.now()

if (datetime.now() - st.session_state["last_auto_scan"]).total_seconds() >= 10:
    scan_result = check_integrity()

    if scan_result is not None:
        # Create a consistent signature of the current alerts
        signature = json.dumps(scan_result, sort_keys=True)

        previous_signature = st.session_state.get(
            "last_auto_alert_signature"
        )

        # Update the dashboard with the latest scan
        st.session_state["alerts"] = scan_result
        st.session_state["scan_time"] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Save history only when the alert state changes
        if signature != previous_signature:
            save_scan_history(scan_result)
            st.session_state["last_auto_alert_signature"] = signature

    st.session_state["last_auto_scan"] = datetime.now()



st.divider()

if not os.path.exists(BASELINE_FILE):
    st.warning("No baseline found. Create a baseline to begin monitoring.")
else:
    st.info("A saved baseline is available.")

if "alerts" in st.session_state:
    alerts = st.session_state["alerts"]

    if alerts is None:
        st.warning("Create a baseline before scanning.")
    else:
        total = len(alerts)
        modified = sum(a["Status"] == "Modified" for a in alerts)
        deleted = sum(a["Status"] == "Deleted" for a in alerts)
        new_files = sum(a["Status"] == "New File" for a in alerts)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Alerts", total)
        c2.metric("Modified", modified)
        c3.metric("Deleted", deleted)
        c4.metric("New Files", new_files)
        
        st.subheader("📊 Security Alert Analytics")

        chart_data = pd.DataFrame({
            "Alert Type": ["Modified", "Deleted", "New File"],
            "Count": [modified, deleted, new_files]
        })

        st.bar_chart(
            chart_data,
            x="Alert Type",
            y="Count",
            color="Alert Type"
        )

        
        st.subheader("🚨 Alert Severity Distribution")

        if alerts:
            severity_data = pd.DataFrame(alerts)

            severity_counts = (
                severity_data["Severity"]
                .value_counts()
                .reindex(["High", "Medium"], fill_value=0)
                .reset_index()
            )

            severity_counts.columns = ["Severity", "Count"]

            st.bar_chart(
                severity_counts,
                x="Severity",
                y="Count"
            )
        else:
            st.info("No security alerts to display.")



        st.subheader("Security Scan Results")

        if total == 0:
            st.success("No changes detected. Files are unchanged.")
        else:
            st.error(f"{total} security alert(s) detected!")
            st.dataframe(alerts, use_container_width=True)

        st.caption(
            "Last scan: " +
            st.session_state.get("scan_time", "Not scanned yet")
        )
        
        st.divider()
        st.subheader("📥 Download Security Report")

        if alerts:
            report_df = pd.DataFrame(alerts)
            report_df.insert(
                0,
                "Scan Time",
                st.session_state.get("scan_time", "")
            )

            csv_data = report_df.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="Download Report as CSV",
                data=csv_data,
                file_name="security_report.csv",
                mime="text/csv"
            )
        else:
            st.info("No security alerts to download.")


st.divider()
st.caption("Educational project • Python • SHA-256 • Streamlit")



st.divider()
st.subheader("📋 Scan History")

if os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "r", encoding="utf-8") as file:
        history = json.load(file)

    if history:
        st.dataframe(
            history[::-1],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No scan history available yet.")
else:
    st.info("No scan history available yet. Run your first scan.")

