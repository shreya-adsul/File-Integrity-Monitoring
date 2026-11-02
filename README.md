# File Integrity Monitoring System

## Project Overview
The File Integrity Monitoring System is a Python-based security application designed to monitor files and detect unauthorized changes. It uses the SHA-256 hashing algorithm to maintain file integrity by comparing the current file hash with its previously stored baseline hash.

The application provides a user-friendly dashboard built using Streamlit to display file monitoring results and security alerts.

## Features
- **File Monitoring:** Monitors files stored in the designated directory.
- **SHA-256 Hashing:** Generates unique hashes to verify file integrity.
- **Baseline Creation:** Creates and stores baseline hashes of monitored files.
- **Modification Detection:** Identifies files that have been modified.
- **Deletion Detection:** Detects files that have been deleted.
- **New File Detection:** Identifies newly added files.
- **Security Alerts:** Generates alerts when file changes are detected.
- **Alert Severity:** Displays severity levels such as High and Medium.
- **Interactive Dashboard:** Provides a Streamlit-based interface for monitoring file integrity.

## Technologies Used
- Python
- Streamlit
- SHA-256 Hashing
- JSON
- Pandas

## Project Structure
```text
FileIntegrityMonitoring/
│
├── app.py
├── main.py
├── baseline.json
├── scan_history.json
├── monitored_files/
│   └── sample.txt
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation and Setup

1. Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/File-Integrity-Monitoring.git
```

2. Navigate to the project directory:

```bash
cd File-Integrity-Monitoring
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Run the application:

```bash
streamlit run app.py
```

## How It Works
1. Select the files or directory to be monitored.
2. Create a baseline using SHA-256 hashing.
3. The system stores the generated hashes.
4. Scan the monitored files to compare their current hashes with the stored baseline.
5. The system detects newly added, modified, and deleted files.
6. Security alerts are displayed on the dashboard.

## Learning Outcomes
- Understanding file integrity monitoring concepts.
- Implementing SHA-256 hashing in Python.
- Working with file handling and JSON.
- Detecting unauthorized file modifications.
- Developing an interactive security dashboard using Streamlit.


