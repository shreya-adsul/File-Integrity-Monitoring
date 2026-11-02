
import os
import json
import hashlib
from datetime import datetime

# Folder containing files to monitor
MONITORED_FOLDER = "monitored_files"

# File that stores the original hashes
BASELINE_FILE = "baseline.json"


def calculate_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_files():
    """Calculate hashes for all files in the monitored folder."""
    current_files = {}

    for root, dirs, files in os.walk(MONITORED_FOLDER):
        for filename in files:
            full_path = os.path.join(root, filename)
            relative_path = os.path.relpath(
                full_path, MONITORED_FOLDER
            )

            current_files[relative_path] = calculate_hash(full_path)

    return current_files


def save_baseline():
    """Save the original hashes of the monitored files."""
    files = scan_files()

    with open(BASELINE_FILE, "w", encoding="utf-8") as file:
        json.dump(files, file, indent=4)

    print("\nBaseline created successfully!")
    print("Files recorded:", len(files))


def check_integrity():
    """Detect modified, deleted, and newly added files."""
    if not os.path.exists(BASELINE_FILE):
        print("\nNo baseline found. Create a baseline first.")
        return

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    current = scan_files()
    alerts = 0

    print("\n===== FILE INTEGRITY SCAN =====")

    for path, old_hash in baseline.items():
        if path not in current:
            print("[DELETED]", path)
            alerts += 1
        elif current[path] != old_hash:
            print("[MODIFIED]", path)
            alerts += 1

    for path in current:
        if path not in baseline:
            print("[NEW FILE]", path)
            alerts += 1

    if alerts == 0:
        print("No changes detected. Files are unchanged.")
    else:
        print("\nTotal security alerts:", alerts)

    print("Scan time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def main():
    os.makedirs(MONITORED_FOLDER, exist_ok=True)

    while True:
        print("\n===== FILE INTEGRITY MONITORING =====")
        print("1. Create baseline")
        print("2. Check file integrity")
        print("3. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            save_baseline()
        elif choice == "2":
            check_integrity()
        elif choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
