from pathlib import Path
from datetime import datetime

from hasher import calculate_hash


def create_baseline(file_path):
    file_hash = calculate_hash(file_path)
    file_size = file_path.stat().st_size
    modified_time = datetime.fromtimestamp(file_path.stat().st_mtime)
    baseline_created = datetime.now()

    baseline = {
        "path": str(file_path),
        "sha256": file_hash,
        "size": file_size,
        "modified_time": modified_time,
        "baseline_created": baseline_created
    }

    return baseline


file_path = Path(r"E:\Sentinel\test_files\important.txt")

baseline = create_baseline(file_path)

print("Path:", baseline["path"])
print("Baseline created:", baseline["baseline_created"].strftime("%Y-%m-%d %H:%M:%S"))
print("SHA-256:", baseline["sha256"])
print("Size:", baseline["size"], "bytes")
print("Modified:", baseline["modified_time"].strftime("%Y-%m-%d %H:%M:%S"))