import json
import glob
import requests
from bs4 import BeautifulSoup


file_pattern = "VirusTotalResults/vt_scan_log_*.json"

all_results = []

for file_path in glob.glob(file_pattern):
    # Open each day's VT scanlog
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"Skipping malformed file: {file_path}")
            continue

        # Consolidate all VT scan logs into one list.
        results = data.get("results", [])
        for r in results:
            all_results.append({
                "country": r.get("country", "Not Available"),
                "engine": r.get("engine", "Not Available"),
                "search_term": r.get("search_term", ""),
                "url": r.get("url", ""),
                "classification": r.get("classification", ""),
                "malicious_count": r.get("malicious_count", 0),    #Note: Not count of URL's. Count of VT flags tripped.
                "suspicious_count": r.get("suspicious_count", 0),  #Note: Not count of URL's. Count of VT flags tripped.
                "safe_count": r.get("safe_count", 0),
                "timestamp": r.get("timestamp", "")
            })


# Convert Consolidated VT Data List to Consolidated JSON. Save as external JSON
with open("consolidated_VT_data.json", 'w') as file:
    json.dump(all_results, file, indent=4)


