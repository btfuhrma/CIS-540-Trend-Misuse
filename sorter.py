import json
import glob
import requests
from bs4 import BeautifulSoup
from tabulate import tabulate

file_pattern = "VirusTotalResults/vt_scan_log_*.json"

all_results = []

for file_path in glob.glob(file_pattern):
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"Skipping malformed file: {file_path}")
            continue

        results = data.get("results", [])
        for r in results:
            all_results.append({
                "search_term": r.get("search_term", ""),
                "url": r.get("url", ""),
                "malicious": r.get("malicious_count", 0),
                "suspicious": r.get("suspicious_count", 0),
                "safe": r.get("safe_count", 0),
                "timestamp": r.get("timestamp", "")
            })

sorted_results = sorted(all_results, key=lambda x: x["malicious"], reverse=True)

table_data = []

for entry in sorted_results[:50]:
    search_term = entry['search_term']
    url = entry['url']
    try:
        response = requests.get(url, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text().lower()
        found = "Yes" if search_term.lower() in text else "No"
    except Exception as e:
        found = "Error"
    
    table_data.append([
        search_term,
        url,
        entry['malicious'],
        entry['suspicious'],
        entry['safe'],
        entry['timestamp'],
        found
    ])

headers = ["Search Term", "URL", "Malicious", "Suspicious", "Safe", "Timestamp", "Found in HTML"]
print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
