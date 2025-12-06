import json
import glob
import requests
from bs4 import BeautifulSoup
from tabulate import tabulate
import matplotlib.pyplot as plt

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
found_counts = {"Yes": 0, "No": 0, "Error": 0}

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
    
    found_counts[found] += 1

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
labels = list(found_counts.keys())
values = list(found_counts.values())

plt.figure(figsize=(7,5))
bars = plt.bar(labels, values)

# Add labels above each bar
for bar in bars:
    height = bar.get_height()
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        height,
        str(height),
        ha='center',
        va='bottom',
        fontsize=12
    )

plt.xlabel("Found in HTML")
plt.ylabel("Count")
plt.title("Distribution of Yes / No / Error (Found in HTML)")
plt.tight_layout()

# Save as PNG
plt.savefig("found_distribution.png", dpi=300)