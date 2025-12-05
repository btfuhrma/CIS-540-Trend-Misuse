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

# #Convert to Data Frame -> Easier to Graph
# data_frame = pd.DataFrame(all_results)
#
# # Create Total Threats column in Dataframe
# data_frame["total_threats"] = data_frame['malicious'] + data_frame['suspicious']
#
# print(f"Total URL's analyzed: {len(data_frame)}")
#
# ################################
# # Graph: Threats by Country
# ################################
#
# country_threats = df.groupby('country').agg({
#     'malicious': 'sum',
#     'suspicious': 'sum',
#     'url': 'sum'
#     }).reset_index()
# country_threats.columns = ['country', 'malicious', 'suspicious', 'total_urls_scanned']
#
#
# fig2 = px.figure
#
#
#
# #######################################################
# # sorted_results = sorted(all_results, key=lambda x: x["malicious"], reverse=True)
#
# # table_data = []
# #
# # for entry in sorted_results[:50]:
# #     search_term = entry['search_term']
# #     url = entry['url']
# #     try:
# #         response = requests.get(url, timeout=10)
# #         html = response.text
# #         soup = BeautifulSoup(html, 'html.parser')
# #         text = soup.get_text().lower()
# #         found = "Yes" if search_term.lower() in text else "No"
# #     except Exception as e:
# #         found = "Error"
# #
# #     table_data.append([
# #         search_term,
# #         url,
# #         entry['malicious'],
# #         entry['suspicious'],
# #         entry['safe'],
# #         entry['timestamp'],
# #         found
# #     ])
# #
# # headers = ["Search Term", "URL", "Malicious", "Suspicious", "Safe", "Timestamp", "Found in HTML"]
# # print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
