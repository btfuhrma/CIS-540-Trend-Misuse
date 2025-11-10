import csv
import json
import time
import os
from ddgs import DDGS

def read_terms(csv_path, max_terms=50):
    terms = []
    with open(csv_path, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for i, row in enumerate(reader):
            if i >= max_terms:
                break
            term = row.get("Trend", "").strip()
            if term:
                terms.append(term)
    return terms

def search_term(ddgs, term, max_results=20):
    results = []
    for result_info in ddgs.text(term, max_results=max_results):
        title = result_info.get("title")
        url = result_info.get("href") or result_info.get("link")
        if title and url:
            results.append({"title": title, "url": url})
        if len(results) >= max_results:
            break
    return results

def load_json(master_json):
    if os.path.exists(master_json):
        with open(master_json, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_json(new_data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(new_data, f, ensure_ascii=False, indent=2)

def save_csv(master_data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Term", "Title", "URL"])
        for term, results in master_data.items():
            for r in results:
                writer.writerow([term, r["title"], r["url"]])

def main():
    today = time.strftime("%m-%d-%Y-%H")
    #csv_files = [f"UK_Trends/UK_{today}.csv", f"US_Trends/US_{today}.csv"]
    csv_files = [f"US_Trends/US_{today}.csv"]
    #csv_files = [f"US_11-05-2025-20.csv"]

    master_json = "ddg_results_master.json"
    master_csv = "ddg_results_master.csv"

    ddgs = DDGS()
    master_data = load_json(master_json)
    new_data = {}

    for csv_path in csv_files:
        if not os.path.exists(csv_path):
            print(f"Warning: {csv_path} not found, skipping.")
            continue

        terms = read_terms(csv_path)
        print(f"\nProcessing {csv_path} \nTotal terms found: {len(terms)}")

        for term in terms:
            print(f"\nSearching: {term}")
            try:
                results = search_term(ddgs, term, max_results=20)
                existing_urls = {r["url"] for r in master_data.get(term, [])}
                new_results = [r for r in results if r["url"] not in existing_urls]

                if new_results:
                    if term not in master_data:
                        master_data[term] = []
                    master_data[term].extend(new_results)
                    new_data[term] = new_results

                print(f"  Found {len(new_results)} new results.")
            except Exception as e:
                print(f"Error searching for {term}: {e}")

    # Save updated master JSON and CSV
    save_json(master_data, os.path.join(".", master_json))
    save_csv(master_data, os.path.join(".", master_csv))
    print(f"\nUpdates made to master files:\nJSON: {os.path.join('JSON_ddg_search', master_json)}\nCSV: {os.path.join('CSV_ddg_search', master_csv)}")

    # Save timestamped new results
    if new_data:
        new_json = os.path.join("JSON_Search_Results", f"us_ddg_results_{today}.json")
        new_csv = os.path.join("CSV_Search_Results", f"us_ddg_results_{today}.csv")
        save_json(new_data, new_json)
        save_csv(new_data, new_csv)
        print(f"\nNew results saved to:\nJSON: {new_json}\nCSV: {new_csv}")
    else:
        print("\nNo new data added")

if __name__ == "__main__":
    main()
