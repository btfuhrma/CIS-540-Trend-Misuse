#########################################
# CIS 540: Information Security Group Project
# Virus Total Scanner
#########################################
import glob
import os.path
import requests
import time
import json
import base64
import csv
from datetime import datetime
import sys


# Initialize Script
CSV_INPUT_DIR = "./CSV_Search_Results"     # Start at current directory (or enter path to start)
DIR_OUTPUT = "./VirusTotalResults/"        # Create a folder named scan_results

# Running Logs (Only Record Malicious and Suspicious URLS)
running_log_text = "malicious_suspicious_running_log.txt"
running_log_json = "malicious_suspicious_running_log.json"


def get_latest_indiv_csv(search_source):
    # Returns list of all filenames (wildcard) that follow naming pattern. Allows for time dated CSV arguments.
    # Find all files named "google_results***.csv
    wildcard_pattern = os.path.join(CSV_INPUT_DIR, f"{search_source}*.csv")
    csv_files = glob.glob(wildcard_pattern)

    if not csv_files:
        print(f"Error: No CSV files found for {search_source}")
        return None

    # Get the latest (newest) CSV containing URLs to scan. Sort max by timestamp the CSV was last modified (i.e. m-time)
    latest_csv = max(csv_files, key=os.path.getmtime)
    return latest_csv


def get_all_today_csv():
    """Consolidate all incoming search engine CSV's into one list per day."""
    # NOTE: Incoming CSV's must follow the naming convention: source_region_date  ex. google_us_*
    search_sources = [
        "us_google_results_",
        "uk_google_results_",
        "us_ddg_results_",
        "uk_ddg_results_",
        "ru_google_results_",
        "ru_ddg_results_"
    ]

    today_csv_all = []

    for source in search_sources:
        latest = get_latest_indiv_csv(source)
        if latest:
            today_csv_all.append(latest)

    return today_csv_all


def vt_encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def vt_request_results(website, api_key):
    """Scan a single url using Virus Total"""
    id = vt_encode_url(website)
    url = f"https://www.virustotal.com/api/v3/urls/{id}"

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    # Call the Virus Total API. Looks for already completed scan's in VT database.
    response = requests.get(url, headers=headers)
    print(f"Status Code: {response.status_code}")

    if response.status_code != 200:
        return None

    try:
        response_json = json.loads(response.content)

        # Check if data key exists
        if 'data' not in response_json:
            print(f"Unexpected response format for {website}")
            print(f"Response: {response_json}")
            return None

        # Return a dictionary for each call (i.e. URL) with its stats
        return {
            "URL": website,
            "malicious": response_json['data']['attributes']['last_analysis_stats']['malicious'],
            "suspicious": response_json['data']['attributes']['last_analysis_stats']['suspicious'],
            "harmless": response_json['data']['attributes']['last_analysis_stats']['harmless'],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
        }
    except Exception as e:
        print(f"Exception: {e}")
        return None


def vt_scan_all_urls(urls, api_key):
    submissions = set()
    failed_submissions = set()

    for url in urls:
        vt_url = "https://www.virustotal.com/api/v3/urls"
        submit_data = {"url": url}

        # Header for POST request. Requires content-type field for new scans (post request).
        submit_headers = {
            "accept": "application/json",
            "x-apikey": api_key,
            "content-type": "application/x-www-form-urlencoded"
        }

        submission_response = requests.post(vt_url, headers=submit_headers, data=submit_data)
        print(f"Status Code: {submission_response.status_code}")

        if submission_response.status_code == 200:
            submissions.add(url)
            print("Successfully submitted URL for scanning")
        else:
            failed_submissions.add(url)
            print(f"Error submitting URL for scanning {submission_response.status_code}")
        time.sleep(.2)

    print(f"Submissions complete, there was an error for the following files {failed_submissions}")
    return submissions, failed_submissions


def safety_classifier(result):
    """Classifier: Logic for categorizing single URL scan as Safe, Suspicious, or Malicious"""
    if result['malicious'] == 0 and result['suspicious'] == 0:
        return "safe"
    elif result['malicious'] == 0 and result['suspicious'] > 0:
        return "suspicious"
    elif result['malicious'] > 0:
        return "malicious"
    else:
        return "error"


def scan_result_handler(result, website, classification, output_txt_file):
    # Populate output_txt_file.txt file.
    with open(output_txt_file, "a") as file_object:
        if classification == 'malicious':
            file_object.write(f"Malicious: {website} \n")
        elif classification == 'suspicious':
            file_object.write(f"Suspicious: {website}\n")
        elif classification == 'safe':
            file_object.write(f"Safe: {website}\n")
        else:
            file_object.write(f"Error: {website}\n")

    # Update running malicious_suspicious logs (text and json files)
    if classification == 'malicious' or classification == 'suspicious':
        with open(running_log_text, 'a') as running_outfile1:
            running_outfile1.write(f"{classification}: {website}\n")
        with open(running_log_json, 'a') as running_outfile2:
            json.dump(result, running_outfile2, indent=3)


def main():
    # Call method to find latest csv
    API_KEY = sys.argv[1]

    INPUT_CSVS = get_all_today_csv()
    if INPUT_CSVS is None:
        print("Error: No relevant csv file found.")
    print(f"Located {len(INPUT_CSVS)} csv file(s): {INPUT_CSVS}")

    # Create today's output files (.txt and .json) saved to scan_results folder
    time_now = datetime.now().strftime("%Y-%m-%d_%H-%M")
    output_txt_file = os.path.join(DIR_OUTPUT, f"virus_total_results_{time_now}.txt")
    output_json_file = os.path.join(DIR_OUTPUT, f"vt_scan_log_{time_now}.json")

    todays_results = []

    for single_csv in INPUT_CSVS:
        print(f"\nProcessing: {single_csv}")

        url_term_map = {}

        # Open the CSV containing URL's to scan.
        with open(single_csv, 'r', encoding="utf-8") as csv_file_object:
            reader_obj = csv.DictReader(csv_file_object)
            for row in reader_obj:
                url = row['URL']
                term = row["Term"]
                url_term_map[url] = term

            print(f"Successfully read CSV with utf-8 encoding")
            print(f"Found {len(url_term_map)} unique URLs to scan")

        urls = list(url_term_map.keys())
        unresolved = []

        # Call the Virus Total Scanner and Store Results
        for url in urls:
            result = vt_request_results(url, API_KEY)

            if result is None:
                unresolved.append(url)
                continue

            classification = safety_classifier(result)

            todays_results.append({
                "csv_source": single_csv,
                "search_term": url_term_map[url],
                "url": url,
                "classification": classification,
                "timestamp": result["timestamp"],
                "malicious_count": result['malicious'],
                "suspicious_count": result['suspicious'],
                "safe_count": result['harmless']
            })

            scan_result_handler(result, url, classification, output_txt_file)

        if unresolved:
            print(f"\nSubmitting all unresolved URLs for scanning. Count: {len(unresolved)}")
            submitted, failed = vt_scan_all_urls(unresolved, API_KEY)
            unresolved = list(submitted)


        retry_limit = 20
        attempts = 0

        while unresolved and attempts < retry_limit:
            attempts += 1
            print(f"Attempt {attempts}/{retry_limit}: Checking {len(unresolved)} remaining URLs")
            time.sleep(5)

            still_pending = []

            for url in unresolved:
                result = vt_request_results(url, API_KEY)

                if result is None:
                    still_pending.append(url)
                    continue

                classification = safety_classifier(result)

                todays_results.append({
                    "csv_source": single_csv,
                    "search_term": url_term_map[url],
                    "url": url,
                    "classification": classification,
                    "timestamp": result["timestamp"],
                    "malicious_count": result['malicious'],
                    "suspicious_count": result['suspicious'],
                    "safe_count": result['harmless']
                })

                scan_result_handler(result, url, classification, output_txt_file)

            unresolved = still_pending

        if unresolved:
            print(f"WARNING: {len(unresolved)} URLs never produced results.")

    output_data = {
        "date_scanned": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "input_files": INPUT_CSVS,
        "results": todays_results
    }

    with open(output_json_file, "w") as outfile:
        json.dump(output_data, outfile, indent=1)


if __name__ == "__main__":
    main()
