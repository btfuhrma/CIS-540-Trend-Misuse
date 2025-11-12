#########################################
# CIS 540: Information Security Group Project
# Virus Total Scanner
#########################################
import glob
import os.path
import vt
import requests
import time
import json
import base64
import csv
from datetime import datetime
import sys


# Initialize Script
CSV_INPUT_DIR = "./CSV_Search_Results"     # Start at current directory (or enter path to start)
DIR_OUTPUT = "./VirusTotalResults/"     # Create a folder named scan_results

# Running Logs (Only Record Malicious and Suspicious URLS)
running_log_text = "malicious_suspicious_running_log.txt"
running_log_json = "malicious_suspicious_running_log.json"

API_KEYS = []
failed_api_keys = set()

def get_latest_indiv_csv(search_source):
    # Returns list of all filenames (wildcard) that follow naming pattern. Allows for time dated CSV arguments.
    # Find all files named "google_results***.csv
    wildcard_pattern = os.path.join(CSV_INPUT_DIR, f"{search_source}*.csv")
    csv_files = glob.glob(wildcard_pattern)             # Return list of all file names that follow the pattern

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
        "uk_ddg_results_"
    ]

    today_csv_all = []

    for source in search_sources:
        latest = get_latest_indiv_csv(source)
        if latest:
            today_csv_all.append(latest)

    return today_csv_all


def scan_url_vt(website):
    """Scan a single url using Virus Total"""
    firstSearch = True
    scanRequired = True
    id = base64.urlsafe_b64encode(f"{website}".encode()).decode().strip("=")    # Required by VT per documentation
    url = f"https://www.virustotal.com/api/v3/urls/{id}"
    for api_key in API_KEYS:
        if api_key in failed_api_keys:
            continue
        if firstSearch:
            headers = {
                "accept": "application/json",
                "x-apikey": api_key
            }

            # Call the Virus Total API. Looks for already completed scan's in VT database.
            response = requests.get(url, headers=headers)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 200:
                return process_response(response, website)
            elif response.status_code == 404:
                print(f"URL not found in Virus Total database: {website}")
                firstSearch = False
            elif response.status_code == 429:
                failed_api_keys.add(api_key)
                print("Virus Total API Key rate limit exceeded during search. Trying next key.")
                continue

        # Check if Virus Total scan was successful. Possible that VT did not have previous scan of url in database.
        if scanRequired:
            # Website may URL not previously scanned / found in database. Submit for scanning.
            print(f"URL not found in Virus Total database. Submitting for scan: {website}")
            vt_url = "https://www.virustotal.com/api/v3/urls"
            submit_data = {"url": website}

            # Header for POST request. Requires content-type field for new scans (post request).
            submit_headers = {
                "accept": "application/json",
                "x-apikey": api_key,
                "content-type": "application/x-www-form-urlencoded"
            }

            submission_response = requests.post(vt_url, headers=submit_headers, data=submit_data)

            if submission_response.status_code == 200:
                scanRequired = False
                print("Successfully submitted URL for scanning. Waiting for result.")
            elif submission_response.status_code == 429:
                print("Virus Total API Key rate limit exceeded during submission. Trying next key.")
                failed_api_keys.add(api_key)
                continue
            else:
                print(f"Error submitting URL: {submission_response.status_code}")
                return None
        if not firstSearch and not scanRequired:
            # API takes time to run scan on new (unseen) website. Wait for new scan to complete.
            max_tries = 5       # Make 5 attempts. Ten-second delay each (see below)
            submit_headers = {
                "accept": "application/json",
                "x-apikey": api_key,
                "content-type": "application/x-www-form-urlencoded"
            }
            for attempt in range(max_tries):
                time.sleep(10)  # Wait 10 seconds allowing VT to complete new scan (i.e. post)

                response = requests.get(url, headers=submit_headers)

                if response.status_code == 200:
                    print(f"Status Code: {response.status_code}. Scan completed successfully.")      # Notify user scan done.
                    return process_response(response, website)
                elif response.status_code == 429:
                    print("Virus Total API Key rate limit exceeded during scan retrieval. Trying next key.")
                    failed_api_keys.add(api_key)
                    break
                elif response.status_code == 404:
                    print(f"Scan still processing for {website}. Attempt {attempt + 1} of {max_tries}. Retrying...")
                    continue
                else:
                    print(f"Error scanning {website}: Status {response.status_code}")
                    print(f"Response: {response.text}")
                    return None
    print("All Virus Total API keys have been exhausted or rate limited.")
    return None

def process_response(response, website):
    try:
        response_json = json.loads(response.content)

        # Check if data key exists
        if 'data' not in response_json:
            print(f"Unexpected response format for {website}")
            print(f"Response: {response_json}")
            return None

        # Return a dictionary for each call (i.e. URL) with its stats
        return{
            "URL": website,
            "malicious": response_json['data']['attributes']['last_analysis_stats']['malicious'],
            "suspicious": response_json['data']['attributes']['last_analysis_stats']['suspicious'],
            "harmless": response_json['data']['attributes']['last_analysis_stats']['harmless'],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")  #Must be converted to String to be accepted by JSON
        }
    except Exception as e:
        print(f"Exception: {e}")
        return None


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


def main():
    # Call method to find latest csv
    API_KEYS = [key.strip() for key in sys.argv[1].split(",")]

    INPUT_CSVS = get_all_today_csv()
    if INPUT_CSVS is None:
        print("Error: No relevant csv file found.")
    print(f"Located {len(INPUT_CSVS)} csv file(s): {INPUT_CSVS}")

    # Create today's output files (.txt and .json) saved to scan_results folder
    time_now = datetime.now().strftime("%Y-%m-%d_%H-%M")
    output_txt_file = os.path.join(DIR_OUTPUT, f"virus_total_results_{time_now}.txt")   #Create timestamped .txt with VT results
    output_json_file = os.path.join(DIR_OUTPUT, f"vt_scan_log_{time_now}.json")          #Create timestamped json with todays VT results

    # List to consolidate results of all CSV's scanned per day (i.e. google_us, ddg_us, etc.)
    todays_results = []

    # Loop through each individual CSV
    for single_csv in INPUT_CSVS:
        print(f"\nProcessing: {single_csv}")

        websites_to_scan = []       # Websites per individual csv
        search_terms = []

        # Open the CSV containing url's to scan. Must be utf-8. Read in URL's to list of websites to scan.
        with open(single_csv, 'r', encoding="utf-8") as csv_file_object:
            reader_obj = csv.DictReader(csv_file_object)
            for row in reader_obj:
                url = row['URL']
                term = row["Term"]
                websites_to_scan.append(url)
                search_terms.append(term)
            print(f"Successfully read CSV with utf-8 encoding")
            print(f"Found {len(websites_to_scan)} URLs to scan")

        # Call the Virus Total Scanner and Store Results
        for i, website in enumerate(websites_to_scan):      # Enumerate to allow matching index in second search_terms list
            result = scan_url_vt(website)          # scan_url returns dictionary w. data. Assign to result

            # Note: Returning None above during errors, allows skipping over failed scans due to encoding issues.
            if result is None:
                print(f"Skipping {website} due to scan error.")
                continue

            classification = safety_classifier(result)      # Pass VT dictionary for single url to classifer method.

            todays_results.append({
                "csv_source": single_csv,
                "search_term": search_terms[i],
                "url": website,
                "classification": classification,
                "timestamp": result["timestamp"],
                "malicious_count": result['malicious'],
                "suspicious_count": result['suspicious'],
                "safe_count": result['harmless']
            })
            time.sleep(15)  # Rate limit due to Virus Total API MAX 4 queries/min

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

            # Update running malicious_suspicious logs (text and json files) with malicious sites per csv.
            # Note: Running log --> So append mode, not write mode (i.e. Avoid overwriting existing data).
            # Updated per website
            if classification == 'malicious' or classification == 'suspicious':
                with open(running_log_text, 'a') as running_outfile1:
                    running_outfile1.write(f"{classification}: {website}\n")
                with open(running_log_json, 'a') as running_outfile2:
                    json.dump(result, running_outfile2, indent=3)

    # Per CSV output of Virus Total findings
    output_data = {
        "date_scanned": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "input_files": INPUT_CSVS,      # List of all csv's scanned today.
        "results": todays_results       # todays_results consolidates results across all CSV's scanned
    }

    with open(output_json_file, "w") as outfile:
        json.dump(output_data, outfile, indent=1)



if __name__ == "__main__":
    main()