This repository contains the scripts, data, and final analysis for a project analyzing the use of malicious and suspicious URLs among trending topics scraped from social media (Twitter/X) and searched across two search engines (Google and DuckDuckGo). The goal was to quantify the rate at which trending search terms lead users to unsafe websites, and analyze how this rate varies by search engine and region between the United States, the United Kingdom, and Russia.
<br>
#Project Scope <br>
    The core of this project is an automated pipeline that performs continuous data collection, security analysis, and post-processing of web content. <br>
    The pipeline operated in four main stages: <br>
        1. Trend Collection: Sourcing current trending topics from various geographic regions (US, UK, Russia). <br>
        2. Search Result Collection: Querying Google and DuckDuckGo (DDG) for the search results associated with the collected trends. <br>
        3. Security Analysis: Submitting all collected URLs to the VirusTotal API for comprehensive malware and anti-virus scanning. <br>
        4. Post-Processing: Analyzing the content of highly malicious URLs to determine if they explicitly embedded the originating trend term. <br>
<br>
#Components:<br>
    1. Trend Collection - twitterTrendsScraperV2.py - Scrapes real-time trending topics from the chosen web source (twittrend.us) for the US, UK, and Russia. <br>
    2. Search Collection - Uk_trends_to_google_results_keyed_ratelimit.py, us_trends_to_google_results_keyed_ratelimit.py, ru_trends_to_google_results_keyed_ratelimit.py <br>
        Queries Google Custom Search Engine (CSE) for trend results, implementing rate limiting and exponential backoff. <br>
    3. Search Collection - ddg_trends_US.py, ddg_trends_UK.py, ddg_trends_RU.py - Queries DuckDuckGo (DDGS library) for trend results. <br>
    4. Security Analysis - virus_total_check_CSVinput_V2.py - Aggregates daily search results from all regions/engines and submits URLs to the VirusTotal API for scanning. <br>
    5. Post-Processing - sorter.py - Aggregates all VirusTotal logs, sorts URLs by malicious count, and performs HTML content analysis on the top 50 most malicious URLs. <br>
<br>
#Outputs: <br>
    1. Raw Search Results: Stored in regional rolling master CSVs (e.g., us_google_results_master.csv, ddg_results_master.csv). <br>
    2. VirusTotal Results: Daily raw JSON files containing the detailed findings from 70+ anti-virus engines for every scanned URL (stored in the VirusTotalResults/ folder).<br>
    3. Malicious Log: A running text file (malicious_suspicious_running_log) that tracks all URLs flagged as malicious or suspicious for long-term monitoring.<br>
    4. Final Content Analysis: The output of sorter.py, which produces a table showing whether the original search trend was found within the fetched HTML of the most malicious pages.<br>
<br>
#Execution:<br>
    Prerequisites:<br>
        1. Python 3.x<br>
        2. Required libraries (requests, beautifulsoup4, tabulate, ddgs, csv, json, pandas).<br>
        3. Active Google Custom Search Engine (CSE) API Key (for Google search).<br>
        4. Active VirusTotal Academic API Key (The free tier is insufficient for the project's scale).<br>
<br>
    To ensure you have all requirements installed, run the commands below:
        python -m pip install --upgrade pip<br>
        pip install -r requirements.txt<br>
    <br>
    Running the Project:<br>
        To run the pipeline manually, execute the scripts in the sequence listed below.<br>
        Disclaimer 1: Reproducing the analysis can be done without steps 1-4 using previously collected data in VirusTotalResults folder.<br>
        Disclaimer 2: Steps 1-4 must be run on the same day as the naming convention of the files is based on dates to use the latest collected data. <br>
        Disclaimer 3: sorter_v2.py is connected to graph_plotter.py and must be run sequentially. sorter.py, however, can be run by itself. <br>
        1. Run Trends Scraper<br>
            python twitterTrendsScraperV2.py<br>
        2. Run DDG Collector<br>
            python ddg_trends_US.py<br>
            python ddg_trends_UK.py<br>
            python ddg_trends_RU.py<br>
        3. Run Google Collector (The ${{ secrets.UK_GOOGLE_API_KEY}} is an argument to the python file for the API keys)<br>
            python uk_trends_to_google_results_keyed_ratelimit.py ${{ secrets.UK_GOOGLE_API_KEY}}<br>
            python us_trends_to_google_results_keyed_ratelimit.py ${{ secrets.US_GOOGLE_API_KEY}}<br>
            python ru_trends_to_google_results_keyed_ratelimit.py ${{ secrets.RU_GOOGLE_API_KEY}}<br>
        4. Run VirusTotal (The ${{ secrets.ACADEMIC_API_KEY }} is an argument to the python file for the API key)<br>
            python virus_total_check_CSVinput_V2.py ${{ secrets.ACADEMIC_API_KEY }}<br>
        5. Run Post-Processing<br>
            python sorter.py<br>
            python sorter_v2.py <br>
            python graph_plotter.py<br>
            
