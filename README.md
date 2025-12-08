This repository contains the scripts, data, and final analysis for a project analyzing the use of malicious and suspicious URLs among trending topics scraped from social media (Twitter/X) and searched across two search engines (Google and DuckDuckGo). The goal was to quantify the rate at which trending search terms lead users to unsafe websites, and analyze how this rate varies by search engine and region between the United States, the United Kingdom, and Russia.

Project Scope
    The core of this project is an automated pipeline that performs continuous data collection, security analysis, and post-processing of web content.
    The pipeline operated in four main stages:
        1. Trend Collection: Sourcing current trending topics from various geographic regions (US, UK, Russia).
        2. Search Result Collection: Querying Google and DuckDuckGo (DDG) for the search results associated with the collected trends.
        3. Security Analysis: Submitting all collected URLs to the VirusTotal API for comprehensive malware and anti-virus scanning.
        4. Post-Processing: Analyzing the content of highly malicious URLs to determine if they explicitly embedded the originating trend term

Components:
    1. Trend Collection - twitterTrendsScraperV2.py - Scrapes real-time trending topics from the chosen web source (twittrend.us) for the US, UK, and Russia.
    2. Search Collection - Uk_trends_to_google_results_keyed_ratelimit.py, us_trends_to_google_results_keyed_ratelimit.py, ru_trends_to_google_results_keyed_ratelimit.py
        Queries Google Custom Search Engine (CSE) for trend results, implementing rate limiting and exponential backoff.
    3. Search Collection - ddg_trends_US.py, ddg_trends_UK.py, ddg_trends_RU.py - Queries DuckDuckGo (DDGS library) for trend results.
    4. Security Analysis - virus_total_check_CSVinput_V2.py - Aggregates daily search results from all regions/engines and submits URLs to the VirusTotal API for scanning.
    5. Post-Processing - sorter.py - Aggregates all VirusTotal logs, sorts URLs by malicious count, and performs HTML content analysis on the top 50 most malicious URLs.

Outputs: 
    1. Raw Search Results: Stored in regional rolling master CSVs (e.g., us_google_results_master.csv, ddg_results_master.csv).
    2. VirusTotal Results: Daily raw JSON files containing the detailed findings from 70+ anti-virus engines for every scanned URL (stored in the VirusTotalResults/ folder).
    3. Malicious Log: A running text file (malicious_suspicious_running_log) that tracks all URLs flagged as malicious or suspicious for long-term monitoring.
    4. Final Content Analysis: The output of sorter.py, which produces a table showing whether the original search trend was found within the fetched HTML of the most malicious pages.

Execution:
    Prerequisites:
        1. Python 3.x
        2. Required libraries (requests, beautifulsoup4, tabulate, ddgs, csv, json, pandas).
        3. Active Google Custom Search Engine (CSE) API Key (for Google search).
        4. Active VirusTotal Academic API Key (The free tier is insufficient for the project's scale).

    To ensure you have all requirements installed, run the commands below:
        python -m pip install --upgrade pip
        pip install -r requirements.txt
    
    Running the Project:
        To run the pipeline manually, execute the scripts in the sequence listed below.
        Disclaimer 1: Reproducing the analysis can be done without steps 1-4 using previously collected data in VirusTotalResults folder.
        Disclaimer 2: Steps 1-4 must be run on the same day as the naming convention of the files is based on dates to use the latest collected data. 
        Disclaimer 3: sorter_v2.py is connected to graph_plotter.py and must be run sequentially. sorter.py, however, can be run by itself. 
        1. Run Trends Scraper
            python twitterTrendsScraperV2.py
        2. Run DDG Collector
            python ddg_trends_US.py
            python ddg_trends_UK.py
            python ddg_trends_RU.py
        3. Run Google Collector (The ${{ secrets.UK_GOOGLE_API_KEY}} is an argument to the python file for the API keys)
            python uk_trends_to_google_results_keyed_ratelimit.py ${{ secrets.UK_GOOGLE_API_KEY}}
            python us_trends_to_google_results_keyed_ratelimit.py ${{ secrets.US_GOOGLE_API_KEY}}
            python ru_trends_to_google_results_keyed_ratelimit.py ${{ secrets.RU_GOOGLE_API_KEY}}
        4. Run VirusTotal (The ${{ secrets.ACADEMIC_API_KEY }} is an argument to the python file for the API key)
            python virus_total_check_CSVinput_V2.py ${{ secrets.ACADEMIC_API_KEY }}
        5. Run Post-Processing
            python sorter.py
            python sorter_v2.py 
            python graph_plotter.py
            
