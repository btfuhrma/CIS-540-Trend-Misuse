import requests
from bs4 import BeautifulSoup
import pandas as pd
from datetime import datetime

LOCATIONS = {
    "US": "https://twittrend.us/",
    "UK": "https://twittrend.us/place/23424975/"
}

TOP_N = 6

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
}

def fetch_trends(url, top_n=TOP_N):
    resp = requests.get(url, headers=HEADERS, timeout=10)
    resp.encoding = 'utf-8'
    soup = BeautifulSoup(resp.text, "lxml")
    trends = []
    trends_items = soup.find_all("p", class_="trend")[:top_n]
    for counter, item in enumerate(trends_items, start=1):
        name = item.find("a").text.strip()
        trends.append({"Rank": counter, "Trend": name})

    df = pd.DataFrame(trends)
    return df

def main():
    today_str = datetime.today().strftime("%m-%d-%Y-%H")
    for country, url in LOCATIONS.items():
        df = fetch_trends(url, TOP_N)
        filename = f"./{country}_Trends/{country}_{today_str}.csv"
        df.to_csv(filename, index=False, encoding="utf-8-sig")
        print(f"Saved {country} trends to {filename}")

main()
