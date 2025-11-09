#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rate-limit-aware Google CSE collector that:
- Reads top50_twitter_trends.csv (Rank, Trend)
- Fetches RESULTS_PER_TERM results per term with retries & pacing
- Adds per-row UTC timestamps
- Writes per-run timestamped snapshots: google_results_YYYY-MM-DD_HH.{json,csv}
- Updates rolling masters: google_results_master.json (merged, de-duped) and google_results_master.csv (append)
- Checkpoints after each term to never lose progress
"""

# 🔑 CREDENTIALS
GOOGLE_API_KEY = sys.argv[1]
GOOGLE_CSE_ID  = "d5f8a69a19b22423d"

# ⚙️ KNOBS
RESULTS_PER_TERM = 20          # 1..100
PAGE_THROTTLE_SEC = 0.8        # sleep between paginated page requests
RPM_BUDGET = 20                # requests per minute (stay below 25/project/min)
TERM_SLEEP_SEC = 60.0 / max(RPM_BUDGET, 1)  # sleep after each TERM to respect RPM
MAX_RETRIES_429 = 5            # exponential backoff attempts on 429
CHECKPOINT_EVERY_N_TERMS = 1   # write outputs every N terms (masters)
TOP_N_TERMS = 25               # limit to top N terms (set to 50 to process all)

import csv
import json
import time
import math
import requests
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone

GOOGLE_API_ENDPOINT = "https://www.googleapis.com/customsearch/v1"

# ---------- Helpers for time & IO ----------

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _fail(msg: str):
    raise SystemExit(msg)

def _self_test():
    params = {
        "key": GOOGLE_API_KEY,
        "cx": GOOGLE_CSE_ID,
        "q": "hello",
        "num": 1,
        "fields": "items(title,link)"
    }
    r = requests.get(GOOGLE_API_ENDPOINT, params=params, timeout=20)
    if r.status_code != 200:
        try:
            data = r.json()
        except Exception:
            data = {"error": {"message": r.text, "code": r.status_code}}
        _fail(f"Self-test failed (HTTP {r.status_code}). Response:\n{data}")
    j = r.json()
    if not j.get("items"):
        _fail("Self-test returned no items—verify that CX can search the web.")
    print("✅ Self-test OK\n")

def read_top_terms(csv_path: Path, max_terms: int = 50) -> List[Tuple[int, str]]:
    rows: List[Tuple[int, str]] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        try:
            reader = csv.DictReader(f)
            fns = [fn.lower() for fn in (reader.fieldnames or [])]
            if "rank" in fns and "trend" in fns:
                for r in reader:
                    if not r: continue
                    try:
                        rank = int((r.get("Rank") or r.get("rank") or "").strip())
                    except Exception:
                        continue
                    trend = (r.get("Trend") or r.get("trend") or "").strip()
                    if trend: rows.append((rank, trend))
            else:
                raise ValueError("No headers")
        except Exception:
            f.seek(0)
            rdr = csv.reader(f)
            for r in rdr:
                if len(r) < 2: continue
                try:
                    rank = int(str(r[0]).strip())
                except Exception:
                    continue
                trend = str(r[1]).strip()
                if trend: rows.append((rank, trend))
    rows.sort(key=lambda x: x[0])
    return rows[:max_terms]

# ---------- Google API calls with retries ----------

def _google_call(params: Dict[str, Any]) -> Dict[str, Any]:
    """Call Google CSE with retries on 429 and return JSON."""
    backoff = 2.0
    for attempt in range(1, MAX_RETRIES_429 + 1):
        r = requests.get(GOOGLE_API_ENDPOINT, params=params, timeout=30)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 429:
            try:
                data = r.json()
            except Exception:
                data = {"error": {"message": r.text, "code": r.status_code}}
            wait = backoff
            print(f"  ⏳ 429 rate limited. Retry {attempt}/{MAX_RETRIES_429} in {wait:.1f}s ...")
            time.sleep(wait)
            backoff *= 1.6
            continue
        try:
            data = r.json()
        except Exception:
            data = {"error": {"message": r.text, "code": r.status_code}}
        _fail(f"Google API error {r.status_code}: {data}")
    _fail("Exceeded max retries after repeated 429 responses.")

def _google_search_once(query: str, start: int = 1) -> Dict[str, Any]:
    params = {
        "key": GOOGLE_API_KEY,
        "cx": GOOGLE_CSE_ID,
        "q": query,
        "start": start,
        "num": 10,
        "safe": "off",
        "fields": "items(title,link)"
    }
    return _google_call(params)

def google_search(query: str, num: int = RESULTS_PER_TERM) -> List[Dict[str, str]]:
    num = max(1, min(int(num), 100))
    res: List[Dict[str, str]] = []
    pages = math.ceil(num / 10)
    start = 1
    for _ in range(pages):
        data = _google_search_once(query, start=start)
        items = data.get("items") or []
        for it in items:
            title = (it.get("title") or "").strip()
            link = (it.get("link") or "").strip()
            if title and link:
                res.append({"title": title, "url": link})
            if len(res) >= num:
                return res
        if not items:
            break
        start += 10
        time.sleep(PAGE_THROTTLE_SEC)
    return res

# ---------- Writing: snapshots and masters ----------

def write_json_snapshot(p: Path, by_term: Dict[str, list]) -> None:
    p.write_text(json.dumps(by_term, ensure_ascii=False, indent=2), encoding="utf-8")

def write_csv_snapshot(p: Path, rows: List[tuple]) -> None:
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Rank", "Term", "ResultIndex", "Title", "URL", "Timestamp"])
        for row in rows:
            w.writerow(row)

def write_json_master_merge(p: Path, new_by_term: Dict[str, list]) -> None:
    """Merge new results into master JSON (de-duped by URL per term)."""
    master: Dict[str, list] = {}
    if p.exists():
        try:
            master = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            master = {}
    for term, items in new_by_term.items():
        existing = master.get(term, [])
        seen = {it.get("url") for it in existing if isinstance(it, dict)}
        merged = list(existing)
        for it in items:
            u = it.get("url")
            if u and u not in seen:
                merged.append(it)
                seen.add(u)
        master[term] = merged
    p.write_text(json.dumps(master, ensure_ascii=False, indent=2), encoding="utf-8")

def write_csv_master_append(p: Path, rows: List[tuple]) -> None:
    """Append to master CSV; write header if file doesn't exist."""
    header = ["Rank", "Term", "ResultIndex", "Title", "URL", "Timestamp"]
    file_exists = p.exists()
    with p.open("a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if not file_exists:
            w.writerow(header)
        for row in rows:
            w.writerow(row)

# ---------- Main ----------

def main():
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H")
    here = Path(__file__).resolve().parent
    csv_in = "US_Trends/US_"+stamp+".csv"
    snapshot_json = f"./JSON_Search_Results/us_google_results_{stamp}.json"
    snapshot_csv  = f"./CSV_Search_Results/us_google_results_{stamp}.csv"
    master_json   = here / "us_google_results_master.json"
    master_csv    = here / "us_google_results_master.csv"

    if not GOOGLE_API_KEY or not GOOGLE_CSE_ID:
        _fail("Missing GOOGLE_API_KEY / GOOGLE_CSE_ID at top of file.")
    if not csv_in.exists():
        _fail(f"Input CSV not found: {csv_in.name}")

    print("Self-testing credentials...")
    _self_test()

    trends = read_top_terms(csv_in, max_terms=TOP_N_TERMS)
    if not trends:
        _fail(f"No terms found in {csv_in.name}")
    print(f"Loaded {len(trends)} terms")

    by_term_run: Dict[str, list] = {}
    flat_rows_run: List[tuple] = []
    by_term_batch: Dict[str, list] = {}
    flat_rows_batch: List[tuple] = []

    for i, (rank, term) in enumerate(trends, 1):
        print(f"[{i}/{len(trends)}] {term} (rank {rank})")
        try:
            results = google_search(term, num=RESULTS_PER_TERM)
        except SystemExit:
            raise
        except Exception as e:
            print(f"  ⚠️ Error: {e}")
            results = []

        ts = now_utc_iso()
        results_with_ts = [{"title": r.get("title", ""), "url": r.get("url", ""), "timestamp": ts} for r in results]
        by_term_run[term] = results_with_ts

        for j, r in enumerate(results_with_ts, 1):
            flat_rows_run.append((rank, term, j, r["title"], r["url"], r["timestamp"]))
            flat_rows_batch.append((rank, term, j, r["title"], r["url"], r["timestamp"]))
        by_term_batch[term] = results_with_ts

        print(f"  Got {len(results)} results")

        if i % CHECKPOINT_EVERY_N_TERMS == 0 or i == len(trends):
            write_json_master_merge(master_json, by_term_batch)
            write_csv_master_append(master_csv, flat_rows_batch)
            print(f"  💾 master checkpoint saved ({master_json.name}, {master_csv.name})")
            by_term_batch, flat_rows_batch = {}, []

        time.sleep(TERM_SLEEP_SEC)

    write_json_snapshot(snapshot_json, by_term_run)
    write_csv_snapshot(snapshot_csv, flat_rows_run)
    print(f"\n✅ Snapshots written: {snapshot_json.name}, {snapshot_csv.name}")
    print(f"✅ Masters updated:   {master_json.name}, {master_csv.name}")

if __name__ == "__main__":
    main()
