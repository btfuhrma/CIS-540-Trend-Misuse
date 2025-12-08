import json
import glob
import re
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np

file_pattern = "VirusTotalResults/vt_scan_log_*.json"

all_results = []

def extract_engine_region(csv_path):
    """
    Extract region (us/uk/etc.) and search engine (google/ddg/bing/etc.)
    from the CSV filename.
    """
    match = re.search(r"([a-z]{2})_([a-z]+)_results", csv_path)
    if match:
        region, engine = match.group(1), match.group(2)
        return region, engine
    return "unknown", "unknown"


# -----------------------------------------------------------
# Load and annotate all results
# -----------------------------------------------------------

for file_path in glob.glob(file_pattern):
    with open(file_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"Skipping malformed file: {file_path}")
            continue

        results = data.get("results", [])
        for r in results:
            csv_src = r.get("csv_source", "")
            region, engine = extract_engine_region(csv_src)
            if region == "unknown" or engine == "unknown":
                pass  # Skip if we can't determine engine/region

            all_results.append({
                "search_term": r.get("search_term", ""),
                "url": r.get("url", ""),
                "malicious": r.get("malicious_count", 0),
                "suspicious": r.get("suspicious_count", 0),
                "safe": r.get("safe_count", 0),
                "timestamp": r.get("timestamp", ""),
                "engine": engine,
                "region": region
            })


# -----------------------------------------------------------
# GLOBAL (all search engines) — PIE CHART
# -----------------------------------------------------------

malicious_count = sum(1 for r in all_results if r["malicious"] > 0)
suspicious_count = sum(1 for r in all_results if r["malicious"] == 0 and r["suspicious"] > 0)
safe_count = sum(1 for r in all_results if r["malicious"] == 0 and r["suspicious"] == 0)

labels = ["Malicious", "Suspicious", "Safe"]
sizes = [malicious_count, suspicious_count, safe_count]

plt.figure(figsize=(7, 7))
plt.pie(sizes, labels=labels, autopct="%1.1f%%")
plt.title("Classification Distribution of URLs (All Search Engines)")
plt.tight_layout()
plt.savefig("classification_pie_all_engines.png")
plt.close()

print("Saved: classification_pie_all_engines.png")


# -----------------------------------------------------------
# GLOBAL — MALICIOUS FLAG DISTRIBUTION BAR GRAPH
# -----------------------------------------------------------

malicious_values = [r["malicious"] for r in all_results]
count_by_value = Counter(malicious_values)
sorted_keys = sorted(count_by_value.keys())
sorted_counts = [count_by_value[k] for k in sorted_keys]

plt.figure(figsize=(10, 5))
plt.bar(sorted_keys, sorted_counts)
plt.yscale("log")
plt.xlabel("Malicious Count")
plt.ylabel("Number of Websites (log scale)")
plt.title("Malicious Flag Count Distribution (All Search Engines)")
plt.tight_layout()
plt.savefig("malicious_distribution_log_all_engines.png")
plt.close()

print("Saved: malicious_distribution_log_all_engines.png")


# -----------------------------------------------------------
# PER-SEARCH-ENGINE GRAPHS
# -----------------------------------------------------------

engines = sorted(set(r["engine"] for r in all_results))

for engine in engines:
    subset = [r for r in all_results if r["engine"] == engine]
    if not subset:
        continue

    # PIE chart counts
    mal = sum(1 for r in subset if r["malicious"] > 0)
    sus = sum(1 for r in subset if r["malicious"] == 0 and r["suspicious"] > 0)
    safe = sum(1 for r in subset if r["malicious"] == 0 and r["suspicious"] == 0)

    labels = ["Malicious", "Suspicious", "Safe"]
    sizes = [mal, sus, safe]

    plt.figure(figsize=(7, 7))
    plt.pie(sizes, labels=labels, autopct="%1.1f%%")
    plt.title(f"Classification Distribution — {engine.upper()}")
    plt.tight_layout()
    plt.savefig(f"classification_pie_{engine}.png")
    plt.close()

    print(f"Saved: classification_pie_{engine}.png")

    # MALICIOUS distribution
    malicious_vals = [r["malicious"] for r in subset]
    count_vals = Counter(malicious_vals)

    keys = sorted(count_vals.keys())
    counts = [count_vals[k] for k in keys]

    plt.figure(figsize=(10, 5))
    plt.bar(keys, counts)
    plt.yscale("log")
    plt.xlabel("Malicious Count")
    plt.ylabel("Number of Websites (log scale)")
    plt.title(f"Malicious Flag Distribution — {engine.upper()}")
    plt.tight_layout()
    plt.savefig(f"malicious_distribution_log_{engine}.png")
    plt.close()

    print(f"Saved: malicious_distribution_log_{engine}.png")


# -----------------------------------------------------------
# Region Individual GRAPHS
# -----------------------------------------------------------

region = sorted(set(r["region"] for r in all_results))

for region in region:
    subset = [r for r in all_results if r["region"] == region]
    if not subset:
        continue

    # PIE chart counts
    mal = sum(1 for r in subset if r["malicious"] > 0)
    sus = sum(1 for r in subset if r["malicious"] == 0 and r["suspicious"] > 0)
    safe = sum(1 for r in subset if r["malicious"] == 0 and r["suspicious"] == 0)

    labels = ["Malicious", "Suspicious", "Safe"]
    sizes = [mal, sus, safe]

    plt.figure(figsize=(7, 7))
    plt.pie(sizes, labels=labels, autopct="%1.1f%%")
    plt.title(f"Classification Distribution — {region.upper()}")
    plt.tight_layout()
    plt.savefig(f"classification_pie_{region}.png")
    plt.close()

    print(f"Saved: classification_pie_{region}.png")

    # MALICIOUS distribution
    malicious_vals = [r["malicious"] for r in subset]
    count_vals = Counter(malicious_vals)

    keys = sorted(count_vals.keys())
    counts = [count_vals[k] for k in keys]

    plt.figure(figsize=(10, 5))
    plt.bar(keys, counts)
    plt.yscale("log")
    plt.xlabel("Malicious Count")
    plt.ylabel("Number of Websites (log scale)")
    plt.title(f"Malicious Flag Distribution — {region.upper()}")
    plt.tight_layout()
    plt.savefig(f"malicious_distribution_log_{region}.png")
    plt.close()

    print(f"Saved: malicious_distribution_log_{region}.png")

# -----------------------------------------------------------
# GROUPED MALICIOUS DISTRIBUTION (ALL COUNTRIES)
# -----------------------------------------------------------

regions = sorted(set(r["region"] for r in all_results))

# Build malicious distributions per region
region_dist = {}
all_mal_counts = set()

for region in regions:
    subset = [r["malicious"] for r in all_results if r["region"] == region]
    count = Counter(subset)
    region_dist[region] = count
    all_mal_counts.update(count.keys())

all_mal_counts = sorted(all_mal_counts)

x = np.arange(len(all_mal_counts))
bar_width = 0.8 / len(regions)  # Fit all bars cleanly

plt.figure(figsize=(14, 6))

for i, region in enumerate(regions):
    counts = [region_dist[region].get(mc, 0) for mc in all_mal_counts]
    plt.bar(x + i * bar_width, counts, width=bar_width, label=region.upper())

plt.yscale("log")
plt.xlabel("Malicious Count")
plt.ylabel("Number of URLs (log scale)")
plt.title("Malicious Distribution by Country (Grouped)")
plt.xticks(x + bar_width * len(regions) / 2, all_mal_counts)
plt.legend()
plt.tight_layout()
plt.savefig("malicious_distribution_grouped_countries.png")
plt.close()

print("Saved: malicious_distribution_grouped_countries.png")


# -----------------------------------------------------------
# GROUPED MALICIOUS DISTRIBUTION (SEARCH ENGINES)
# -----------------------------------------------------------

engines = sorted(set(r["engine"] for r in all_results))

engine_dist = {}
all_mal_counts = set()

for engine in engines:
    subset = [r["malicious"] for r in all_results if r["engine"] == engine]
    count = Counter(subset)
    engine_dist[engine] = count
    all_mal_counts.update(count.keys())

all_mal_counts = sorted(all_mal_counts)

x = np.arange(len(all_mal_counts))
bar_width = 0.8 / len(engines)

plt.figure(figsize=(14, 6))

for i, engine in enumerate(engines):
    counts = [engine_dist[engine].get(mc, 0) for mc in all_mal_counts]
    plt.bar(x + i * bar_width, counts, width=bar_width, label=engine.upper())

plt.yscale("log")
plt.xlabel("Malicious Count")
plt.ylabel("Number of URLs (log scale)")
plt.title("Malicious Distribution by Search Engine")
plt.xticks(x + bar_width * len(engines) / 2, all_mal_counts)
plt.legend()
plt.tight_layout()
plt.savefig("malicious_distribution_grouped_engines.png")
plt.close()

print("Saved: malicious_distribution_grouped_engines.png")

wanted_engines = ["google", "ddg"]

engine_counts = {}

for engine in wanted_engines:
    subset = [r for r in all_results if r["engine"] == engine]
    if not subset:
        continue

    mal = sum(1 for r in subset if r["malicious"] > 0)
    sus = sum(1 for r in subset if r["malicious"] == 0 and r["suspicious"] > 0)
    safe = sum(1 for r in subset if r["malicious"] == 0 and r["suspicious"] == 0)

    engine_counts[engine] = [safe, sus, mal]

categories = ["Safe", "Suspicious", "Malicious"]
x = np.arange(len(categories))
bar_width = 0.35

plt.figure(figsize=(10, 6))

for i, engine in enumerate(wanted_engines):
    if engine in engine_counts:
        plt.bar(
            x + i * bar_width,
            engine_counts[engine],
            width=bar_width,
            label=engine.upper()
        )

plt.yscale("log")   # <-- LOG SCALE ADDED
plt.xlabel("Classification")
plt.ylabel("Number of URLs (log scale)")
plt.title("Comparison of Safe / Suspicious / Malicious (Google vs DDG)")
plt.xticks(x + bar_width / 2, categories)
plt.legend()
plt.tight_layout()
plt.savefig("classification_google_vs_ddg_log.png")
plt.close()

print("Saved: classification_google_vs_ddg_log.png")