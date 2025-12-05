import json
import pandas as pd
import plotly.express as px

# Open & Read In From "Consolidated_VT_data.json"
with open('consolidated_VT_data.json') as file_object:
    all_VT_data = json.load(file_object)

# Convert to Data Frame (Main Record)-> Easier to Graph
data_frame = pd.DataFrame(all_VT_data)

# Creates column in data frame to store boolean flag. Allows for filtering out where country / search engine not saved.
# Note: Initially data collection (1st week) did not record the country or search engine used. Updated in 2nd week.
# Not Available will return 1; Available country / search engine data return 0.
data_frame['is_not_available'] = ((data_frame['country'] == 'Not Available') |
                                  (data_frame['engine'] == 'Not Available')).astype(int)

# Filter out URL's where search engine used / country were not recorded
data_frame = data_frame[data_frame['is_not_available'] == 0]

########################### STRICT "Malicious" and "Suspicious" Categorizations #################################
# NOTE: For the STRICT categorizations, any positive VirusTotal identification results in URL being labeled
# as Malicious or Suspicious.

# Columns for Binary Flags in DataFrame
# I.E. Each malicious likely results in multiple detections (counts).
# Don't want to sum counts of VT detection. Want to sum malicious URL's.
data_frame['is_malicious'] = (data_frame['malicious_count'] > 0).astype(int)    # Returns Boolean (1 true; 0 false).
data_frame['is_suspicious'] = ((data_frame['suspicious_count'] > 0) & (data_frame['malicious_count'] == 0)).astype(int)
data_frame['is_threat'] = ((data_frame['malicious_count'] > 0) | (data_frame['suspicious_count'] > 0)).astype(int)

print(f"Strict Classification Criteria:")
print(f"Total URL's analyzed: {len(data_frame)}")
print(f"Malicious URLs: {data_frame['is_malicious'].sum()}")
print(f"Suspicious URLs: {data_frame['is_suspicious'].sum()}")
print(f"Total threat URLs: {data_frame['is_threat'].sum()}")

# print(data_frame.head(50))

############################ RELAXED "Malicious" and "Suspicious" Categorizations ##############################
# NOTE: Noticed during data analysis that many of the URL's were categorized as malicious or suspicious by only one (1)
# of the seventy plus (70+) malware detection tools. This infers that the other detection tools did not consider the URL
# as harmful. Updated the categorization criteria with "Relaxed Standards" so that only URL's >= 2 VirusTotal Positive
# ID's are actually classified as malicious or suspicious. This significantly reduced the number of malicious and
# suspicious URL results.


print("\n")
# Columns for Binary Flags in DataFrame
# I.E. Each malicious likely results in multiple detections (counts).
# Don't want to sum counts of VT detection. Want to sum malicious URL's.
data_frame['is_malicious_relaxed'] = (data_frame['malicious_count'] >= 2).astype(int)    # Returns Boolean (1 true; 0 false).
data_frame['is_suspicious_relaxed'] = ((data_frame['suspicious_count'] >= 2) & (data_frame['malicious_count'] == 0)).astype(int)
data_frame['is_threat_relaxed'] = ((data_frame['is_malicious_relaxed'] >= 1) | (data_frame['is_suspicious_relaxed'] >= 1)).astype(int)

print("-----------------------------------")
print(f"Relaxed Classification Criteria")
print(f"Total URL's analyzed: {len(data_frame)}")
print(f"Malicious URLs (Relaxed Criteria): {data_frame['is_malicious_relaxed'].sum()}")
print(f"Suspicious URLs (Relaxed Criteria): {data_frame['is_suspicious_relaxed'].sum()}")
print(f"Total threat URLs (Relaxed Criteria): {data_frame['is_threat_relaxed'].sum()}")


# ############################################ Graphs / Plots ########################################################

# #################### GRAPH 1: Malicious Rate by Country - Stringent Criteria #######################################

country = data_frame.groupby('country').agg({
    'is_malicious': 'sum',
    'is_suspicious': 'sum',
    'is_threat': 'sum',
    'url': 'count'
}).reset_index()

country.columns = ['country', 'malicious_urls', 'suspicious_urls', 'threat_urls', 'total_urls']
country['malicious_rate'] = (country['malicious_urls'] / country['total_urls'] * 100)
country['suspicious_rate'] = (country['suspicious_urls'] / country['total_urls'] * 100)
country['threat_rate'] = (country['threat_urls'] / country['total_urls'] * 100)

fig1 = px.bar(country.sort_values('threat_rate', ascending=False),
              x='country',
              y=['malicious_rate', 'suspicious_rate'],
              title='Malicious and Suspicious Rates (%) by Country',
              labels={'value': 'Rate (%)', 'country': 'Country', 'variable': 'Threat Type'},
              barmode='group',
              color_discrete_map={'malicious_rate': 'darkred',
                                 'suspicious_rate': 'darkorange'})
fig1.update_layout(xaxis_tickangle=-45)
fig1.write_html('threats_by_country.html')
fig1.show()


# ################## GRAPH 2: Threats by Search Engine (Side-by-Side) - Stringent Criteria #############################

engine = data_frame.groupby('engine').agg({
    'is_malicious': 'sum',
    'is_suspicious': 'sum',
    'is_threat': 'sum',
    'url': 'count'
}).reset_index()

engine.columns = ['engine', 'malicious_urls', 'suspicious_urls', 'threat_urls', 'total_urls']
engine['malicious_rate'] = (engine['malicious_urls'] / engine['total_urls'] * 100)
engine['suspicious_rate'] = (engine['suspicious_urls'] / engine['total_urls'] * 100)
engine['threat_rate'] = (engine['threat_urls'] / engine['total_urls'] * 100)

fig2 = px.bar(engine.sort_values('threat_rate', ascending=False),
              x='engine',
              y=['malicious_rate', 'suspicious_rate'],
              title='Malicious and Suspicious Rates (%) by Search Engine',
              labels={'value': 'Rate (%)', 'engine': 'Search Engine', 'variable': 'Threat Type'},
              barmode='group',
              color_discrete_map={'malicious_rate': 'darkgrey',
                                 'suspicious_rate': 'lightgrey'})
fig2.write_html('threats_by_engine.html')
fig2.show()

# #################### GRAPH 3: Malicious Rate by Country - Relaxed Criteria #######################################

country_relaxed = data_frame.groupby('country').agg({
    'is_malicious_relaxed': 'sum',
    'is_suspicious_relaxed': 'sum',
    'is_threat_relaxed': 'sum',
    'url': 'count'
}).reset_index()

country_relaxed.columns = ['country', 'malicious_urls_relaxed', 'suspicious_urls_relaxed', 'threat_urls_relaxed', 'total_urls']
country_relaxed['malicious_rate_relaxed'] = (country_relaxed['malicious_urls_relaxed'] / country_relaxed['total_urls'] * 100)
country_relaxed['suspicious_rate_relaxed'] = (country_relaxed['suspicious_urls_relaxed'] / country_relaxed['total_urls'] * 100)
country_relaxed['threat_rate_relaxed'] = (country_relaxed['threat_urls_relaxed'] / country_relaxed['total_urls'] * 100)

fig3 = px.bar(country_relaxed.sort_values('threat_rate_relaxed', ascending=False),
              x='country',
              y=['malicious_rate_relaxed', 'suspicious_rate_relaxed'],
              title='Malicious and Suspicious Rates (%) by Country - Relaxed Criteria (>= Two VirusTotal Positive IDs)',
              labels={'value': 'Rate (%)', 'country': 'Country', 'variable': 'Threat Type'},
              barmode='group',
              color_discrete_map={'malicious_rate_relaxed': 'darkred',
                                 'suspicious_rate_relaxed': 'darkorange'})
fig3.update_layout(xaxis_tickangle=-45)
fig3.write_html('threats_by_country_relaxed.html')
fig3.show()


# ################## GRAPH 4: Threats by Search Engine (Side-by-Side) - Stringent Criteria #############################


engine_relaxed = data_frame.groupby('engine').agg({
    'is_malicious_relaxed': 'sum',
    'is_suspicious_relaxed': 'sum',
    'is_threat_relaxed': 'sum',
    'url': 'count'
}).reset_index()

engine_relaxed.columns = ['engine', 'malicious_urls_relaxed', 'suspicious_urls_relaxed', 'threat_urls_relaxed', 'total_urls']
engine_relaxed['malicious_rate_relaxed'] = (engine_relaxed['malicious_urls_relaxed'] / engine_relaxed['total_urls'] * 100)
engine_relaxed['suspicious_rate_relaxed'] = (engine_relaxed['suspicious_urls_relaxed'] / engine_relaxed['total_urls'] * 100)
engine_relaxed['threat_rate_relaxed'] = (engine_relaxed['threat_urls_relaxed'] / engine_relaxed['total_urls'] * 100)

fig4 = px.bar(engine_relaxed.sort_values('threat_rate_relaxed', ascending=False),
              x='engine',
              y=['malicious_rate_relaxed', 'suspicious_rate_relaxed'],
              title='Malicious and Suspicious Rates (%) by Search Engine: Relaxed Criteria (>= 2 VT Positive IDs)',
              labels={'value': 'Rate (%)', 'engine': 'Search Engine', 'variable': 'Threat Type'},
              barmode='group',
              color_discrete_map={'malicious_rate_relaxed': 'darkgrey',
                                 'suspicious_rate_relaxed': 'lightgrey'})
fig4.write_html('threats_by_engine.html')
fig4.show()


# ###################################### Print Summary Statistics - Strict Criteria ####################################

print("\n")
print("SUMMARY BY COUNTRY")
print("============================================")
print(country.sort_values('threat_rate', ascending=False).to_string(index=False))

print("\n")
print("SUMMARY BY SEARCH ENGINE")
print("=============================================")
print(engine.sort_values('threat_rate', ascending=False).to_string(index=False))

# #################################### Print Summary Statistics - Relaxed Criteria ##################################

print("\n")
print("SUMMARY BY COUNTRY:  Relaxed Criteria >= 2 VT Positive IDs")
print("=============================================")
print(country_relaxed.sort_values('threat_rate_relaxed', ascending=False).to_string(index=False))

print("\n")
print("SUMMARY BY SEARCH ENGINE: Relaxed Criteria >= 2 VT Positive IDs")
print("=============================================")
print(engine_relaxed.sort_values('threat_rate_relaxed', ascending=False).to_string(index=False))