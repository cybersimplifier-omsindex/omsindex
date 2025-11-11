################  imports  ##################

import requests
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
import numpy as np
import os
import plotly.graph_objects as go
import nbformat
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import seaborn as sns
import matplotlib.colors as mcolors
from adjustText import adjust_text
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans, AgglomerativeClustering
from sklearn.decomposition import PCA
from matplotlib.patches import Patch


################ changeable inputs  ########################

#path to save are read from
folder=os.path.dirname(os.path.abspath("__file__"))

#defined KEYS:

# VulDB API key
vuldbd_apikey = "YOUR_vuldbd_apikey"
#this is a apikey from vuldba account (set to marta.jozwik@cybersimplifier, we only have 50 credits per day to use)

# GitHub token
token = "YOUR_GitHub_token"
#this token is set to never expire

######################  functional code  #############################

# List of queries
zapytania_do_vuldbd = [
    "nuclei", "Zeek", "OpenBao", "Cilium", "Mattermost", "Safeline", "Keycloak", "zaproxy", "trivy", "Teleport",
    "Passbolt", "hackingtool", "Wireshark", "Grafana", "Wazuh", "Sn1per", "infisical", "Suricata", "EasyEASM",
    "MISP", "OpenCTI", "Prometheus", "TheHive", "OpenVAS", "Velociraptor", "Gophish", "flow", "Elasticsearch",
    "osquery", "Artemis"
]

# Simulated repos_pages DataFrame (replace with your actual data)
repos_pages = pd.DataFrame({'repo_name': zapytania_do_vuldbd})

# Prepare output DataFrame
data_vuldb = pd.DataFrame(columns=["name", "n_vunerabilities_1y", "n_vunerabilities_2y"])


# Define repository owners and names
repo_owner = [
    "projectdiscovery", "zeek", "openbao", "cilium",
    "mattermost", "chaitin", "keycloak", "zaproxy", "aquasecurity", "gravitational",
    "passbolt", "Z4nzu", "wireshark", "grafana", "wazuh", "1N3",
    "infisical", "OISF", "g0ldencybersec", "MISP", "OpenCTI-Platform",
    "prometheus", "TheHive-Project", "greenbone", "Velocidex", "gophish",
    "mixeway", "elastic", "osquery", "CERT-Polska"
]

repo_name = [
    "nuclei", "zeek", "openbao", "cilium",
    "mattermost", "SafeLine", "keycloak", "zaproxy", "trivy", "teleport",
    "passbolt_docker", "hackingtool", "wireshark", "grafana", "wazuh", "Sn1per",
    "infisical", "suricata", "EasyEASM", "MISP", "opencti",
    "prometheus", "TheHive", "openvas-scanner", "velociraptor", "gophish",
    "flow", "elasticsearch", "osquery", "Artemis"
]

# Create DataFrame
repos_pages = pd.DataFrame({
    "repo_owner": repo_owner,
    "repo_name": repo_name
})

# Selected indices (marked yellow in Word)
wybrane = [14, 19, 20, 22, 23, 24, 25, 26, 27, 29]  # Python uses 0-based indexing

# Friendly names
name_nice = [
    "Nuclei", "Zeek", "OpenBao", "Cilium",
    "Mattermost", "Safeline", "Keycloak", "Zaproxy", "Trivy", "Teleport",
    "Passbolt", "Hackingtool", "Wireshark", "Grafana", "Wazuh", "Sn1per",
    "Infisical", "Suricata", "EasyEASM", "MISP", "OpenCTI",
    "Prometheus", "TheHive", "OpenVAS", "Velociraptor", "Gophish",
    "Flow", "Elasticsearch", "osquery", "Artemis"
]

# Loop through each repo
for i in range(len(repos_pages)):
    vuldbd_request_name = zapytania_do_vuldbd[i]
    url = "https://vuldb.com/?api"
    payload = {
            "apikey": vuldbd_apikey,
            "search": vuldbd_request_name,
            "details": 0
    }

    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            data = response.json()
            result = data.get("result", [])

            # Ensure result is a list
            entries = result if isinstance(result, list) else []

            formatted_dates = []
            for j, item in enumerate(entries):
                entry = item.get("entry", {})
                ts_str = entry.get("timestamp", {}).get("create")

                if ts_str:
                    try:
                        ts = int(ts_str)
                        dt = datetime.utcfromtimestamp(ts)
                        formatted_date = dt.strftime('%Y-%m-%d')  # Format as '2025-01-01'
                        formatted_dates.append(formatted_date)
                    except ValueError:
                        print(f"Invalid timestamp format at index {j}: {ts_str}")

            if formatted_dates:
                today = datetime.utcnow()
                one_year_ago = today - timedelta(days=365)
                two_years_ago = today - timedelta(days=730)

                        # Format thresholds for comparison
                one_year_ago_str = one_year_ago.strftime('%Y-%m-%d')
                two_years_ago_str = two_years_ago.strftime('%Y-%m-%d')

                        # Count vulnerabilities based on formatted date strings
                n_vunerabilities_1y = sum(date >= one_year_ago_str for date in formatted_dates)
                n_vunerabilities_2y = sum(date >= two_years_ago_str for date in formatted_dates)
            else:
                print("No valid timestamps found.")
                n_vunerabilities_1y = -1
                n_vunerabilities_2y = -1    
        else:
            print(f"Request failed with status code {response.status_code}")
            n_vunerabilities_1y = -2
            n_vunerabilities_2y = -2

    except Exception as e:
        print(f"Error during processing: {e}")
        n_vunerabilities_1y = -2
        n_vunerabilities_2y = -2

    # Append results
    data_vuldb.loc[i] = [
        repos_pages.loc[i, "repo_name"],
        n_vunerabilities_1y,
        n_vunerabilities_2y
    ]

    print(f"Processed {i + 1}/{len(repos_pages)}")

# Final warning if any failed
if (data_vuldb["n_vunerabilities_1y"] == -2).any():
    #Warning("Warning: Not all connections to VulDB succeeded!")
    raise ValueError("Not all connections to VulDB succeeded! Probably a problem with apikey to vuldb") from None

if (data_vuldb["n_vunerabilities_1y"] == -1).sum()>=10:
    #Warning("Warning: Not all connections to VulDB succeeded!")
    raise ValueError("Not all connections to VulDB succeeded! Probably a problem with apikey to vuldb") from None

# GitHub data
headers = {"Authorization": f"token {token}"}

# Date range: last 30 days
last_day = datetime.today().strftime("%Y-%m-%d")
first_day = (datetime.today() - timedelta(days=30)).strftime("%Y-%m-%d")

# Assuming repos_pages and name_nice are already defined
data_input = []

for i in range(len(repos_pages)):
    repo_owner = repos_pages.loc[i, "repo_owner"]
    repo_name = repos_pages.loc[i, "repo_name"]
    name = name_nice[i]

    print(f"Processing {i + 1}/{len(repos_pages)}: {name}")

    # --- Repo metadata ---
    repo_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
    repo_response = requests.get(repo_url, headers=headers)
    repo_data = repo_response.json()

    # --- Contributors (paginated) ---
    contributors_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contributors"
    all_contributors = []
    page = 1
    per_page = 100

    while True:
        contributors_url_page = f"{contributors_url}?per_page={per_page}&page={page}"
        response = requests.get(contributors_url_page, headers=headers)
        data = response.json()

        if not data or not isinstance(data, list):
            break

        all_contributors.extend(data)
        page += 1

    contributors_df = pd.DataFrame(all_contributors)
    n_contributors = len(contributors_df)
    sum_contributions = contributors_df["contributions"].sum() if "contributions" in contributors_df else 0

    perc_first_10_contributors = (
        contributors_df.sort_values(by="contributions", ascending=False)
        .head(10)["contributions"]
        .sum() / sum_contributions
        if sum_contributions > 0 else 0
    )

    perc_of_1contr_contributors = (
        (contributors_df["contributions"] == 1).sum() / n_contributors
        if n_contributors > 0 else 0
    )

    # --- Releases (paginated) ---
    releases_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/releases"
    all_releases = []
    page = 1

    while True:
        paged_url = f"{releases_url}?per_page={per_page}&page={page}"
        response = requests.get(paged_url, headers=headers)
        page_data = response.json()

        if not page_data or not isinstance(page_data, list):
            break

        all_releases.extend(page_data)
        page += 1

    releases_df = pd.DataFrame([{
        "tag_name": release.get("tag_name"),
        "published_at": release.get("published_at")
    } for release in all_releases])

    n_releases = len(releases_df)
    avg_time_between_releases = 0
    n_releases_last60days = 0
    avg_time_between_releases_last60d = 0
    releases_1m_n = 0

    if n_releases > 1:
        releases_df["published_at"] = pd.to_datetime(releases_df["published_at"])
        releases_df = releases_df.sort_values(by="published_at", ascending=False).reset_index(drop=True)

        date_diffs = releases_df["published_at"].diff().dropna().dt.days
        avg_time_between_releases = date_diffs.mean()

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=60)
        recent_releases = releases_df[releases_df["published_at"] >= cutoff_date]
        n_releases_last60days = len(recent_releases)

        if n_releases_last60days > 1:
            recent_diffs = recent_releases["published_at"].diff().dropna().dt.days
            avg_time_between_releases_last60d = recent_diffs.mean()

        # Releases in last 30 days
        releases_1m_n = len(releases_df[
            (releases_df["published_at"] >= first_day) &
            (releases_df["published_at"] <= last_day)
        ])

    # --- Issues last 30 days ---
    new_issues_url = (
        f"https://api.github.com/search/issues?q=repo:{repo_owner}/{repo_name}"
        f"+is:issue+created:{first_day}..{last_day}"
    )
    new_issues_response = requests.get(new_issues_url, headers=headers)
    new_issues_data = new_issues_response.json()
    new_issues_1m_n = new_issues_data.get("total_count", 0)

    closed_issues_url = (
        f"https://api.github.com/search/issues?q=repo:{repo_owner}/{repo_name}"
        f"+is:issue+is:closed+closed:{first_day}..{last_day}"
    )
    closed_issues_response = requests.get(closed_issues_url, headers=headers)
    closed_issues_data = closed_issues_response.json()
    closed_issues_1m_n = closed_issues_data.get("total_count", 0)

    # --- Commits last 30 days ---
    commits_url = (
        f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits"
        f"?since={first_day}&until={last_day}&per_page=500"
    )
    commits_response = requests.get(commits_url, headers=headers)
    commits_data = commits_response.json()

    authors = [commit.get("author", {}).get("id") for commit in commits_data if commit.get("author")]
    authors_1m_n = len(set(authors))

    # --- Commits from main branch ---
    def get_commits(branch):
        all_commits = []
        page = 1
        while True:
            url = (
                f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits"
                f"?sha={branch}&since={first_day}&until={last_day}&per_page=100&page={page}"
            )
            response = requests.get(url, headers=headers)
            commits = response.json()
            if not commits or not isinstance(commits, list):
                break
            all_commits.extend(commits)
            page += 1
        return pd.DataFrame(all_commits)

    main_commits_df = get_commits("main")
    main_commit_1m_n = len(main_commits_df)

    # --- Security tab existence ---
    security_url = f"https://github.com/{repo_owner}/{repo_name}/security"
    security_response = requests.get(security_url, headers=headers)
    if security_response.status_code == 200:
        sec_policy = "Yes"
    elif security_response.status_code == 404:
        sec_policy = "No"
    else:
        sec_policy = "?"

    # --- FUNDING.yml presence ---
    funding_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/.github/FUNDING.yml"
    funding_response = requests.get(funding_url, headers=headers)
    if funding_response.status_code == 200:
        funding_info = "Repozytorium ma plik FUNDING.yml i prawdopodobnie sponsorów"
    else:
        funding_info = "Brak pliku FUNDING.yml – brak informacji o sponsorach"

    # --- License handling ---
    license_name = repo_data.get("license", {}).get("name") if repo_data.get("license") else "None"

    # --- Final record ---
    details = {
        "name": name,
        "description": repo_data.get("description"),
        "stars": repo_data.get("stargazers_count"),
        "forks": repo_data.get("forks_count"),
        "subscribers_now": repo_data.get("subscribers_count"),
        "open_issues": repo_data.get("open_issues_count"),
        "license": license_name,
        "created_at": repo_data.get("created_at", "")[:10],
        "updated_at": repo_data.get("updated_at", "")[:10],
        "default_branch": repo_data.get("default_branch"),
        "n_contributors": n_contributors,
        "perc_first_10_contributors": perc_first_10_contributors,
        "perc_of_1contr_contributors": perc_of_1contr_contributors,
        "sum_contributions": sum_contributions,
        "avg_time_between_releases": (-1)*avg_time_between_releases,
        "n_releases_last60days": n_releases_last60days,
        "avg_time_between_releases_last60d": (-1)*avg_time_between_releases_last60d,
        "releases_1m_n": releases_1m_n,
        "new_issues_1m_n": new_issues_1m_n,
        "closed_issues_1m_n": closed_issues_1m_n,
        "authors_1m_n": authors_1m_n,
        "main_commit_1m_n": main_commit_1m_n,
        "sec_policy": sec_policy,
        "funding_info": funding_info,
        "n_vunerabilities_1y":0,
        "n_vunerabilities_2y":0,
        "day_of_download": datetime.now(timezone.utc).strftime("%Y-%m-%d")
    }

    data_input.append(details)

# Convert to DataFrame
data_input_df = pd.DataFrame(data_input)

# Assign columns 2 and 3 from data_vuldb to columns 25 and 26 in data_input
# Assuming data_input_df and data_vuldb are pandas DataFrames
data_input_df["n_vunerabilities_1y"] = data_vuldb.iloc[:, 1]
data_input_df["n_vunerabilities_2y"] = data_vuldb.iloc[:, 2]

# Set perc_first_10_contributors to 1 where n_contributors < 10
data_input_df.loc[data_input_df["n_contributors"] < 10, "perc_first_10_contributors"] = 1

# Calculate age in days
# Ensure 'created_at' is converted to datetime
data_input_df["created_at"] = pd.to_datetime(data_input_df["created_at"], errors='coerce')
# Now calculate age in days
data_input_df["age_in_days"] = (datetime.today() - data_input_df["created_at"]).dt.days

# Replace NaN in avg_time_between_releases with age_in_days
mask_nan = data_input_df["avg_time_between_releases"].isna()
data_input_df.loc[mask_nan, "avg_time_between_releases"] = data_input_df.loc[mask_nan, "age_in_days"]

# Convert sec_policy to binary
data_input_df["sec_policy"] = np.where(data_input_df["sec_policy"] == "Yes", 1, 0)

# Convert funding_info to binary
data_input_df["funding_info"] = np.where(
    data_input_df["funding_info"] == "Brak pliku FUNDING.yml – brak informacji o sponsorach", 0, 1
)

# Calculate issue dynamics
data_input_df["issues_dynamic"] = data_input_df["new_issues_1m_n"] - data_input_df["closed_issues_1m_n"]

# Calculate open issues per contributor
data_input_df["open_issues_vs_contributors"] = data_input_df["open_issues"] / data_input_df["n_contributors"]

# Calculate delta vulnerabilities
data_input_df["delta_vunerabilities"] = (
    data_input_df["n_vunerabilities_2y"] - 2 * data_input_df["n_vunerabilities_1y"]
)

# Save current data to CSV
name1 = datetime.today().strftime("%Y-%m-%d")
output_path = f"{folder}{'//'}{name1}.csv"
data_input_df.to_csv(output_path, index=False)



# Select relevant columns for index
cols_to_keep = [0, 2, 3, 4, 11, 12, 14, 15, 22, 24, 27, 28, 29, 30]  # Python uses 0-based indexing
data_input_artificial = data_input_df.iloc[:, cols_to_keep].copy()

# Transform perc_first_10_contributors
data_input_artificial["perc_first_10_contributors"] = abs(data_input_artificial["perc_first_10_contributors"] - 0.6)

# Initialize pkt_releases
data_input_artificial["pkt_releases"] = 0

# Apply release scoring logic
cond = data_input_artificial
pkt = cond["pkt_releases"]  # shortcut

pkt[(cond["avg_time_between_releases"].between(25, 35)) & (cond["n_releases_last60days"].isin([2, 3]))] = 10
pkt[(cond["avg_time_between_releases"].between(15, 45)) & (cond["n_releases_last60days"].isin([2, 3])) & (pkt == 0)] = 8
pkt[(cond["avg_time_between_releases"].between(10, 55)) & (cond["n_releases_last60days"].isin([2, 3])) & (pkt == 0)] = 7
pkt[(cond["avg_time_between_releases"].between(10, 55)) & (cond["n_releases_last60days"].isin([1, 4, 5])) & (pkt == 0)] = 6
pkt[(cond["avg_time_between_releases"] < 10) & (cond["n_releases_last60days"].isin(range(1, 6))) & (pkt == 0)] = 5
pkt[(cond["avg_time_between_releases"] > 55) & (cond["n_releases_last60days"].isin(range(1, 6))) & (pkt == 0)] = 5
pkt[(cond["avg_time_between_releases"] < 10) & (cond["n_releases_last60days"].isin(range(6, 11))) & (pkt == 0)] = 4
pkt[(cond["avg_time_between_releases"] > 55) & (cond["n_releases_last60days"].isin(range(6, 11))) & (pkt == 0)] = 4
pkt[(cond["n_releases_last60days"].isin(range(1, 16))) & (pkt == 0)] = 3
pkt[(cond["n_releases_last60days"] > 0) & (pkt == 0)] = 2
pkt[(cond["avg_time_between_releases"] > 0) & (pkt == 0)] = 1

data_input_artificial["pkt_releases"] = pkt / 10

# Age group
data_input_artificial["age_group"] = np.where(data_input_artificial["age_in_days"] < 356 * 2, 2, 1)
data_input_artificial["age"] = data_input_artificial["age_in_days"]

# Drop columns 7, 8, 11 (Python index: 6, 7, 10)
data_input_artificial.drop(data_input_artificial.columns[[6, 7, 10]], axis=1, inplace=True)

# Invert selected columns
cols_to_invert = ["perc_first_10_contributors", "perc_of_1contr_contributors", "open_issues_vs_contributors", "issues_dynamic"]
data_input_artificial[cols_to_invert] *= -1

# Binning selected columns
data_input_art2_bin = data_input_artificial.copy()
for col in [data_input_art2_bin.columns[1], data_input_art2_bin.columns[2],
            data_input_art2_bin.columns[3], data_input_art2_bin.columns[9]]:
    bins = np.quantile(data_input_art2_bin[col].dropna(), q=np.linspace(0, 1, 11))
    data_input_art2_bin[col] = pd.cut(data_input_art2_bin[col], bins=bins, include_lowest=True, labels=False) / 10

# Scoring n_vunerabilities_1y
vuln = data_input_art2_bin["n_vunerabilities_1y"]
pkt = np.zeros_like(vuln)

pkt[vuln < 0] = 3
pkt[(vuln >= 0) & (vuln <= 3) & (pkt == 0)] = 10
pkt[(vuln <= 5) & (pkt == 0)] = 8
pkt[(vuln <= 7) & (pkt == 0)] = 6
pkt[(vuln <= 9) & (pkt == 0)] = 4
pkt[(vuln <= 12) & (pkt == 0)] = 2
pkt[(vuln <= 20) & (pkt == 0)] = 1

data_input_art2_bin["n_vunerabilities_1y"] = pkt / 10

# Scoring issues_dynamic
issues = data_input_art2_bin["issues_dynamic"]
pkt = np.zeros_like(issues)

pkt[issues > 10] = 10
pkt[(issues > 5) & (pkt == 0)] = 8
pkt[(issues >= 0) & (pkt == 0)] = 7
pkt[(issues > -5) & (pkt == 0)] = 5
pkt[(issues > -10) & (pkt == 0)] = 4
pkt[(issues > -15) & (pkt == 0)] = 2
pkt[(issues > -20) & (pkt == 0)] = 1

data_input_art2_bin["issues_dynamic"] = pkt / 10

# Scoring delta_vunerabilities
delta = data_input_art2_bin["delta_vunerabilities"]
pkt = np.zeros_like(delta)

pkt[delta > 5] = 5
pkt[(delta > 3) & (pkt == 0)] = 4
pkt[(delta > 1) & (pkt == 0)] = 3
pkt[(delta > -1) & (pkt == 0)] = 2
pkt[(delta > -3) & (pkt == 0)] = 1

data_input_art2_bin["delta_vunerabilities"] = pkt / 5

# Final adjustments
data_input_art2_bin["perc_first_10_contributors"] += 1
data_input_art2_bin["perc_of_1contr_contributors"] += 1

# --- Main index calculation ---
weights1 = [4, 7, 10] + [7] * 8
max_score = sum(weights1)
scaling = 100 / (max_score - 0)

weights = np.array(weights1)
results = data_input_art2_bin.iloc[:, 1:12].values @ weights  # matrix multiplication

data_input_art2_bin["index_value"] = results
data_input_art2_bin["index"] = np.nan

# Ranking by index_value and name
order_scores = data_input_art2_bin.sort_values(by=["index_value", "name"]).index
data_input_art2_bin.loc[order_scores, "index"] = np.arange(1, len(data_input_art2_bin) + 1)
data_input_art2_bin["index_value"] *= scaling

# --- Double ranking version ---
weights_part1 = [4, 7, 10, 7, 7, 7]
weights_part2 = [7] * 5
scaling1 = 100 / sum(weights_part1)
scaling2 = 100 / sum(weights_part2)

results1 = data_input_art2_bin.iloc[:, [1, 2, 3, 4, 5, 11]].values @ np.array(weights_part1)
results2 = data_input_art2_bin.iloc[:, [6, 7, 8, 9, 10]].values @ np.array(weights_part2)

data_input_art2_bin["index_part1_value"] = results1
data_input_art2_bin["index_part1"] = np.nan
order_scores1 = data_input_art2_bin.sort_values(by=["index_part1_value", "name"]).index
data_input_art2_bin.loc[order_scores1, "index_part1"] = np.arange(1, len(data_input_art2_bin) + 1)
data_input_art2_bin["index_part1_value"] *= scaling1

data_input_art2_bin["index_part2_value"] = results2
data_input_art2_bin["index_part2"] = np.nan
order_scores2 = data_input_art2_bin.sort_values(by=["index_part2_value", "name"]).index
data_input_art2_bin.loc[order_scores2, "index_part2"] = np.arange(1, len(data_input_art2_bin) + 1)
data_input_art2_bin["index_part2_value"] *= scaling2

# --- Merge with original data_input ---
data_input_index = data_input_df.copy()
data_input_index["index_value"] = data_input_art2_bin["index_value"]
data_input_index["index"] = data_input_art2_bin["index"]
data_input_index["index_part1_value"] = data_input_art2_bin["index_part1_value"]
data_input_index["index_part1"] = data_input_art2_bin["index_part1"]
data_input_index["index_part2_value"] = data_input_art2_bin["index_part2_value"]
data_input_index["index_part2"] = data_input_art2_bin["index_part2"]

# --- Save full index to CSV ---
output_path_full = f"{folder}{'//'}{name1}_index.csv"
data_input_index.to_csv(output_path_full, index=False)

# --- Save selected columns for chart ---
selected_cols = [0, 1, 2, 3, 4, 7, 15, 24, 31]  # Python uses 0-based indexing
data_input_index_ch = data_input_index.iloc[wybrane, selected_cols]
output_path_chart = f"{folder}{'//'}{name1}_index_ch.csv"
data_input_index_ch.to_csv(output_path_chart, index=False)

# Extract data
x = data_input_index["index_part1_value"]
y = data_input_index["index_part2_value"]
scores = data_input_index["index_value"]
labels = data_input_index["name"]

# Normalize scores for colormap
norm = plt.Normalize(vmin=min(scores), vmax=max(scores))
colors = cm.viridis(norm(scores))

# Create figure and axis
fig, ax = plt.subplots(figsize=(12, 8))
fig.patch.set_facecolor('#0b1f2a')
ax.set_facecolor('#0b1f2a')

# Plot points
scatter = ax.scatter(x, y, s=250, c=colors, edgecolors='black', linewidths=1.8)

# Add labels slightly to the right of each point
texts = []
for i, label in enumerate(labels):
    texts.append(ax.text(x[i] + 2, y[i], label, fontsize=9, color='white', va='center', ha='left'))

# Adjust to avoid overlap
adjust_text(
    texts,
    ax=ax,
    expand_text=(1.05, 1.2),  # Slight expansion to help spacing
    arrowprops=dict(arrowstyle='-', color='white')
)
# Add colorbar
cbar = plt.colorbar(cm.ScalarMappable(norm=norm, cmap='viridis'), ax=ax)
cbar.set_label('Score', color='white')
cbar.ax.yaxis.set_tick_params(color='white')
plt.setp(plt.getp(cbar.ax.axes, 'yticklabels'), color='white')

# Customize axes
x_max=max(x+10)
y_max=max(y+10)
ax.set_xlim(20, x_max)
ax.set_ylim(20, y_max)
ax.set_xlabel("Contribution & Usage Score", color='white', fontsize=12)
ax.set_ylabel("Issues Resolution & Low Vulnerability Score", color='white', fontsize=12)
ax.tick_params(colors='white')
ax.xaxis.label.set_color('white')
ax.yaxis.label.set_color('white')

# Title
plt.title("Open Source Cybersecurity Solutions\nMaturity and Development Index",
          fontsize=18, color='white', fontweight='bold', pad=20)

plt.tight_layout()
#plt.show()

# Save plot
today_str = datetime.today().strftime('%Y-%m-%d')
filename = f"{today_str}_index_plot1.png"
filepath = os.path.join(folder, filename)
plt.savefig(filepath, bbox_inches='tight')
plt.close()

# Sort data if needed
data = data_input_index.sort_values(by='index_value')

# Normalize values for colormap
norm = mcolors.Normalize(vmin=min(data['index_value']), vmax=max(data['index_value']))
colors = cm.plasma(norm(data['index_value']))  # Use 'plasma' colormap

# Create figure
fig, ax = plt.subplots(figsize=(10, 6))
fig.patch.set_facecolor('#0b1f2a')
ax.set_facecolor('#0b1f2a')

# Plot horizontal bars (negative values for reversed axis)
bars = ax.barh(data['index'], -data['index_value'], color=colors, edgecolor='black')

# Add labels on bars
for i, (value, label) in enumerate(zip(data['index_value'], data['name'])):
    ax.text(-value-1, i+1, label, va='center', ha='right', color='white', fontsize=9)

# Customize axes
x_max2=max(data['index_value']+10)
ax.set_xlim((-1)*x_max2, 0)
ax.set_xticks([-90, -70, -50, -30, -10, 0])
ax.set_xticklabels([abs(x) for x in ax.get_xticks()], color='white')
ax.set_yticklabels(data['index'], color='white')
ax.tick_params(axis='y', colors='white')
ax.tick_params(axis='x', colors='white')

# Title
plt.title("Open Source Cybersecurity Solutions Maturity and Development Index",
          fontsize=14, color='white', fontweight='bold', pad=20)

# Remove grid and spines
ax.grid(axis='y', visible=False)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_visible(False)
ax.spines['bottom'].set_color('#444444')

# Hide legend
ax.legend_.remove() if ax.legend_ else None
ax.yaxis.set_ticks([])

plt.tight_layout()
#plt.show()

# Save plot
today_str = datetime.today().strftime('%Y-%m-%d')
filename = f"{today_str}_index_plot2.png"
filepath = os.path.join(folder, filename)
plt.savefig(filepath, bbox_inches='tight')
plt.close()

# Load previous historical data
filename = f"inp_hist.csv"
filepath = os.path.join(folder, filename)
inp_hist_prev = pd.read_csv(filepath)

# Calculate new time step
new_max_time = inp_hist_prev['time'].max() + 1

# Select current data (assuming 'wybrane' is a list of row indices)
selected = data_input_index.loc[wybrane].copy()

# Reset indices to avoid duplicate labels
selected.reset_index(drop=True, inplace=True)
inp_hist_prev.reset_index(drop=True, inplace=True)

# Combine current and historical data
data_plot_historical_full = pd.DataFrame({
    'name': pd.concat([selected['name'], inp_hist_prev['name']], ignore_index=True),
    'index_value': pd.concat([selected['index_value'], inp_hist_prev['index_value']], ignore_index=True),
    'time': pd.concat([pd.Series([new_max_time] * len(selected)), inp_hist_prev['time']], ignore_index=True),
    'date': pd.concat([selected['day_of_download'], inp_hist_prev['date']], ignore_index=True)
})

# Save updated datasets
filename1 = f"inp_hist.csv"
filename2 = f"inp_hist_prev.csv"
filepath1 = os.path.join(folder, filename1)
filepath2 = os.path.join(folder, filename2)

data_plot_historical_full.to_csv(
    filepath1,
    index=False
)
inp_hist_prev.to_csv(
    filepath2,
    index=False
)

# Filter last 4 time steps
time_max = data_plot_historical_full['time'].max()
data_plot_historical_4parts = data_plot_historical_full[
    data_plot_historical_full['time'] >= (time_max - 3)
]

# Define vibrant colors
vibrant_colors = [
    "#FF6F61", "#7301A8FF", "#0D0887FF", "#F7CAC9",
    "#92A8D1", "#F0F921FF", "#BD3786FF", "#009B77"
]

data = data_plot_historical_4parts
ymin3=min(data['index_value']-15)
ymax3=max(data['index_value']+15)
data['date'] = pd.to_datetime(data['date'])


# Set plot style
plt.style.use('dark_background')
fig, ax = plt.subplots(figsize=(12, 6))
fig.patch.set_facecolor('#0b1f2a')
ax.set_facecolor('#0b1f2a')

# Use seaborn color palette
palette = sns.color_palette("bright", n_colors=data['name'].nunique())

# Plot each project and label only the last point (shifted left)
for i, (name, group) in enumerate(data.groupby('name')):
    ax.plot(group['date'], group['index_value'], label=name, color=palette[i], marker='o')
    
    # Label only the last point, shifted slightly left
    last_point = group.iloc[-1]
    first_point = group.iloc[1]
    ax.text(last_point['date'] - pd.Timedelta(days=0.25),  # shift left by ~10 days
            last_point['index_value'],
            name,
            fontsize=9, color=palette[i], ha='right')

# Move legend outside plot
ax.legend(loc='center left', bbox_to_anchor=(1, 0.5), fontsize=10)

# Adjust layout to make room for legend
plt.tight_layout(rect=[0, 0, 0.85, 1])

# Customize axes and title
ax.set_title("General Score Value Over Time per Project", fontsize=16, color='white')
ax.set_xlabel("Date", fontsize=12, color='white')
ax.set_ylabel("Index Value", fontsize=12, color='white')
ax.tick_params(colors='white')
#ax.set_ylim(0, 100)
ax.set_ylim(ymin3, ymax3)
min_date = data['date'].min() - pd.Timedelta(days=1.2)
max_date = data['date'].max()
ax.set_xlim(min_date, max_date)
#ax.set_xlim(last_point['date'] - pd.Timedelta(days=0.25),first_point['date'])
ax.set_xticks(data['date'].unique())
#ax.set_xticklabels([abs(x) for x in ax.get_xticks()], color='white')

#plt.show()

# Save plot
today_str = datetime.today().strftime('%Y-%m-%d')
filename = f"{today_str}_index_plot3.png"
filepath = os.path.join(folder, filename)
plt.savefig(filepath, bbox_inches='tight')
plt.close()

# Load  data
filename1 = f"{name1}_index.csv"
filename2 = f"{name1}.csv"
filepath1 = os.path.join(folder, filename1)
filepath2 = os.path.join(folder, filename2)
data_input_hist_km = pd.read_csv(filepath1)
data_input_hist_km_plot = pd.read_csv(filepath1)

#Important - the model is being recalculated every run, it is possible that results obtained may not be matching the previous runs (e.g. the identified areas - names may not match)
#in that case it will be best to do manual adjustments

# Select relevant columns
cols_km = [0, 2, 3, 4, 11, 12, 14, 15, 22, 24] + list(range(27, 31))  # Adjusted for 0-based indexing
data_input_km = data_input_hist_km.iloc[:, cols_km].copy()

# Convert age_in_days to numeric
data_input_km['age_in_days'] = pd.to_numeric(data_input_km['age_in_days'], errors='coerce')

# Cap outliers
data_input_km.loc[data_input_km['avg_time_between_releases'] > 100, 'avg_time_between_releases'] = 100
data_input_km.loc[data_input_km['open_issues_vs_contributors'] > 15, 'open_issues_vs_contributors'] = 15

# Standardize selected columns (excluding security policy)
cols_to_scale = list(data_input_km.columns[1:8]) + list(data_input_km.columns[9:13])
scaler = StandardScaler()
data_standardized = pd.DataFrame(np.round(scaler.fit_transform(data_input_km[cols_to_scale]), 4),
                                 columns=data_input_km[cols_to_scale].columns)

# Repeat with index columns added
data_input_km2 = data_input_km.copy()
data_input_km2['index1'] = data_input_hist_km_plot['index_part1_value']
data_input_km2['index2'] = data_input_hist_km_plot['index_part2_value']

cols_to_scale2 = list(data_input_km2.columns[1:8]) + list(data_input_km2.columns[9:16])
data_standardized2 = pd.DataFrame(np.round(scaler.fit_transform(data_input_km2[cols_to_scale2]), 4),
                                  columns=data_input_km2[cols_to_scale2].columns)

# Increase weight of index columns
data_standardized2[['index1', 'index2']] *= 3

# K-means clustering
kmeans = KMeans(n_clusters=4, n_init=100, random_state=123)
kmeans_labels = kmeans.fit_predict(data_standardized2)

# Hierarchical clustering
hclust = AgglomerativeClustering(n_clusters=4, linkage='complete')
hclust_labels = hclust.fit_predict(data_standardized2)

# PCA
pca = PCA()
pca_result = pca.fit_transform(data_standardized2)
pca_summary = pd.DataFrame({'Explained Variance': pca.explained_variance_ratio_})

# Hierarchical clustering on first 5 PCs
hclust_pca = AgglomerativeClustering(n_clusters=3, linkage='complete')
hclust_pca_labels = hclust_pca.fit_predict(pca_result[:, :5])

# Extract data
x = data_input_hist_km_plot["index_part1_value"]
y = data_input_hist_km_plot["index_part2_value"]
labels = data_input_hist_km_plot["name"]
clusters = kmeans_labels  # from your fitted KMeans model

# Normalize cluster labels for colormap
unique_clusters = np.unique(clusters)
cluster_colors = cm.viridis(np.linspace(0, 1, len(unique_clusters)))
color_map = dict(zip(unique_clusters, cluster_colors))
point_colors = [color_map[c] for c in clusters]

# Create figure and axis
fig, ax = plt.subplots(figsize=(12, 8))
fig.patch.set_facecolor('#0b1f2a')
ax.set_facecolor('#0b1f2a')

# Plot points
scatter = ax.scatter(x, y, s=250, c=point_colors, edgecolors='black', linewidths=1.8)

# Add labels slightly to the right of each point
texts = []
for i, label in enumerate(labels):
    texts.append(ax.text(x.iloc[i] + 1, y.iloc[i], label,
                         fontsize=9, color='white', va='center', ha='left'))

# Adjust to avoid overlap
adjust_text(
    texts,
    ax=ax,
    expand_text=(1.05, 1.1),
    arrowprops=dict(arrowstyle='-', color='white')
)

# Create discrete legend
from matplotlib.patches import Patch
legend_elements = [Patch(facecolor=color_map[c], edgecolor='black', label=f'Cluster {c}')
                   for c in unique_clusters]
legend = ax.legend(handles=legend_elements, title="Clusters", fontsize=10, title_fontsize=11,
                   loc='upper right', frameon=True)
legend.get_frame().set_facecolor('#0b1f2a')
legend.get_frame().set_edgecolor('white')
for text in legend.get_texts():
    text.set_color('white')
legend.get_title().set_color('white')

# Customize axes
ax.set_xlim(20, max(x) + 10)
ax.set_ylim(20, max(y) + 15)
ax.set_xlabel("Contribution & Usage Score", color='white', fontsize=12)
ax.set_ylabel("Issues Resolution & Low Vulnerability Score", color='white', fontsize=12)
ax.tick_params(colors='white')
ax.xaxis.label.set_color('white')
ax.yaxis.label.set_color('white')

# Title
plt.title("K-means Clustering of Cybersecurity Projects",
          fontsize=18, color='white', fontweight='bold', pad=20)

plt.tight_layout()
#plt.show()

# Save plot
today_str = datetime.today().strftime('%Y-%m-%d')
filename = f"{today_str}_index_plot_cluster_noname.png"
filepath = os.path.join(folder, filename)
plt.savefig(filepath, bbox_inches='tight')
plt.close()


# Extract data
x = data_input_hist_km_plot["index_part1_value"]
y = data_input_hist_km_plot["index_part2_value"]
labels = data_input_hist_km_plot["name"]
clusters = kmeans_labels  # from your fitted KMeans model

# Define custom cluster names
cluster_names = {
    0: "Solid solutions with some concerns",
    1: "Solutions with shortness of breath",
    2: "Mature solutions",
    3: "Promising solutions"
}

# Normalize cluster labels for colormap
unique_clusters = np.unique(clusters)
cluster_colors = cm.viridis(np.linspace(0, 1, len(unique_clusters)))
color_map = dict(zip(unique_clusters, cluster_colors))
point_colors = [color_map[c] for c in clusters]

# Create figure and axis
fig, ax = plt.subplots(figsize=(12, 8))
fig.patch.set_facecolor('#0b1f2a')
ax.set_facecolor('#0b1f2a')

# Plot points
scatter = ax.scatter(x, y, s=250, c=point_colors, edgecolors='black', linewidths=1.8)

# Add labels slightly to the right of each point
texts = []
for i, label in enumerate(labels):
    texts.append(ax.text(x.iloc[i] + 1, y.iloc[i], label,
                         fontsize=9, color='white', va='center', ha='left'))

# Adjust to avoid overlap
adjust_text(
    texts,
    ax=ax,
    expand_text=(1.05, 1.1),
    arrowprops=dict(arrowstyle='-', color='white')
)

# Create discrete legend with custom names
legend_elements = [
    Patch(facecolor=color_map[c], edgecolor='black', label=f"{cluster_names[c]}")
    for c in unique_clusters
]
legend = ax.legend(handles=legend_elements, title="Clusters", fontsize=10, title_fontsize=11,
                   loc='upper right', frameon=True)
legend.get_frame().set_facecolor('#0b1f2a')
legend.get_frame().set_edgecolor('white')
for text in legend.get_texts():
    text.set_color('white')
legend.get_title().set_color('white')

# Customize axes
ax.set_xlim(20, max(x) + 10)
ax.set_ylim(20, max(y) + 15)
ax.set_xlabel("Contribution & Usage Score", color='white', fontsize=12)
ax.set_ylabel("Issues Resolution & Low Vulnerability Score", color='white', fontsize=12)
ax.tick_params(colors='white')
ax.xaxis.label.set_color('white')
ax.yaxis.label.set_color('white')

# Title
plt.title("K-means Clustering of Cybersecurity Projects",
          fontsize=18, color='white', fontweight='bold', pad=20)

plt.tight_layout()
#plt.show()

# Save plot
today_str = datetime.today().strftime('%Y-%m-%d')
filename = f"{today_str}_index_plot_cluster_name.png"
filepath = os.path.join(folder, filename)
plt.savefig(filepath, bbox_inches='tight')
plt.close()
