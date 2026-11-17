# OMSIndex

🛡️ **Open-source Maturity and Security Index** — a transparent, data-driven index of how mature and how secure open-source cybersecurity projects are.

This repository contains the reference implementation of **OMSIndex v5**, the same calculation that powers the live ranking at **[cybersimplifier.com/index](https://cybersimplifier.com/index)**. Given the same raw data it reproduces the published scores, ranks and clusters exactly, and given the same score history it reproduces the published **score forecast** exactly (both are covered by the tests).

![2D Index — Contribution vs Security](docs/omsindex-2d.png)

*2D Index — Contribution vs Security, snapshot of 2026‑11‑16. The interactive, daily refreshed version is on the [website](https://cybersimplifier.com/index).*

## Purpose

OMSIndex helps developers, organizations and security teams make informed decisions when adopting or contributing to open-source security tools. Every number in the index comes from public data and a published formula, so anyone can verify or challenge a result.

## How it works

```
GitHub REST + GraphQL API ─┐
                           ├─► raw metrics ─► component scores (0–1) ─► weighted index (0–100)
Shodan CVEDB ──────────────┘                                          ├─► 2D index (two dimensions)
                                                                      └─► 3 clusters of similar projects
```

### 1. Data collection

| Source | Data |
| --- | --- |
| [GitHub API](https://docs.github.com/rest) | stars, forks, subscribers (watchers), open issues, contributors and their contributions, releases, issues opened and closed in the last 30 days |
| [Shodan CVEDB](https://cvedb.shodan.io) | CVEs per product with CVSS score, EPSS probability and EPSS ranking, in three windows: last year, the year before, and full history |

The tracked projects (currently 50) are listed in [`projects.py`](projects.py).

### 2. Component scores

Each component is scored from 0 (worst) to 1 (best).

| Component | Weight | What scores well |
| --- | ---: | --- |
| `stars` | 4 | More stars than the other indexed projects (percentile) |
| `forks` | 7 | More forks than the other indexed projects (percentile) |
| `subscribers` | 10 | More watchers than the other indexed projects (percentile) |
| `contributorBalance` | 7 | The 10 most active contributors author close to 60% of the work — neither a one-person project nor one without a core team |
| `contributorDepth` | 7 | Few contributors with only a single contribution |
| `releaseCadence` | 0 ¹ | Close to one release every 30 days, both historically and in the last 60 days |
| `vulnerabilitiesRecent` | 4 | Few CVEs in the last year |
| `cvssRecent` | 4 | Low average CVSS in the last year |
| `issueResolution` | 7 | More issues closed than opened in the last 30 days |
| `issueLoad` | 4 | Fewer open issues per contributor than the other projects (percentile) |
| `vulnerabilityTrend` | 4 | Fewer CVEs in the last year than in the year before |
| `cvssTrend` | 8 | Average CVSS falling year over year |
| `epssTrend` | 8 | Average EPSS (exploitation probability) falling year over year |
| `epssRisk` | 7 | Low EPSS ranking of the most recent CVEs |
| `severeVulnerabilities` | 7 | Few high-severity CVEs (CVSS ≥ 7) in the last year |
| `severeShare` | 7 | Small share of high-severity CVEs among recent ones |
| `severityBurden` | 2 | Low count × average CVSS, relative to the other projects (percentile) |
| `cvssImprovement` | 7 | Recent CVSS score better than the previous year's |

¹ Release cadence does not count toward the overall index, but it does count (weight 7) in the *Contribution & Usage* dimension.

Popularity weights follow `subscribers > forks > stars`: watching a repository is the strongest signal of real technical use, a star the weakest. Security-policy presence is collected as metadata but is not scored. Projects with no vulnerability data get neutral-to-low scores for the vulnerability components rather than the best ones — no data is not the same as no vulnerabilities.

### 3. The index

* **Index (0–100)** — weighted average of all components. Projects are ranked by it.
* **2D index** — the same components split into two independent dimensions:
  * **Contribution & Usage** (X axis): `stars`, `forks`, `subscribers`, `contributorBalance`, `contributorDepth`, `releaseCadence`
  * **Security & Issues** (Y axis): all vulnerability and issue components
* **Clusters** — complete-linkage hierarchical clustering on the standardized raw metrics plus the two dimensions (which are weighted ×3) groups the projects into three clusters, named by their average index: **Needs attention**, **Promising**, **Mature**.

The exact thresholds and formulas are in [`omsindex_math.py`](omsindex_math.py), which has no third-party dependencies.

### 4. The forecast

The website also shows where each project's score may be in 30 and 90 days. The model is a **joint moving-block bootstrap** — it only replays how much the score has actually moved recently:

1. Take the project's last 90 *observed* daily snapshots computed with index v5. Days that were gap-filled (`snapshotQuality` other than `observed`) are ignored. Until a project has 30 observed v5 snapshots, its pre-v5 history is used instead and the forecast is marked *provisional*.
2. Turn them into daily changes of three values at once: the index, *Contribution & Usage* and *Security & Issues*.
3. Simulate 1000 possible futures. Each starts at today's values and repeatedly appends a randomly chosen 7-day block of those historical changes (wrapping around the end of the history), keeping every value within 0–100. A block moves all three values together, so the relation between them is preserved, and no statistical distribution is assumed.
4. For each future day, the **median** of the 1000 futures is the forecast and the 2.5% and 97.5% quantiles are the **95% uncertainty interval**. For the 2D chart, the model also reports the regions holding the central 95, 80, 50, 20 and 5% of simulated positions.

The random numbers come from a generator seeded with the model version, project name, date and history length, so the same history always gives the same forecast — there is nothing to tune and nothing hidden.

The forecast is an extrapolation of past variability, not a prediction of events: it does not know about upcoming releases or vulnerabilities, and a project whose score has not moved gets a flat forecast.

The model is in [`omsindex_forecast.py`](omsindex_forecast.py), which has no third-party dependencies.

## Usage

Requires Python 3.9+.

```bash
pip install -r requirements.txt
```

**Full run** — collects fresh data from the APIs (about 2 minutes):

```bash
export GITHUB_TOKEN=<your token>   # any token; public read access is enough
python security_index.py
```

Without `GITHUB_TOKEN` the script still runs, but GitHub allows only 60 requests per hour and the contributor, release and issue-flow metrics are skipped, so the result will not match the published index.

**Recompute from a published snapshot** — no token needed; takes the raw data published by the website and recalculates everything:

```bash
python security_index.py --snapshot https://www.cybersimplifier.com/index-data.json
```

Options: `--output-dir DIR` (default `output`), `--no-plot` (skip the chart; matplotlib not needed), `--plot-file PNG` (save an extra copy of the chart).

**Forecast** — no token and no third-party packages needed; downloads the daily score history published by the website (about 4 MB) and computes the forecast of every project:

```bash
python forecast_index.py
```

Add `--verify` to also download the forecast the website currently shows and confirm that yours is identical:

```bash
python forecast_index.py --verify
```

Options: `--history SOURCE` (a local or remote `history.csv` / `history.json`; default `https://www.cybersimplifier.com/exports/history.csv`), `--output-dir DIR` (default `output`), `--verify [EXPORTS]` (URL or directory with published forecasts to compare against; default `https://www.cybersimplifier.com/exports`).

A forecast needs a history of daily snapshots, which cannot be collected after the fact. The website publishes its full history, including every raw metric, in `history.csv`; to forecast from your own runs, keep the daily `indexValue`, `indexPart1` and `indexPart2` of each project and pass them as `--history`.

### Output

| File | Content |
| --- | --- |
| `output/index-data.json` | Full result: raw data, component scores, index, 2D index, rank and cluster for every project. Same format as the website's data file. Also used as a fallback for the next run if an API call fails. |
| `output/<date>_index.csv` | The ranking as a table |
| `output/<date>_index_2d.png` | The *2D Index — Contribution vs Security* chart |
| `output/forecast-summary.json` | 30-day forecast of every project: expected score, 95% interval and 2D regions. Same format as the website's `/exports/forecast-summary.json`. |
| `output/forecasts/<slug>.json` | 90-day day-by-day forecast of one project, with the history it was built from. Same format as the website's `/exports/forecasts/<slug>.json`. |

### Use as a library

```python
from omsindex_math import compute_index_v5

ranked = compute_index_v5(projects)   # list of {"name", "github": {...}, "vulnerabilities": {...}}
for project in ranked[:5]:
    print(project["rank"], project["name"], project["indexValue"], project["clusterKey"])
```

```python
from omsindex_forecast import build_forecast

history = [  # one record per day
    {"date": "2026-11-16", "indexValue": 46.2, "indexPart1": 69.4, "indexPart2": 30.4, "indexVersion": "5.0"},
    {"date": "2026-11-17", "indexValue": 46.0, "indexPart1": 69.4, "indexPart2": 30.1, "indexVersion": "5.0"},
    # ...
]
result = build_forecast(history, {"name": "Wazuh"})
in_30_days = result["hoverEndpoint"]
print(in_30_days["indexValue"], in_30_days["indexValueLower95"], in_30_days["indexValueUpper95"])
```

## Repository layout

| File | Purpose |
| --- | --- |
| [`security_index.py`](security_index.py) | Command-line entry point: data collection and output |
| [`omsindex_math.py`](omsindex_math.py) | Index v5 scoring, ranking and clustering |
| [`plot_index.py`](plot_index.py) | 2D chart |
| [`forecast_index.py`](forecast_index.py) | Command-line entry point for the forecast: history loading, output and verification |
| [`omsindex_forecast.py`](omsindex_forecast.py) | Forecast model |
| [`projects.py`](projects.py) | Tracked projects |
| [`euvd_client.py`](euvd_client.py) | Standalone client for the ENISA EUVD vulnerability database (not used in the index calculation) |
| [`tests/`](tests) | Tests, including checks against a snapshot and a forecast published by the website |

## Tests

```bash
python -m unittest discover -s tests
```

## Why a fresh run can differ slightly from the website

The website refreshes once a day, so stars, issues and CVEs move between its run and yours. In addition, when the CVE database has no entry for a product, this script scores the project as *no vulnerability data*, while the website may still carry an older stored record for it. Use `--snapshot` to reproduce the website's numbers exactly.

## Status

🧠 In active development. Feedback and proposals for new projects or metrics are welcome — please open an issue.

## License

[AGPL-3.0](LICENSE)
