#!/usr/bin/env python3
"""OMSIndex -- Open-source Maturity and Security Index (v5).

Collects GitHub and vulnerability data for the tracked projects, computes the
index exactly as published at https://cybersimplifier.com/index and writes:

    <output>/index-data.json          full result, same shape as the website data
    <output>/<date>_index.csv         ranking table
    <output>/<date>_index_2d.png      "2D Index -- Contribution vs Security" chart

Usage:
    export GITHUB_TOKEN=...            # required for the full set of metrics
    python security_index.py

    # Recompute from an already published snapshot (no token, no API calls
    # other than downloading the snapshot):
    python security_index.py --snapshot https://www.cybersimplifier.com/index-data.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

from omsindex_math import CLUSTER_LABELS, INDEX_VERSION, INDEX_WEIGHTS, compute_index_v5
from projects import PROJECTS

GITHUB_API = "https://api.github.com"
CVEDB_API = "https://cvedb.shodan.io"
USER_AGENT = f"OMSIndex/{INDEX_VERSION}"
REQUEST_TIMEOUT = 30
BATCH_SIZE = 5
DAY_MS = 86_400_000

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": "2022-11-28",
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

HEALTH_KEYS = (
    "contributorCount",
    "totalContributions",
    "top10ContributorShare",
    "singleContributionShare",
    "avgDaysBetweenReleases",
    "releasesLast60Days",
    "newIssuesLast30Days",
    "closedIssuesLast30Days",
)

# Fields added by the index calculation (everything else is raw input data).
COMPUTED_KEYS = (
    "scores", "metrics", "indexValue", "indexPart1", "indexPart2",
    "indexVersion", "rank", "clusterId", "clusterKey",
)


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

def request_with_retry(method: str, url: str, retries: int = 2, **kwargs) -> Optional[requests.Response]:
    """Perform a request, backing off when rate-limited. None if never served."""
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    for attempt in range(retries + 1):
        try:
            response = requests.request(method, url, **kwargs)
        except requests.RequestException:
            if attempt < retries:
                time.sleep((attempt + 1) * 3)
                continue
            raise
        if response.status_code in (403, 429):
            wait = min(60, (attempt + 1) * 10)
            print(f"  Rate-limited ({response.status_code}), waiting {wait}s before retry...")
            time.sleep(wait)
            continue
        return response
    return None


def fetch_paginated_github(path: str, max_pages: int) -> List[dict]:
    items: List[dict] = []
    for page in range(1, max_pages + 1):
        separator = "&" if "?" in path else "?"
        response = request_with_retry(
            "GET", f"{GITHUB_API}{path}{separator}per_page=100&page={page}", headers=GITHUB_HEADERS
        )
        if response is None or not response.ok:
            status = response.status_code if response is not None else "no response"
            raise RuntimeError(f"GitHub API {status} for {path}")
        page_items = response.json()
        if not isinstance(page_items, list):
            raise RuntimeError(f"Malformed paginated response for {path}")
        items.extend(page_items)
        if len(page_items) < 100:
            break
    return items


def average(values, fallback: float = -1) -> float:
    usable = [float(v) for v in values if isinstance(v, (int, float)) and v == v and abs(v) != float("inf")]
    if not usable:
        return fallback
    total = 0.0
    for value in usable:  # plain left-to-right sum keeps results identical to the website
        total += value
    return total / len(usable)


def parse_time_ms(value: Any) -> Optional[int]:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return round(parsed.timestamp() * 1000)


def to_number(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number and abs(number) != float("inf") else None


# --------------------------------------------------------------------------
# GitHub
# --------------------------------------------------------------------------

def fetch_issue_activity(owner: str, repo: str) -> Dict[str, int]:
    """Issues opened and closed in the last 30 days (GitHub GraphQL search)."""
    today = datetime.now(timezone.utc)
    start = (today - timedelta(days=30)).strftime("%Y-%m-%d")
    end = today.strftime("%Y-%m-%d")
    query = """
    query($createdQuery: String!, $closedQuery: String!) {
      created: search(query: $createdQuery, type: ISSUE, first: 1) { issueCount }
      closed: search(query: $closedQuery, type: ISSUE, first: 1) { issueCount }
    }
    """
    response = request_with_retry(
        "POST",
        f"{GITHUB_API}/graphql",
        headers=GITHUB_HEADERS,
        json={
            "query": query,
            "variables": {
                "createdQuery": f"repo:{owner}/{repo} is:issue created:{start}..{end}",
                "closedQuery": f"repo:{owner}/{repo} is:issue is:closed closed:{start}..{end}",
            },
        },
    )
    if response is None or not response.ok:
        status = response.status_code if response is not None else "no response"
        raise RuntimeError(f"GitHub GraphQL {status}")
    body = response.json()
    if body.get("errors"):
        raise RuntimeError("; ".join(error.get("message", "") for error in body["errors"]))
    data = body.get("data") or {}
    return {
        "newIssuesLast30Days": (data.get("created") or {}).get("issueCount") or 0,
        "closedIssuesLast30Days": (data.get("closed") or {}).get("issueCount") or 0,
    }


def fetch_repository_health(owner: str, repo: str) -> Optional[dict]:
    """Contributor, release and issue-flow metrics. Needs an authenticated token."""
    if not GITHUB_TOKEN:
        return None
    contributors = fetch_paginated_github(f"/repos/{owner}/{repo}/contributors", 50)
    releases = fetch_paginated_github(f"/repos/{owner}/{repo}/releases", 25)
    issue_activity = fetch_issue_activity(owner, repo)

    contributions = [c for c in (to_number(item.get("contributions")) for item in contributors) if c is not None]
    total_contributions = int(sum(contributions))
    top10_contributions = int(sum(sorted(contributions, reverse=True)[:10]))

    release_times = sorted(
        (t for t in (parse_time_ms(r.get("published_at") or r.get("created_at")) for r in releases) if t is not None),
        reverse=True,
    )
    release_gaps = [abs(release_times[i] - release_times[i + 1]) / DAY_MS for i in range(len(release_times) - 1)]
    sixty_days_ago = time.time() * 1000 - 60 * DAY_MS

    return {
        "contributorCount": len(contributors),
        "totalContributions": total_contributions,
        "top10ContributorShare": top10_contributions / total_contributions if total_contributions > 0 else 0,
        "singleContributionShare": (
            sum(1 for value in contributions if value == 1) / len(contributors) if contributors else 0
        ),
        "avgDaysBetweenReleases": max(0, average(release_gaps, 0)),
        "releasesLast60Days": sum(1 for t in release_times if t >= sixty_days_ago),
        **issue_activity,
    }


def retain_health_metrics(current: Optional[dict], previous: Optional[dict]) -> dict:
    """Use fresh metrics when available, otherwise the last known values."""
    current = current or {}
    previous = previous or {}
    result = {}
    for key in HEALTH_KEYS:
        value = current.get(key)
        if value is None:
            value = previous.get(key)
        result[key] = 0 if value is None else value
    return result


def fetch_github_data(owner: str, repo: str, previous: Optional[dict] = None) -> Optional[dict]:
    previous = previous or {}
    try:
        response = request_with_retry("GET", f"{GITHUB_API}/repos/{owner}/{repo}", headers=GITHUB_HEADERS)
        if response is None or not response.ok:
            status = response.status_code if response is not None else "no response"
            raise RuntimeError(f"GitHub API {status}")
        data = response.json()
        if data.get("stargazers_count") is None:
            raise RuntimeError("Malformed response")
        health = None
        try:
            health = fetch_repository_health(owner, repo)
        except Exception as error:  # extended metrics are best-effort
            print(f"    ! Extended GitHub metrics failed for {owner}/{repo}: {error}")
        license_info = data.get("license") or {}
        return {
            "stars": data.get("stargazers_count") or 0,
            "forks": data.get("forks_count") or 0,
            "openIssues": data.get("open_issues_count") or 0,
            "subscribers": data.get("subscribers_count") or 0,
            "license": license_info.get("spdx_id") or license_info.get("name") or "None",
            "createdAt": data.get("created_at"),
            "updatedAt": data.get("updated_at"),
            "description": data.get("description") or "",
            "language": data.get("language") or "",
            "defaultBranch": data.get("default_branch") or "main",
            # Metadata only -- security-policy presence is not scored in v5.
            "hasSecurityPolicy": previous.get("hasSecurityPolicy") or False,
            **retain_health_metrics(health, previous),
            "healthMetricsFresh": bool(health),
        }
    except Exception as error:
        print(f"  ! GitHub failed for {owner}/{repo}: {error}")
        return None


# --------------------------------------------------------------------------
# Vulnerabilities (Shodan CVEDB)
# --------------------------------------------------------------------------

def empty_vulnerabilities() -> dict:
    return {
        "total": 0,
        "cves": [],
        "recentCount": 0,
        "twoYearCount": 0,
        "lowSeverityCount1y": 0,
        "lowSeverityCount2y": 0,
        "highSeverityCount1y": 0,
        "highSeverityCount2y": 0,
        "cvssAvg1y": -1,
        "cvssAvgPreviousYear": -1,
        "cvssAvgFull": -1,
        "epssAvg1y": -1,
        "epssAvgPreviousYear": -1,
        "epssAvgFull": -1,
        "epssRankAvg1y": -1,
        "epssRankAvgPreviousYear": -1,
        "epssRankAvgFull": -1,
        "statsAvailable": False,
    }


def fetch_cves(product_name: Optional[str]) -> Optional[dict]:
    """CVE statistics for a product: counts, CVSS and EPSS over 1- and 2-year windows."""
    if not product_name:
        return empty_vulnerabilities()
    try:
        response = request_with_retry(
            "GET", f"{CVEDB_API}/cves?product={quote(product_name, safe='')}", headers={"User-Agent": USER_AGENT}
        )
        if response is None or not response.ok:
            status = response.status_code if response is not None else "no response"
            raise RuntimeError(f"CVEDB API {status}")
        data = response.json()
        if data.get("detail") == "No information available":
            return empty_vulnerabilities()
        cves = data.get("cves") or []
        now = time.time() * 1000
        one_year_ago = now - 365 * DAY_MS
        two_years_ago = now - 730 * DAY_MS

        valid = []
        for cve in cves:
            published = parse_time_ms(cve.get("published_time"))
            if published is None:
                continue
            valid.append({
                "published": published,
                "cvss": to_number(cve.get("cvss")),
                "epss": to_number(cve.get("epss")),
                "epssRank": to_number(cve.get("ranking_epss")),
            })
        recent = [c for c in valid if c["published"] >= one_year_ago]
        previous_year = [c for c in valid if two_years_ago <= c["published"] < one_year_ago]
        two_years = [c for c in valid if c["published"] >= two_years_ago]

        def values(records, key):
            return [c[key] for c in records if c[key] is not None]

        def high(records):
            return sum(1 for c in records if c["cvss"] is not None and c["cvss"] >= 7)

        def low(records):
            return sum(1 for c in records if c["cvss"] is not None and c["cvss"] < 7)

        return {
            "total": len(valid),
            "recentCount": len(recent),
            "twoYearCount": len(two_years),
            "lowSeverityCount1y": low(recent),
            "lowSeverityCount2y": low(two_years),
            "highSeverityCount1y": high(recent),
            "highSeverityCount2y": high(two_years),
            "cvssAvg1y": average(values(recent, "cvss")),
            "cvssAvgPreviousYear": average(values(previous_year, "cvss")),
            "cvssAvgFull": average(values(valid, "cvss")),
            "epssAvg1y": average(values(recent, "epss")),
            "epssAvgPreviousYear": average(values(previous_year, "epss")),
            "epssAvgFull": average(values(valid, "epss")),
            "epssRankAvg1y": average(values(recent, "epssRank")),
            "epssRankAvgPreviousYear": average(values(previous_year, "epssRank")),
            "epssRankAvgFull": average(values(valid, "epssRank")),
            "statsAvailable": len(valid) > 0,
            "cves": [
                {
                    "id": c.get("cve_id"),
                    "summary": c.get("summary"),
                    "cvss": c.get("cvss"),
                    "epss": c.get("epss"),
                    "published": c.get("published_time"),
                    "kev": c.get("kev"),
                }
                for c in cves[:10]
            ],
        }
    except Exception as error:
        print(f"  ! CVEDB failed for {product_name}: {error}")
        return None


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

def has_valid_github(record: Optional[dict]) -> bool:
    return bool(record) and ((record.get("stars") or 0) > 0 or (record.get("forks") or 0) > 0)


def collect_project(project: dict, previous: Optional[dict]) -> dict:
    previous = previous or {}
    github = fetch_github_data(project["owner"], project["repo"], previous.get("github"))
    vulnerabilities = fetch_cves(project["cveProduct"]) or previous.get("vulnerabilities") or empty_vulnerabilities()

    if not has_valid_github(github) and previous.get("github"):
        print(f"    <- {project['name']}: GitHub data invalid, keeping previous record")
        return {**project, "github": previous["github"], "vulnerabilities": vulnerabilities}
    if not has_valid_github(github):
        print(f"    ! {project['name']}: no GitHub data and no previous fallback")
    return {**project, "github": github or previous.get("github"), "vulnerabilities": vulnerabilities}


def collect_live(previous_data: Dict[str, dict]) -> List[dict]:
    print(f"OMSIndex: fetching data for {len(PROJECTS)} projects...")
    if GITHUB_TOKEN:
        print("  GitHub token: present (authenticated)")
    else:
        print("  GitHub token: NOT SET -- 60 requests/hour and no contributor, release or")
        print("  issue-flow metrics. Set GITHUB_TOKEN to reproduce the published index.")

    results: List[dict] = []
    batch_count = -(-len(PROJECTS) // BATCH_SIZE)
    for start in range(0, len(PROJECTS), BATCH_SIZE):
        batch = PROJECTS[start:start + BATCH_SIZE]
        print(f"  Batch {start // BATCH_SIZE + 1}/{batch_count}: {', '.join(p['name'] for p in batch)}")
        with ThreadPoolExecutor(max_workers=BATCH_SIZE) as pool:
            results.extend(pool.map(
                lambda project: collect_project(project, previous_data.get(f"{project['owner']}/{project['repo']}")),
                batch,
            ))
        if start + BATCH_SIZE < len(PROJECTS):
            time.sleep(0.5 if GITHUB_TOKEN else 2)
    return results


def load_snapshot(source: str) -> dict:
    """Load a published index-data.json from a URL or a local file."""
    if source.startswith(("http://", "https://")):
        response = requests.get(source, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        snapshot = response.json()
    else:
        snapshot = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(snapshot.get("data"), list):
        raise ValueError(f"{source} is not an OMSIndex snapshot (missing 'data' list)")
    return snapshot


def raw_projects(snapshot: dict) -> List[dict]:
    """Strip previously computed fields, leaving only the raw input data."""
    return [{k: v for k, v in project.items() if k not in COMPUTED_KEYS} for project in snapshot["data"]]


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_csv(path: Path, indexed: List[dict]) -> None:
    score_keys = list(INDEX_WEIGHTS.keys())
    header = [
        "rank", "name", "owner", "repo", "category", "index", "contribution_usage", "security_issues",
        "cluster", "stars", "forks", "subscribers", "open_issues", "contributors",
        "vulnerabilities_1y", "vulnerabilities_2y", "high_severity_1y", "cvss_avg_1y", "epss_avg_1y",
    ] + [f"score_{key}" for key in score_keys]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        for project in indexed:
            gh = project.get("github") or {}
            vulnerability = project.get("vulnerabilities") or {}
            writer.writerow([
                project["rank"], project["name"], project.get("owner", ""), project.get("repo", ""),
                project.get("category", ""), project["indexValue"], project["indexPart1"], project["indexPart2"],
                CLUSTER_LABELS.get(project.get("clusterKey"), ""),
                gh.get("stars", ""), gh.get("forks", ""), gh.get("subscribers", ""), gh.get("openIssues", ""),
                gh.get("contributorCount", ""),
                vulnerability.get("recentCount", ""), vulnerability.get("twoYearCount", ""),
                vulnerability.get("highSeverityCount1y", ""), vulnerability.get("cvssAvg1y", ""),
                vulnerability.get("epssAvg1y", ""),
            ] + [project["scores"].get(key, "") for key in score_keys])


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compute the OMSIndex (v5).")
    parser.add_argument(
        "--snapshot", metavar="URL_OR_FILE",
        help="recompute from the raw data of a published index-data.json instead of calling the APIs",
    )
    parser.add_argument("--output-dir", default="output", help="where results are written (default: output)")
    parser.add_argument("--no-plot", action="store_true", help="skip the 2D chart (no matplotlib needed)")
    parser.add_argument("--plot-file", metavar="PNG", help="also save the 2D chart to this path")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    data_path = output_dir / "index-data.json"

    if args.snapshot:
        snapshot = load_snapshot(args.snapshot)
        now_ms = snapshot.get("timestamp") or time.time() * 1000
        results = raw_projects(snapshot)
        print(f"OMSIndex: recomputing {len(results)} projects from snapshot {args.snapshot}")
    else:
        previous_data: Dict[str, dict] = {}
        if data_path.exists():
            try:
                for project in json.loads(data_path.read_text(encoding="utf-8")).get("data", []):
                    previous_data[f"{project['owner']}/{project['repo']}"] = project
                print(f"  Loaded {len(previous_data)} previous records for fallback")
            except (ValueError, KeyError):
                print("  ! Could not parse previous index-data.json")
        results = collect_live(previous_data)
        now_ms = time.time() * 1000

        valid_count = sum(1 for record in results if has_valid_github(record.get("github")))
        print(f"\n  Valid GitHub data: {valid_count}/{len(results)}")
        if valid_count < len(results) / 2:
            print("Too many failed fetches -- aborting without writing results.", file=sys.stderr)
            return 1

    indexed = compute_index_v5(results, now_ms=now_ms)
    generated = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc)
    date = generated.strftime("%Y-%m-%d")

    data_path.write_text(
        json.dumps({
            "data": indexed,
            "timestamp": int(now_ms),
            "generatedAt": generated.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "indexVersion": INDEX_VERSION,
        }, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    csv_path = output_dir / f"{date}_index.csv"
    write_csv(csv_path, indexed)

    print(f"\nOMSIndex v{INDEX_VERSION} written to {data_path} and {csv_path}")
    print("  Top 5: " + ", ".join(f"{p['name']} ({p['indexValue']})" for p in indexed[:5]))

    if not args.no_plot:
        from plot_index import plot_2d_index  # imported late so --no-plot works without matplotlib

        targets = [output_dir / f"{date}_index_2d.png"]
        if args.plot_file:
            targets.append(Path(args.plot_file))
        for target in targets:
            plot_2d_index(indexed, target, date=date)
            print(f"  2D chart: {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
