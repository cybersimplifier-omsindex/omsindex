#!/usr/bin/env python3
"""OMSIndex forecast -- reproduce the score forecast published on the website.

Reads the daily score history of every project, runs the forecast model from
``omsindex_forecast.py`` and writes, in the same format as the website:

    <output>/forecast-summary.json     30-day forecast of every project
    <output>/forecasts/<slug>.json     90-day forecast and history of one project

Usage:
    # Forecast from the history published by the website
    python forecast_index.py

    # ... and check that the result equals the forecast the website shows
    python forecast_index.py --verify

    # Forecast from a local copy of the history
    python forecast_index.py --history history.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

from omsindex_forecast import (
    DETAIL_FORECAST_DAYS,
    FORECAST_MODEL_VERSION,
    HOVER_FORECAST_DAYS,
    build_forecast,
    forecast_summary,
    parse_iso_date,
    slugify_project,
)
from omsindex_math import INDEX_VERSION

SITE_EXPORTS = "https://www.cybersimplifier.com/exports"
DEFAULT_HISTORY = f"{SITE_EXPORTS}/history.csv"
USER_AGENT = f"OMSIndex/{INDEX_VERSION}"
REQUEST_TIMEOUT = 60


def read_source(source: str) -> str:
    """Return the text of a local file or an http(s) URL."""
    if source.startswith(("http://", "https://")):
        request = Request(source, headers={"User-Agent": USER_AGENT})
        with urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return response.read().decode("utf-8")
    return Path(source).read_text(encoding="utf-8")


def load_history(source: str) -> List[dict]:
    """Load daily records from the website's ``history.csv`` or ``history.json``."""
    text = read_source(source)
    if text.lstrip().startswith("{"):
        records = json.loads(text).get("data") or []
    else:
        records = list(csv.DictReader(io.StringIO(text, newline="")))
    for record in records:
        if not record.get("name"):
            record["name"] = record.get("projectName") or ""
    return records


def _rank(record: dict) -> float:
    try:
        return float(record.get("rank"))
    except (TypeError, ValueError):
        return float("inf")


def group_history(records: List[dict]) -> Tuple[Dict[str, List[dict]], List[dict]]:
    """Return (history per project slug, records of the latest day ordered by rank)."""
    grouped: Dict[str, List[dict]] = {}
    dated = []
    for record in records:
        iso_date = parse_iso_date(record.get("isoDate") or record.get("date"))
        if not iso_date:
            continue
        dated.append((iso_date, record))
        grouped.setdefault(slugify_project(record["name"]), []).append(record)
    latest_date = max((iso_date for iso_date, _ in dated), default=None)
    latest = sorted((record for iso_date, record in dated if iso_date == latest_date), key=_rank)
    return grouped, latest


def compute_forecasts(records: List[dict]) -> Dict[str, dict]:
    """Forecast every project present on the latest day of the history."""
    grouped, latest = group_history(records)
    details: Dict[str, dict] = {}
    for project in latest:
        slug = slugify_project(project["name"])
        if not slug or slug in details:
            raise ValueError(f"Invalid or duplicate project slug: {slug or project['name']}")
        details[slug] = build_forecast(grouped.get(slug, []), project)
    return details


def summary_document(details: Dict[str, dict], generated_at: str) -> dict:
    return {
        "generatedAt": generated_at,
        "modelVersion": FORECAST_MODEL_VERSION,
        "hoverHorizonDays": HOVER_FORECAST_DAYS,
        "detailHorizonDays": DETAIL_FORECAST_DAYS,
        "projects": {slug: forecast_summary(detail) for slug, detail in details.items()},
    }


def _whole_numbers_as_integers(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _whole_numbers_as_integers(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_whole_numbers_as_integers(item) for item in value]
    return value


def to_json(document: Any) -> str:
    """Serialize the way the website does (compact, 46 rather than 46.0)."""
    return json.dumps(_whole_numbers_as_integers(document), ensure_ascii=False, separators=(",", ":"))


def write_forecasts(details: Dict[str, dict], output_dir: Path, generated_at: str) -> None:
    (output_dir / "forecasts").mkdir(parents=True, exist_ok=True)
    for slug, detail in details.items():
        document = {**detail, "generatedAt": generated_at}
        (output_dir / "forecasts" / f"{slug}.json").write_text(to_json(document), encoding="utf-8")
    summary = summary_document(details, generated_at)
    (output_dir / "forecast-summary.json").write_text(to_json(summary), encoding="utf-8")


def first_difference(computed: Any, published: Any, path: str = "") -> Optional[str]:
    """Describe the first place where two JSON values differ, or return None."""
    if isinstance(computed, dict) and isinstance(published, dict):
        for key in sorted(set(computed) | set(published)):
            if key not in computed or key not in published:
                return f"{path}/{key}: only in {'published' if key in published else 'computed'}"
            difference = first_difference(computed[key], published[key], f"{path}/{key}")
            if difference:
                return difference
        return None
    if isinstance(computed, list) and isinstance(published, list):
        if len(computed) != len(published):
            return f"{path}: {len(computed)} items computed, {len(published)} published"
        for index, (left, right) in enumerate(zip(computed, published)):
            difference = first_difference(left, right, f"{path}/{index}")
            if difference:
                return difference
        return None
    return None if computed == published else f"{path}: computed {computed!r}, published {published!r}"


def _without_timestamp(document: dict) -> dict:
    return {key: value for key, value in document.items() if key != "generatedAt"}


def verify(details: Dict[str, dict], published_base: str) -> List[str]:
    """Compare computed forecasts with published ones; return the differences found."""
    base = published_base.rstrip("/")
    problems = []
    published_summary = json.loads(read_source(f"{base}/forecast-summary.json"))
    computed_summary = json.loads(to_json(summary_document(details, "")))
    difference = first_difference(_without_timestamp(computed_summary), _without_timestamp(published_summary))
    if difference:
        problems.append(f"forecast-summary.json{difference}")
    for slug, detail in details.items():
        try:
            published = json.loads(read_source(f"{base}/forecasts/{slug}.json"))
        except (OSError, ValueError) as error:
            problems.append(f"forecasts/{slug}.json: cannot read published file ({error})")
            continue
        difference = first_difference(json.loads(to_json(detail)), _without_timestamp(published))
        if difference:
            problems.append(f"forecasts/{slug}.json{difference}")
    return problems


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compute the OMSIndex score forecast.")
    parser.add_argument(
        "--history", default=DEFAULT_HISTORY, metavar="SOURCE",
        help=f"history.csv or history.json, as a path or URL (default: {DEFAULT_HISTORY})",
    )
    parser.add_argument("--output-dir", default="output", help="where results are written (default: output)")
    parser.add_argument(
        "--verify", nargs="?", const=SITE_EXPORTS, metavar="EXPORTS",
        help=f"compare the result with published forecasts at this URL or directory (default: {SITE_EXPORTS})",
    )
    args = parser.parse_args(argv)

    print(f"Loading history from {args.history} ...")
    records = load_history(args.history)
    details = compute_forecasts(records)
    if not details:
        print("No dated records found in the history.", file=sys.stderr)
        return 1

    generated_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    output_dir = Path(args.output_dir)
    write_forecasts(details, output_dir, generated_at)
    latest_date = next(iter(details.values()))["current"]["isoDate"]
    print(f"History up to {latest_date}: {len(records)} records, {len(details)} projects forecast.")
    print(f"Wrote {output_dir / 'forecast-summary.json'} and {output_dir / 'forecasts'}/<slug>.json")

    if args.verify:
        problems = verify(details, args.verify)
        if problems:
            print(f"\nDIFFERENT from {args.verify} ({len(problems)} files):", file=sys.stderr)
            for problem in problems[:20]:
                print(f"  {problem}", file=sys.stderr)
            return 1
        print(f"\nIdentical to {args.verify}: forecast-summary.json and {len(details)} project forecasts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
