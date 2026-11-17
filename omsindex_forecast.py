"""OMSIndex score forecast -- joint moving-block bootstrap (v1).

Reference implementation of the forecast shown at https://cybersimplifier.com/index.
Given the same score history it reproduces the published forecast exactly: the
random numbers come from a seeded generator, so there is nothing to tune and
nothing hidden. No third-party dependencies.

The model, in short
-------------------
1. Take the project's last 90 *observed* daily snapshots in the v5 methodology
   (gap-filled days are ignored). Until 30 such snapshots exist the pre-v5
   history is used instead and the forecast is marked provisional.
2. Turn them into daily increments of three values at once: the index, the
   Contribution & Usage dimension and the Security & Issues dimension.
3. Simulate 1000 futures. Each one starts at today's values and repeatedly
   appends a randomly chosen 7-day block of historical increments (wrapping
   around the end of the history), clamping every value to 0-100. Because a
   block moves all three values together, their dependence is preserved, and
   no distribution is assumed.
4. For every future day report the median as the forecast and the 2.5% / 97.5%
   quantiles as the 95% uncertainty interval. For the 2D chart, also report
   the regions that contain the central 95/80/50/20/5% of simulated positions.

This is an extrapolation of how much the score has moved recently. It does not
predict new vulnerabilities, releases or any other event.
"""

from __future__ import annotations

import math
import re
import unicodedata
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

FORECAST_MODEL_VERSION = "joint-moving-block-bootstrap-v1"
FORECAST_MODEL_NAME = "Joint moving-block bootstrap"
FORECAST_ITERATIONS = 1000
FORECAST_BLOCK_DAYS = 7
HOVER_FORECAST_DAYS = 30
DETAIL_FORECAST_DAYS = 90
BASIS_WINDOW = 90
V5_MIN_OBSERVATIONS = 30
CONFIDENCE_LEVEL = 0.95
TRAJECTORY_CONFIDENCE_LEVELS = (95, 80, 50, 20, 5)
TRAJECTORY_MILESTONE_DAYS = (5, 10, 15, 20, 25, 30)

FORECAST_FIELDS = ("indexValue", "indexPart1", "indexPart2")

Point = Tuple[float, float]
_UINT32 = 0xFFFFFFFF
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# ---------------------------------------------------------------- helpers ----

def slugify_project(value: Any) -> str:
    """"Security Onion" -> "security-onion"."""
    text = unicodedata.normalize("NFKD", str(value or "").lower())
    text = re.sub(r"[̀-ͯ]", "", text)
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")


def _clamp_score(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(100.0, value))


def _round_half_up(value: float) -> int:
    floor = math.floor(value)
    return floor + 1 if value - floor >= 0.5 else floor


def round_score(value: float, decimals: int = 1) -> float:
    scale = 10 ** decimals
    return _round_half_up(_clamp_score(value) * scale) / scale


def _numeric(value: Any, fallback: float = 0.0) -> float:
    if value is None or value == "":
        return fallback
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return number if math.isfinite(number) else fallback


def _field(mapping: Optional[dict], key: str) -> Any:
    return mapping.get(key) if isinstance(mapping, dict) else None


def parse_iso_date(value: Any) -> Optional[str]:
    """Accept "2026-11-17" as well as the website's "17-11-2026"."""
    text = str(value or "")
    if _ISO_DATE.match(text):
        return text
    parts = re.split(r"[.-]", text)
    if len(parts) >= 3 and all(parts[:3]):
        day, month, year = parts[:3]
        return f"{year}-{month}-{day}"
    return None


def _display_date(iso_date: str) -> str:
    parts = str(iso_date or "").split("-")
    if len(parts) >= 3 and all(parts[:3]):
        return f"{parts[2]}-{parts[1]}-{parts[0]}"
    return str(iso_date or "")


def _add_days(iso_date: str, days: int) -> str:
    return (date.fromisoformat(iso_date) + timedelta(days=days)).isoformat()


def _day_difference(left: str, right: str) -> int:
    return (date.fromisoformat(right) - date.fromisoformat(left)).days


def _methodology(record: Optional[dict]) -> str:
    return "v5" if str(_field(record, "indexVersion") or "").startswith("5") else "legacy"


def quantile(values: Sequence[float], probability: float) -> float:
    """Linear-interpolation quantile (the "type 7" definition)."""
    ordered = sorted(value for value in values if math.isfinite(value))
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def median(values: Sequence[float]) -> float:
    return quantile(values, 0.5)


# ------------------------------------------------- deterministic randomness ----

def hash_seed(value: str) -> int:
    """32-bit FNV-1a hash of the seed text."""
    result = 2166136261
    for character in str(value):
        code = ord(character)
        if code > 0xFFFF:  # the website hashes UTF-16 code units
            code = 0xD800 + ((code - 0x10000) >> 10)
        result = ((result ^ code) * 16777619) & _UINT32
    return result


def seeded_random(seed: int) -> Callable[[], float]:
    """Mulberry32-style generator returning floats in [0, 1).

    The state is kept as a double on purpose: the website's generator does not
    wrap its counter to 32 bits, and this keeps both in step for any length.
    """
    state = float(seed or 1)

    def random() -> float:
        nonlocal state
        state += 0x6D2B79F5
        value = int(state) & _UINT32
        value = ((value ^ (value >> 15)) * (value | 1)) & _UINT32
        value = (value ^ (value + (value ^ (value >> 7)) * (value | 61))) & _UINT32
        return (value ^ (value >> 14)) / 4294967296

    return random


# ------------------------------------------------------------------ history ----

def _history_point(record: dict, fallback_project: Optional[dict]) -> Optional[dict]:
    iso_date = parse_iso_date(_field(record, "isoDate") or _field(record, "date"))
    if not iso_date:
        return None
    point = {"date": _field(record, "date") or _display_date(iso_date), "isoDate": iso_date}
    for field in FORECAST_FIELDS:
        point[field] = round_score(_numeric(_field(record, field), _numeric(_field(fallback_project, field))))
    point["indexVersion"] = _field(record, "indexVersion") or None
    point["methodology"] = _methodology(record)
    point["snapshotQuality"] = _field(record, "snapshotQuality") or "observed"
    return point


def prepare_history(history: Optional[Sequence[dict]], current_project: Optional[dict] = None) -> List[dict]:
    """One point per day, oldest first; an observed snapshot wins over a gap-filled one."""
    by_date: Dict[str, dict] = {}
    for record in history or []:
        point = _history_point(record, current_project)
        if not point:
            continue
        existing = by_date.get(point["isoDate"])
        if existing is None or (existing["snapshotQuality"] != "observed" and point["snapshotQuality"] == "observed"):
            by_date[point["isoDate"]] = point
    ordered = [by_date[key] for key in sorted(by_date)]

    # A gap-filled day can carry the version of the snapshot that follows it,
    # i.e. from before the methodology went live. The v5 boundary is therefore
    # the first *observed* v5 snapshot, never a synthetic point.
    first_observed_v5 = next(
        (p["isoDate"] for p in ordered if p["methodology"] == "v5" and p["snapshotQuality"] == "observed"),
        None,
    )
    for point in ordered:
        point["methodology"] = "v5" if first_observed_v5 and point["isoDate"] >= first_observed_v5 else "legacy"
    return ordered


def daily_increments(points: Sequence[dict]) -> List[Tuple[float, float, float]]:
    """Per-day change of (index, part 1, part 2) between consecutive snapshots."""
    increments = []
    for previous, current in zip(points, points[1:]):
        elapsed = _day_difference(previous["isoDate"], current["isoDate"])
        if elapsed <= 0:
            continue
        increments.append(tuple((current[field] - previous[field]) / elapsed for field in FORECAST_FIELDS))
    return increments


def _segment_history(history: Sequence[dict]) -> List[dict]:
    segments: List[dict] = []
    for point in history:
        if not segments or segments[-1]["methodology"] != point["methodology"]:
            segments.append({"methodology": point["methodology"], "points": [point]})
        else:
            segments[-1]["points"].append(point)
    return segments


# --------------------------------------------------------------- simulation ----

def sample_path(
    increments: Sequence[Tuple[float, float, float]],
    start: Tuple[float, float, float],
    horizon_days: int,
    random: Callable[[], float],
    block_days: int,
) -> List[Tuple[float, float, float]]:
    """One simulated future: a list of (index, part 1, part 2), one entry per day."""
    values = list(start)
    if not increments:
        return [tuple(values)] * horizon_days

    path: List[Tuple[float, float, float]] = []
    while len(path) < horizon_days:
        block_start = math.floor(random() * len(increments))
        for offset in range(block_days):
            if len(path) >= horizon_days:
                break
            increment = increments[(block_start + offset) % len(increments)]
            values = [_clamp_score(value + change) for value, change in zip(values, increment)]
            path.append(tuple(values))
    return path


def _summarize(samples: Sequence[Sequence[Tuple[float, float, float]]], current: dict, horizon_days: int) -> List[dict]:
    forecast = []
    for day in range(horizon_days):
        iso_date = _add_days(current["isoDate"], day + 1)
        point: Dict[str, Any] = {"date": _display_date(iso_date), "isoDate": iso_date, "snapshotQuality": "forecast"}
        for position, field in enumerate(FORECAST_FIELDS):
            values = [sample[day][position] for sample in samples]
            point[field] = round_score(median(values))
            point[f"{field}Lower95"] = round_score(quantile(values, 0.025))
            point[f"{field}Upper95"] = round_score(quantile(values, 0.975))
        forecast.append(point)
    return forecast


# ------------------------------------------------------------ 2D geometry ----

def _cross(origin: Point, middle: Point, end: Point) -> float:
    return (middle[0] - origin[0]) * (end[1] - origin[1]) - (middle[1] - origin[1]) * (end[0] - origin[0])


def convex_hull(points: Sequence[Point]) -> List[Point]:
    """Andrew's monotone chain; counter-clockwise, collinear points dropped."""
    unique = sorted(set(points))
    if len(unique) <= 2:
        return unique

    def chain(sequence) -> List[Point]:
        result: List[Point] = []
        for point in sequence:
            while len(result) >= 2 and _cross(result[-2], result[-1], point) <= 0:
                result.pop()
            result.append(point)
        return result

    return chain(unique)[:-1] + chain(reversed(unique))[:-1]


def _bounding_box(points: Sequence[Point]) -> List[Point]:
    x_low = round_score(min(x for x, _ in points))
    x_high = round_score(max(x for x, _ in points))
    y_low = round_score(min(y for _, y in points))
    y_high = round_score(max(y for _, y in points))
    return [(x_low, y_low), (x_high, y_low), (x_high, y_high), (x_low, y_high)]


def central_region(points: Sequence[Point], confidence_level: float) -> List[Point]:
    """Convex hull of the `confidence_level` share of points closest to the median.

    Distance is measured in median absolute deviations along each axis, so the
    region is robust to outliers and to the two axes having different spreads.
    """
    if not points:
        return []
    center_x = median([x for x, _ in points])
    center_y = median([y for _, y in points])
    mad_x = median([abs(x - center_x) for x, _ in points]) or 1.0
    mad_y = median([abs(y - center_y) for _, y in points]) or 1.0

    def distance(point: Point) -> float:
        dx = (point[0] - center_x) / mad_x
        dy = (point[1] - center_y) / mad_y
        return dx * dx + dy * dy

    keep = max(1, math.ceil(len(points) * confidence_level))
    central = [(round_score(x), round_score(y)) for x, y in sorted(points, key=distance)[:keep]]
    hull = convex_hull(central)
    return hull if len(hull) >= 3 else _bounding_box(central)


def _milestones(horizon_days: int) -> List[int]:
    return sorted({day for day in TRAJECTORY_MILESTONE_DAYS if day <= horizon_days} | {horizon_days})


def _xy(points: Sequence[Point]) -> List[dict]:
    return [{"x": x, "y": y} for x, y in points]


def _trajectory_fan(samples, current: dict, forecast: Sequence[dict], horizon_days: int) -> dict:
    """Where the project may travel on the 2D chart over the next 30 days."""
    fan_days = min(HOVER_FORECAST_DAYS, horizon_days)
    milestone_days = _milestones(fan_days)
    origin = (current["indexPart1"], current["indexPart2"])
    regions = []
    for level in TRAJECTORY_CONFIDENCE_LEVELS:
        envelope = [origin]
        for day in milestone_days:
            positions = [(sample[day - 1][1], sample[day - 1][2]) for sample in samples]
            envelope.extend(central_region(positions, level / 100))
        polygon = convex_hull([(round_score(x), round_score(y)) for x, y in envelope])
        regions.append({"level": level, "polygon": _xy(polygon if len(polygon) >= 3 else _bounding_box(envelope))})

    median_path = [{"day": 0, "isoDate": current["isoDate"], **{field: current[field] for field in FORECAST_FIELDS}}]
    for day in milestone_days:
        step = forecast[day - 1]
        median_path.append({"day": day, "isoDate": step["isoDate"], **{field: step[field] for field in FORECAST_FIELDS}})
    return {"horizonDays": fan_days, "milestoneDays": milestone_days, "medianPath": median_path, "regions": regions}


# ----------------------------------------------------------------- forecast ----

def build_forecast(
    history: Optional[Sequence[dict]],
    current_project: Optional[dict],
    horizon_days: int = DETAIL_FORECAST_DAYS,
    iterations: int = FORECAST_ITERATIONS,
    block_days: int = FORECAST_BLOCK_DAYS,
    v5_minimum: int = V5_MIN_OBSERVATIONS,
) -> dict:
    """Forecast one project.

    ``history`` is the project's daily records, each with ``date`` (or
    ``isoDate``), ``indexValue``, ``indexPart1``, ``indexPart2``,
    ``indexVersion`` and ``snapshotQuality``. ``current_project`` is its latest
    record; only ``name`` is required. The result has the same shape as the
    website's ``/exports/forecasts/<slug>.json``.
    """
    points = prepare_history(history, current_project)
    if points:
        current = points[-1]
    else:
        fallback_iso = parse_iso_date(_field(current_project, "date")) or datetime.now(timezone.utc).date().isoformat()
        current = {"date": _display_date(fallback_iso), "isoDate": fallback_iso}
        for field in FORECAST_FIELDS:
            current[field] = round_score(_numeric(_field(current_project, field)))
        current["indexVersion"] = _field(current_project, "indexVersion") or None
        current["methodology"] = _methodology(current_project)
        current["snapshotQuality"] = "observed"

    observed = [point for point in points if point["snapshotQuality"] == "observed"]
    v5_observed = [point for point in observed if point["methodology"] == "v5"]
    legacy_observed = [point for point in observed if point["methodology"] == "legacy"]
    use_v5 = len(v5_observed) >= v5_minimum
    basis = (v5_observed if use_v5 else legacy_observed)[-BASIS_WINDOW:]
    increments = daily_increments(basis)
    provisional = not use_v5
    status = ("provisional" if provisional else "ready") if increments else "insufficient"

    name = _field(current_project, "name") or ""
    slug = slugify_project(name)
    basis_version = "v5" if use_v5 else "legacy"
    seed_text = ":".join([FORECAST_MODEL_VERSION, slug, current["isoDate"], basis_version, str(len(increments))])
    random = seeded_random(hash_seed(seed_text))

    start = tuple(current[field] for field in FORECAST_FIELDS)
    samples = [sample_path(increments, start, horizon_days, random, block_days) for _ in range(iterations)]
    forecast = _summarize(samples, current, horizon_days)
    hover_days = min(HOVER_FORECAST_DAYS, horizon_days)
    hover_positions = [(sample[hover_days - 1][1], sample[hover_days - 1][2]) for sample in samples]

    return {
        "slug": slug,
        "projectName": name,
        "current": current,
        "endpoint": forecast[-1] if forecast else current,
        "hoverEndpoint": forecast[hover_days - 1] if forecast else current,
        "positionRegion95": _xy(central_region(hover_positions, CONFIDENCE_LEVEL)),
        "trajectoryFan": _trajectory_fan(samples, current, forecast, hover_days),
        "forecast": forecast,
        "history": points,
        "historySegments": _segment_history(points),
        "methodologyChangedAt": next((p["isoDate"] for p in points if p["methodology"] == "v5"), None),
        "horizonDays": horizon_days,
        "hoverHorizonDays": hover_days,
        "model": {
            "version": FORECAST_MODEL_VERSION,
            "name": FORECAST_MODEL_NAME,
            "status": status,
            "provisional": provisional,
            "basisVersion": basis_version,
            "basisObservationCount": len(basis),
            "v5ObservationCount": len(v5_observed),
            "switchAtV5Observations": v5_minimum,
            "incrementCount": len(increments),
            "sampleSize": len(basis),
            "iterations": iterations,
            "blockDays": block_days,
            "confidenceLevel": CONFIDENCE_LEVEL,
            "observedFrom": basis[0]["isoDate"] if basis else current["isoDate"],
            "observedTo": basis[-1]["isoDate"] if basis else current["isoDate"],
        },
    }


def forecast_summary(detail: dict) -> dict:
    """The lightweight 30-day view, as in the website's ``/exports/forecast-summary.json``."""
    return {
        "slug": detail["slug"],
        "projectName": detail["projectName"],
        "current": detail["current"],
        "endpoint": detail["hoverEndpoint"],
        "positionRegion95": detail["positionRegion95"],
        "trajectoryFan": detail["trajectoryFan"],
        "horizonDays": detail["hoverHorizonDays"],
        "model": detail["model"],
    }
