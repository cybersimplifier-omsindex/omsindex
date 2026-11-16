"""OMSIndex v5 scoring and clustering.

Pure-Python reference implementation of the index published at
https://cybersimplifier.com/index. It is a line-by-line counterpart of the
calculation that runs on the website, so the same raw data yields the same
scores, ranks and clusters. It has no third-party dependencies.

Security-policy presence is kept as metadata but is intentionally not scored.
"""

from __future__ import annotations

import math
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

INDEX_VERSION = "5.0"

# Weights of the one-dimensional index (order matters for reproducibility).
INDEX_WEIGHTS: Dict[str, int] = {
    "stars": 4,
    "forks": 7,
    "subscribers": 10,
    "contributorBalance": 7,
    "contributorDepth": 7,
    "vulnerabilitiesRecent": 4,
    "cvssRecent": 4,
    "cvssPrevious": 0,
    "issueResolution": 7,
    "issueLoad": 4,
    "vulnerabilityTrend": 4,
    "cvssTrend": 8,
    "epssTrend": 8,
    "epssRisk": 7,
    "severeVulnerabilities": 7,
    "severeShare": 7,
    "releaseCadence": 0,
    "severityBurden": 2,
    "cvssImprovement": 7,
}

# Part 1 -- "Contribution & Usage" (X axis of the 2D index).
PART1_KEYS = (
    "stars",
    "forks",
    "subscribers",
    "contributorBalance",
    "contributorDepth",
    "releaseCadence",
)
PART1_WEIGHTS = (4, 7, 10, 7, 7, 7)

# Part 2 -- "Security & Issues" (Y axis of the 2D index).
PART2_KEYS = (
    "vulnerabilitiesRecent",
    "cvssRecent",
    "cvssPrevious",
    "issueResolution",
    "issueLoad",
    "vulnerabilityTrend",
    "cvssTrend",
    "epssTrend",
    "epssRisk",
    "severeVulnerabilities",
    "severeShare",
    "severityBurden",
    "cvssImprovement",
)
PART2_WEIGHTS = (4, 4, 0, 7, 4, 4, 8, 8, 7, 7, 7, 2, 7)

CLUSTER_KEYS = ("needs-attention", "promising", "mature")
CLUSTER_LABELS = {
    "needs-attention": "Needs attention",
    "promising": "Promising",
    "mature": "Mature",
}

_MISSING = object()
_DAY_MS = 86_400_000


# --------------------------------------------------------------------------
# Numeric helpers
# --------------------------------------------------------------------------

def _field(mapping: Optional[dict], key: str) -> Any:
    """Read a key, distinguishing an absent key from an explicit null."""
    if not isinstance(mapping, dict):
        return _MISSING
    return mapping.get(key, _MISSING)


def _finite(value: Any, fallback: float = 0.0) -> float:
    """Coerce to a finite float: null counts as 0, an absent value as fallback."""
    if value is _MISSING:
        return fallback
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip() or 0)
        except ValueError:
            return fallback
    else:
        return fallback
    return number if math.isfinite(number) else fallback


def _round_half_up(value: float) -> int:
    return math.floor(value + 0.5)


def _round(value: Any, decimals: int = 4) -> float:
    scale = 10 ** decimals
    return _round_half_up(_finite(value) * scale) / scale


def _clamp(value: Any, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, _finite(value)))


def _mean(values: Iterable[Any]) -> float:
    usable = [v for v in (_finite(value, math.nan) for value in values) if math.isfinite(v)]
    if not usable:
        return 0.0
    total = 0.0
    for value in usable:
        total += value
    return total / len(usable)


def _name_key(name: str):
    """Case-insensitive ordering used for deterministic tie-breaks."""
    return (name.casefold(), name.swapcase())


# --------------------------------------------------------------------------
# Step scores
# --------------------------------------------------------------------------

def score_vulnerability_count(value: float) -> float:
    if value < 0:
        return 0.3  # no vulnerability data: neutral-low score
    if value <= 3:
        return 1
    if value <= 5:
        return 0.8
    if value <= 7:
        return 0.6
    if value <= 9:
        return 0.4
    if value <= 12:
        return 0.2
    if value <= 20:
        return 0.1
    return 0


def score_issue_dynamics(value: float) -> float:
    if value > 10:
        return 1
    if value > 5:
        return 0.8
    if value >= 0:
        return 0.7
    if value > -5:
        return 0.5
    if value > -10:
        return 0.4
    if value > -15:
        return 0.2
    if value > -20:
        return 0.1
    return 0


def score_vulnerability_trend(value: float) -> float:
    if value > 5:
        return 1
    if value > 3:
        return 0.8
    if value > 1:
        return 0.6
    if value > -1:
        return 0.4
    if value > -3:
        return 0.2
    return 0


def score_severe_share(severe_count: float, total_count: float) -> float:
    if severe_count < 0 or total_count < 0:
        return 0.5
    if total_count == 0 or severe_count <= 3:
        return 1
    share = severe_count / total_count
    if share <= 0.3:
        return 0.8
    if share <= 0.5:
        return 0.5
    if share <= 0.7:
        return 0.1
    return 0


def score_release_cadence(avg_days: Any, releases_last_60_days: Any) -> float:
    """Reward a cadence close to one release every 30 days."""
    days = _finite(avg_days, 0)
    releases = max(0, _round_half_up(_finite(releases_last_60_days, 0)))
    if 25 <= days <= 35 and releases in (2, 3):
        return 1
    if 15 <= days <= 45 and releases in (2, 3):
        return 0.8
    if 10 <= days <= 55 and releases in (2, 3):
        return 0.7
    if 10 <= days <= 55 and releases in (1, 4, 5):
        return 0.6
    if (days < 10 or days > 55) and 1 <= releases <= 5:
        return 0.5
    if (days < 10 or days > 55) and 6 <= releases <= 10:
        return 0.4
    if 1 <= releases <= 15:
        return 0.3
    if releases > 0:
        return 0.2
    if days > 0:
        return 0.1
    return 0


def percentile_scores(values: Sequence[Any]) -> List[float]:
    """Mid-rank percentile of each value within the cohort, in 0.1 steps."""
    usable = [_finite(value) for value in values]
    if len(usable) <= 1:
        return [0.5 for _ in usable]
    result = []
    for value in usable:
        below = sum(1 for candidate in usable if candidate < value)
        equal = sum(1 for candidate in usable if candidate == value)
        mid_rank = below + ((equal - 1) / 2)
        result.append(_round(_round_half_up((mid_rank / (len(usable) - 1)) * 10) / 10, 1))
    return result


def _average_positive_difference(projects: Sequence[dict], previous_key: str, recent_key: str) -> float:
    improvements = []
    for project in projects:
        vulnerability = project.get("vulnerabilities")
        previous = _finite(_field(vulnerability, previous_key), -1)
        recent = _finite(_field(vulnerability, recent_key), -1)
        if previous >= 0 and recent >= 0 and previous > recent:
            improvements.append(previous - recent)
    return _mean(improvements) if improvements else 0.0


def _delta_with_missing_values(previous, recent, full, average_improvement, penalty) -> float:
    if previous >= 0 and recent >= 0:
        return previous - recent
    if previous >= 0 and recent < 0:
        return average_improvement
    if previous < 0 and recent >= 0 and full >= 0:
        return (full - recent) - penalty
    if previous < 0 and recent < 0 and full >= 0:
        return average_improvement * 1.5
    return 0.0


def _newest_epss_rank(vulnerability: dict) -> float:
    recent = _finite(_field(vulnerability, "epssRankAvg1y"), -1)
    previous = _finite(_field(vulnerability, "epssRankAvgPreviousYear"), -1)
    full = _finite(_field(vulnerability, "epssRankAvgFull"), -1)
    if recent >= 0:
        return recent
    if previous >= 0:
        return previous
    if full >= 0:
        return full
    return 0.5


def _weighted_score(scores: Dict[str, float], keys: Sequence[str], weights: Sequence[float]) -> float:
    maximum = 0
    for weight in weights:
        maximum += weight
    if not maximum:
        return 0.0
    result = 0.0
    for key, weight in zip(keys, weights):
        result += _clamp(scores.get(key, _MISSING)) * weight
    return _round((result / maximum) * 100, 1)


# --------------------------------------------------------------------------
# Clustering: complete-linkage hierarchical clustering into three groups
# --------------------------------------------------------------------------

def _standardize(rows: List[List[float]]) -> List[List[float]]:
    if not rows:
        return []
    column_count = len(rows[0])
    means = [_mean(row[column] for row in rows) for column in range(column_count)]
    deviations = []
    for column in range(column_count):
        variance = _mean((_finite(row[column]) - means[column]) ** 2 for row in rows)
        deviations.append(math.sqrt(variance) or 1)
    return [
        [_round((_finite(value) - means[column]) / deviations[column], 4) for column, value in enumerate(row)]
        for row in rows
    ]


def _euclidean(left: Sequence[float], right: Sequence[float]) -> float:
    total = 0.0
    for a, b in zip(left, right):
        total += (a - b) ** 2
    return math.sqrt(total)


def _hierarchical_clusters(rows: List[List[float]], cluster_count: int = 3) -> List[List[int]]:
    if not rows:
        return []
    size = len(rows)
    pairwise = [[_euclidean(rows[i], rows[j]) for j in range(size)] for i in range(size)]

    def linkage(left: List[int], right: List[int]) -> float:
        maximum = 0.0
        for i in left:
            for j in right:
                maximum = max(maximum, pairwise[i][j])
        return maximum

    clusters = [[index] for index in range(size)]
    while len(clusters) > min(cluster_count, size):
        best_left, best_right, best_distance = 0, 1, math.inf
        for left in range(len(clusters) - 1):
            for right in range(left + 1, len(clusters)):
                distance = linkage(clusters[left], clusters[right])
                current_key = f"{clusters[left][0]}:{clusters[right][0]}"
                best_key = f"{clusters[best_left][0]}:{clusters[best_right][0]}"
                if distance < best_distance or (distance == best_distance and current_key < best_key):
                    best_left, best_right, best_distance = left, right, distance
        merged = sorted(clusters[best_left] + clusters[best_right])
        del clusters[best_right]
        clusters[best_left] = merged
    return clusters


def _min_or_zero(limit: float, value: Any) -> float:
    if value is _MISSING:
        return 0.0
    return min(limit, _finite(value))


def _cluster_feature_row(project: dict) -> List[float]:
    gh = project.get("github") or {}
    vulnerability = project.get("vulnerabilities") or {}
    metrics = project.get("metrics") or {}
    values = [
        _field(gh, "stars"),
        _field(gh, "forks"),
        _field(gh, "subscribers"),
        _field(gh, "top10ContributorShare"),
        _field(gh, "singleContributionShare"),
        _field(vulnerability, "recentCount"),
        _field(vulnerability, "cvssAvg1y"),
        _field(vulnerability, "cvssAvgPreviousYear"),
        _field(metrics, "issuesDynamic"),
        _min_or_zero(15, _field(metrics, "openIssuesPerContributor")),
        _field(metrics, "deltaVulnerabilities"),
        _field(metrics, "deltaCvss"),
        _field(metrics, "deltaEpss"),
        _field(metrics, "newestEpssRank"),
        _field(metrics, "ageInDays"),
        _field(vulnerability, "highSeverityCount1y"),
        _field(metrics, "highSeverityShare"),
        _min_or_zero(100, _field(gh, "avgDaysBetweenReleases")),
        project.get("indexPart1", _MISSING),
        project.get("indexPart2", _MISSING),
    ]
    return [_finite(value) for value in values]


def _add_clusters(projects: List[dict]) -> List[dict]:
    if not projects:
        return projects
    standardized = _standardize([_cluster_feature_row(project) for project in projects])
    for row in standardized:
        # The two index dimensions dominate the grouping.
        row[-2] *= 3
        row[-1] *= 3
    clusters = _hierarchical_clusters(standardized, 3)
    ordered = sorted(
        (
            {
                "members": members,
                "centroid": _mean(projects[index]["indexValue"] for index in members),
                "tieBreaker": sorted(projects[index]["name"] for index in members)[0],
            }
            for members in clusters
        ),
        key=lambda cluster: (cluster["centroid"], _name_key(cluster["tieBreaker"])),
    )
    for stable_index, cluster in enumerate(ordered):
        for project_index in cluster["members"]:
            projects[project_index]["clusterId"] = stable_index + 1
            projects[project_index]["clusterKey"] = CLUSTER_KEYS[min(stable_index, len(CLUSTER_KEYS) - 1)]
    return projects


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def _age_in_days(created_at: Any, now_ms: float) -> float:
    if not created_at or not isinstance(created_at, str):
        return 0
    try:
        created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, math.floor((now_ms - created.timestamp() * 1000) / _DAY_MS))


def compute_index_v5(projects: Sequence[dict], now_ms: Optional[float] = None) -> List[dict]:
    """Score, rank and cluster projects.

    Each project needs ``name`` plus the raw ``github`` and ``vulnerabilities``
    dictionaries (see ``security_index.py`` for how they are collected).
    ``now_ms`` is the reference time in epoch milliseconds; pass the snapshot
    timestamp to reproduce a published result exactly.
    """
    if now_ms is None:
        now_ms = time.time() * 1000

    normalized = [
        {
            **project,
            "github": dict(project.get("github") or {}),
            "vulnerabilities": dict(project.get("vulnerabilities") or {}),
        }
        for project in projects
    ]

    cvss_improvement_average = _average_positive_difference(normalized, "cvssAvgPreviousYear", "cvssAvg1y")
    epss_improvement_average = _average_positive_difference(normalized, "epssAvgPreviousYear", "epssAvg1y")

    raw_rows = []
    for project in normalized:
        gh = project["github"]
        vulnerability = project["vulnerabilities"]
        stats_missing = vulnerability.get("statsAvailable", _MISSING) is False

        contributor_count = max(0, _finite(_field(gh, "contributorCount")))
        top10_share = 1 if 0 < contributor_count < 10 else _clamp(_field(gh, "top10ContributorShare"))
        single_share = _clamp(_field(gh, "singleContributionShare"))
        recent_count = -1 if stats_missing else _finite(_field(vulnerability, "recentCount"), -1)
        two_year_count = -1 if stats_missing else _finite(_field(vulnerability, "twoYearCount"), -1)
        high_count = -1 if stats_missing else _finite(_field(vulnerability, "highSeverityCount1y"), -1)
        cvss_recent = _finite(_field(vulnerability, "cvssAvg1y"), -1)
        cvss_previous = _finite(_field(vulnerability, "cvssAvgPreviousYear"), -1)
        cvss_full = _finite(_field(vulnerability, "cvssAvgFull"), -1)
        epss_recent = _finite(_field(vulnerability, "epssAvg1y"), -1)
        epss_previous = _finite(_field(vulnerability, "epssAvgPreviousYear"), -1)
        epss_full = _finite(_field(vulnerability, "epssAvgFull"), -1)

        new_issues = _finite(_field(gh, "newIssuesLast30Days"))
        closed_issues = _finite(_field(gh, "closedIssuesLast30Days"))
        issue_scale = 1 if new_issues < 20 else 10
        issues_dynamic = (new_issues - closed_issues) / issue_scale
        open_issues_per_contributor = _finite(_field(gh, "openIssues")) / max(1, contributor_count)
        delta_vulnerabilities = two_year_count - (2 * recent_count)
        delta_cvss = _delta_with_missing_values(cvss_previous, cvss_recent, cvss_full, cvss_improvement_average, 0.5)
        delta_epss = _delta_with_missing_values(epss_previous, epss_recent, epss_full, epss_improvement_average, 0.1)
        epss_rank = _newest_epss_rank(vulnerability)
        age_in_days = _age_in_days(gh.get("createdAt"), now_ms)
        high_severity_share = high_count / recent_count if recent_count > 0 and high_count >= 0 else 0
        severity_burden = recent_count * cvss_recent if recent_count >= 0 and cvss_recent >= 0 else -1

        raw_rows.append({
            "project": project,
            "raw": {
                "stars": _finite(_field(gh, "stars")),
                "forks": _finite(_field(gh, "forks")),
                "subscribers": _finite(_field(gh, "subscribers")),
                "issueLoad": -open_issues_per_contributor,
                "severityBurden": -severity_burden,
            },
            "metrics": {
                # Ideal: the ten most active contributors author 60% of the work.
                "contributorBalance": _clamp(1 - abs(top10_share - 0.6)),
                "contributorDepth": _clamp(1 - single_share),
                "vulnerabilitiesRecent": score_vulnerability_count(recent_count),
                "cvssRecent": _clamp(1 - ((cvss_recent if cvss_recent >= 0 else 3) / 10)),
                "cvssPrevious": _clamp(1 - ((cvss_previous if cvss_previous >= 0 else 3) / 10)),
                "issueResolution": score_issue_dynamics(-issues_dynamic),
                "vulnerabilityTrend": score_vulnerability_trend(delta_vulnerabilities),
                "cvssTrend": _clamp((delta_cvss + 2) / 4),
                "epssTrend": _clamp((delta_epss + 0.1) / 0.4),
                "epssRisk": _clamp(1 - epss_rank),
                "severeVulnerabilities": score_vulnerability_count(high_count),
                "severeShare": score_severe_share(high_count, recent_count),
                "releaseCadence": score_release_cadence(
                    _field(gh, "avgDaysBetweenReleases"), _field(gh, "releasesLast60Days")
                ),
                "cvssImprovement": 0,
            },
            "diagnostic": {
                "ageInDays": age_in_days,
                "issuesDynamic": issues_dynamic,
                "openIssuesPerContributor": open_issues_per_contributor,
                "deltaVulnerabilities": delta_vulnerabilities,
                "deltaCvss": delta_cvss,
                "deltaEpss": delta_epss,
                "newestEpssRank": epss_rank,
                "highSeverityShare": high_severity_share,
            },
        })

    # Cohort-relative scores: where a project sits among all indexed projects.
    relative = {
        key: percentile_scores([row["raw"][key] for row in raw_rows])
        for key in ("stars", "forks", "subscribers", "issueLoad", "severityBurden")
    }

    index_keys = list(INDEX_WEIGHTS.keys())
    index_weights = list(INDEX_WEIGHTS.values())

    scored = []
    for position, row in enumerate(raw_rows):
        scores = {
            "stars": relative["stars"][position],
            "forks": relative["forks"][position],
            "subscribers": relative["subscribers"][position],
            **row["metrics"],
            "issueLoad": relative["issueLoad"][position],
            "severityBurden": relative["severityBurden"][position],
        }
        cvss_delta = scores["cvssRecent"] - scores["cvssPrevious"]
        scores["cvssImprovement"] = _clamp((cvss_delta + 0.2) / 1.2) if cvss_delta >= 0 else 0

        scored.append({
            **row["project"],
            "scores": {key: _round(_clamp(value), 4) for key, value in scores.items()},
            "metrics": {key: _round(value, 6) for key, value in row["diagnostic"].items()},
            "indexValue": _weighted_score(scores, index_keys, index_weights),
            "indexPart1": _weighted_score(scores, PART1_KEYS, PART1_WEIGHTS),
            "indexPart2": _weighted_score(scores, PART2_KEYS, PART2_WEIGHTS),
            "indexVersion": INDEX_VERSION,
        })

    ranked = sorted(scored, key=lambda project: (-project["indexValue"], _name_key(project["name"])))
    for position, project in enumerate(ranked):
        project["rank"] = position + 1
    return _add_clusters(ranked)
