"""Parity tests: the Python forecast must reproduce the forecast published on the website."""

import json
import sys
import unittest
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from forecast_index import (  # noqa: E402
    compute_forecasts, first_difference, load_history, summary_document, to_json,
)
from omsindex_forecast import (  # noqa: E402
    FORECAST_FIELDS, build_forecast, convex_hull, hash_seed, quantile, round_score, seeded_random, slugify_project,
)

FIXTURES = Path(__file__).parent / "fixtures"
HISTORY = FIXTURES / "site-history-2026-11-17.csv"
SUMMARY = FIXTURES / "site-forecast-summary-2026-11-17.json"
WAZUH = FIXTURES / "site-forecast-wazuh-2026-11-17.json"


def history(days, version="5.0", start=date(2026, 1, 1), step=0.3):
    return [
        {
            "isoDate": (start + timedelta(days=day)).isoformat(),
            "indexValue": 50 + step * (day % 7),
            "indexPart1": 60 - step * (day % 5),
            "indexPart2": 40 + step * (day % 3),
            "indexVersion": version,
            "snapshotQuality": "observed",
        }
        for day in range(days)
    ]


class PublishedForecastParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.details = compute_forecasts(load_history(str(HISTORY)))
        cls.published_summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
        cls.published_wazuh_text = WAZUH.read_text(encoding="utf-8")

    def test_summary_matches(self):
        computed = json.loads(to_json(summary_document(self.details, self.published_summary["generatedAt"])))
        self.assertEqual(list(computed["projects"]), list(self.published_summary["projects"]))
        self.assertIsNone(first_difference(computed, self.published_summary))

    def test_detail_file_is_byte_identical(self):
        generated_at = json.loads(self.published_wazuh_text)["generatedAt"]
        computed = to_json({**self.details["wazuh"], "generatedAt": generated_at})
        self.assertEqual(computed, self.published_wazuh_text)


class ForecastModel(unittest.TestCase):
    def test_is_deterministic(self):
        project = {"name": "Example"}
        self.assertEqual(build_forecast(history(60), project), build_forecast(history(60), project))

    def test_starts_after_history_and_stays_in_range(self):
        result = build_forecast(history(60), {"name": "Example"}, horizon_days=14, iterations=200)
        self.assertEqual(result["model"]["status"], "ready")
        self.assertEqual(len(result["forecast"]), 14)
        self.assertGreater(result["forecast"][0]["isoDate"], result["current"]["isoDate"])
        for point in result["forecast"]:
            for field in FORECAST_FIELDS:
                self.assertTrue(0 <= point[f"{field}Lower95"] <= point[field] <= point[f"{field}Upper95"] <= 100)

    def test_is_provisional_until_30_v5_observations(self):
        records = history(40, version="4.0") + history(10, start=date(2026, 2, 10))
        result = build_forecast(records, {"name": "Example"}, horizon_days=7, iterations=50)
        self.assertEqual(result["model"]["status"], "provisional")
        self.assertEqual(result["model"]["basisVersion"], "legacy")
        self.assertEqual(result["methodologyChangedAt"], "2026-02-10")

    def test_gap_filled_days_are_not_used(self):
        records = history(40)
        for record in records[5:15]:
            record["snapshotQuality"] = "interpolated"
        result = build_forecast(records, {"name": "Example"}, horizon_days=7, iterations=50)
        self.assertEqual(result["model"]["basisObservationCount"], 30)
        self.assertEqual(len(result["history"]), 40)

    def test_single_snapshot_gives_flat_forecast(self):
        result = build_forecast(history(1), {"name": "Example"}, horizon_days=7, iterations=10)
        self.assertEqual(result["model"]["status"], "insufficient")
        self.assertEqual({point["indexValue"] for point in result["forecast"]}, {result["current"]["indexValue"]})

    def test_building_blocks(self):
        self.assertEqual(slugify_project("GRR Rapid Response"), "grr-rapid-response")
        self.assertEqual(hash_seed(""), 2166136261)
        self.assertEqual(round_score(0.25), 0.3)
        self.assertEqual(round_score(120), 100)
        self.assertEqual(quantile([1, 2, 3, 4], 0.5), 2.5)
        self.assertEqual(convex_hull([(0, 0), (1, 1), (2, 0), (1, 0), (1, 2)]), [(0, 0), (2, 0), (1, 2)])
        random = seeded_random(hash_seed("seed"))
        self.assertTrue(all(0 <= random() < 1 for _ in range(1000)))

    def test_difference_is_reported(self):
        self.assertIsNone(first_difference({"a": [1, 2.0]}, {"a": [1, 2]}))
        self.assertEqual(first_difference({"a": [1, 2]}, {"a": [1, 3]}), "/a/1: computed 2, published 3")


if __name__ == "__main__":
    unittest.main()
