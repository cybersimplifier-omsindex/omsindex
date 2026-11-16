"""Parity tests: the Python index must reproduce the values published on the website."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from omsindex_math import (  # noqa: E402
    INDEX_WEIGHTS, PART1_KEYS, PART2_KEYS, compute_index_v5, percentile_scores, score_release_cadence,
)
from security_index import COMPUTED_KEYS, raw_projects  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "site-snapshot-2026-11-16.json"


class PublishedSnapshotParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.result = compute_index_v5(raw_projects(cls.snapshot), now_ms=cls.snapshot["timestamp"])

    def test_same_ranking_order(self):
        self.assertEqual(
            [project["name"] for project in self.result],
            [project["name"] for project in self.snapshot["data"]],
        )

    def test_every_computed_field_matches(self):
        for computed, published in zip(self.result, self.snapshot["data"]):
            for key in COMPUTED_KEYS:
                self.assertEqual(computed[key], published[key], f"{computed['name']}: {key}")

    def test_three_clusters(self):
        self.assertEqual({project["clusterId"] for project in self.result}, {1, 2, 3})


class ScoringRules(unittest.TestCase):
    def test_two_dimensions_cover_all_scored_components(self):
        scored = {key for key, weight in INDEX_WEIGHTS.items() if weight}
        self.assertTrue(scored <= set(PART1_KEYS) | set(PART2_KEYS))
        self.assertFalse(set(PART1_KEYS) & set(PART2_KEYS))

    def test_percentile_scores_are_relative_to_the_cohort(self):
        self.assertEqual(percentile_scores([10, 20, 30]), [0.0, 0.5, 1.0])
        self.assertEqual(percentile_scores([5, 5]), [0.5, 0.5])
        self.assertEqual(percentile_scores([7]), [0.5])

    def test_release_cadence_prefers_monthly_releases(self):
        self.assertEqual(score_release_cadence(30, 2), 1)
        self.assertEqual(score_release_cadence(3, 20), 0.2)
        self.assertEqual(score_release_cadence(0, 0), 0)

    def test_missing_data_does_not_crash(self):
        result = compute_index_v5([{"name": "Empty", "github": None, "vulnerabilities": None}], now_ms=0)
        self.assertEqual(result[0]["rank"], 1)
        self.assertEqual(result[0]["clusterKey"], "needs-attention")


if __name__ == "__main__":
    unittest.main()
