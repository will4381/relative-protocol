import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import harness  # noqa: E402


class HarnessPolicyTests(unittest.TestCase):
    def test_percentile_interpolates(self):
        values = [10, 20, 30, 40]
        self.assertAlmostEqual(harness.percentile(values, 0.5), 25.0)
        self.assertAlmostEqual(harness.percentile(values, 0.95), 38.5)

    def test_baseline_uses_recent_passing_rows(self):
        rows = []
        for i in range(12):
            rows.append(
                {
                    "suite": "smoke",
                    "scenario": "smoke-core",
                    "profile": "wifi",
                    "stack_mode": "dual_stack",
                    "success_rate": 0.99,
                    "p50_ms": 20 + i,
                    "p95_ms": 40 + i,
                    "pass": True,
                }
            )
        baseline = harness.baseline_for(rows, "smoke", "smoke-core", "wifi", "dual_stack")
        self.assertIsNotNone(baseline)
        assert baseline is not None
        self.assertEqual(baseline.sample_count, 10)
        self.assertAlmostEqual(baseline.p50_ms, 26.5)
        self.assertAlmostEqual(baseline.p95_ms, 46.5)

    def test_regression_flags_success_and_latency(self):
        baseline = harness.Baseline(success_rate=0.995, p50_ms=100.0, p95_ms=200.0, sample_count=10)
        passed, delta, reasons = harness.evaluate_regression(
            success_rate=0.97,
            p50_ms=130.0,
            p95_ms=280.0,
            ipv4_ok=True,
            ipv6_ok=True,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=baseline,
        )
        self.assertFalse(passed)
        self.assertIn("success_rate_below_threshold:0.9700", reasons)
        self.assertTrue(any(reason.startswith("p50_regression") for reason in reasons))
        self.assertTrue(any(reason.startswith("p95_regression") for reason in reasons))
        self.assertGreater(delta["p50"], 0.20)
        self.assertGreater(delta["p95"], 0.30)

    def test_warmup_does_not_fail_without_other_issues(self):
        passed, delta, reasons = harness.evaluate_regression(
            success_rate=0.995,
            p50_ms=100.0,
            p95_ms=200.0,
            ipv4_ok=True,
            ipv6_ok=True,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=harness.Baseline(success_rate=0.995, p50_ms=100.0, p95_ms=200.0, sample_count=2),
        )
        self.assertTrue(passed)
        self.assertEqual(reasons, [])
        self.assertEqual(delta.get("baseline_warmup"), 1.0)

    def test_dual_stack_requires_not_both_lost(self):
        passed, _, reasons = harness.evaluate_regression(
            success_rate=0.995,
            p50_ms=10,
            p95_ms=20,
            ipv4_ok=False,
            ipv6_ok=False,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=None,
        )
        self.assertFalse(passed)
        self.assertIn("dual_stack_lost_ipv4_and_ipv6", reasons)


if __name__ == "__main__":
    unittest.main()
