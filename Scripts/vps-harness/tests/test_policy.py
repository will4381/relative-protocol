import json
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import harness  # noqa: E402


class HarnessPolicyTests(unittest.TestCase):
    class _FakeStatusControl:
        def __init__(self, rss_samples, socket_buffer_capped=False):
            self._samples = list(rss_samples)
            self._last = int(self._samples[-1]) if self._samples else 0
            self._peak = 0
            self._socket_buffer_capped = socket_buffer_capped
            self._lock = threading.Lock()

        def send(self, command, **_kwargs):
            if command != "status":
                return {"ok": True}
            with self._lock:
                if self._samples:
                    self._last = int(self._samples.pop(0))
                self._peak = max(self._peak, self._last)
                return {
                    "ok": True,
                    "status": {
                        "residentMemoryBytes": self._last,
                        "peakResidentMemoryBytes": self._peak,
                        "socketBufferCapped": self._socket_buffer_capped,
                    },
                }

    def test_percentile_interpolates(self):
        values = [10, 20, 30, 40]
        self.assertAlmostEqual(harness.percentile(values, 0.5), 25.0)
        self.assertAlmostEqual(harness.percentile(values, 0.95), 38.5)

    def test_baseline_uses_recent_passing_rows(self):
        rows = []
        for i in range(12):
            rows.append(
                {
                    "harness_baseline_version": harness.HARNESS_BASELINE_VERSION,
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
            profile="wifi",
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

    def test_regression_relative_only_below_absolute_floor_does_not_fail(self):
        baseline = harness.Baseline(success_rate=0.995, p50_ms=100.0, p95_ms=150.0, sample_count=10)
        passed, delta, reasons = harness.evaluate_regression(
            success_rate=0.995,
            p50_ms=120.0,
            p95_ms=196.0,  # +30.6% but +46ms absolute (below 60ms floor)
            profile="wifi",
            ipv4_ok=True,
            ipv6_ok=True,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=baseline,
        )
        self.assertTrue(passed)
        self.assertEqual(reasons, [])
        self.assertGreater(delta["p95"], 0.30)

    def test_warmup_does_not_fail_without_other_issues(self):
        passed, delta, reasons = harness.evaluate_regression(
            success_rate=0.995,
            p50_ms=100.0,
            p95_ms=200.0,
            profile="wifi",
            ipv4_ok=True,
            ipv6_ok=True,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=harness.Baseline(success_rate=0.995, p50_ms=100.0, p95_ms=200.0, sample_count=2),
        )
        self.assertTrue(passed)
        self.assertEqual(reasons, [])
        self.assertEqual(delta.get("baseline_warmup"), 1.0)

    def test_negative_regression_delta_does_not_fail(self):
        baseline = harness.Baseline(success_rate=0.99, p50_ms=120.0, p95_ms=240.0, sample_count=6)
        passed, delta, reasons = harness.evaluate_regression(
            success_rate=0.995,
            p50_ms=100.0,
            p95_ms=180.0,
            profile="wifi",
            ipv4_ok=True,
            ipv6_ok=True,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=baseline,
        )
        self.assertTrue(passed)
        self.assertEqual(reasons, [])
        self.assertLess(delta["p50"], 0.0)
        self.assertLess(delta["p95"], 0.0)

    def test_dual_stack_requires_not_both_lost(self):
        passed, _, reasons = harness.evaluate_regression(
            success_rate=0.995,
            p50_ms=10,
            p95_ms=20,
            profile="wifi",
            ipv4_ok=False,
            ipv6_ok=False,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=None,
        )
        self.assertFalse(passed)
        self.assertIn("dual_stack_lost_ipv4_and_ipv6", reasons)

    def test_dirty_profile_has_lower_success_floor(self):
        passed, _, reasons = harness.evaluate_regression(
            success_rate=0.97,
            p50_ms=20,
            p95_ms=40,
            profile="dirty",
            ipv4_ok=True,
            ipv6_ok=True,
            stack_mode="dual_stack",
            loop_detected=False,
            baseline=None,
        )
        self.assertTrue(passed)
        self.assertEqual(reasons, [])

    def test_parse_socks_udp_response_round_trip(self):
        payload = b"hello"
        packet = b"\x00\x00\x00" + harness.encode_socks_addr("157.245.121.27") + b"\x1b\x8d" + payload
        host, port, parsed_payload = harness.parse_socks_udp_response(packet)
        self.assertEqual(host, "157.245.121.27")
        self.assertEqual(port, 7053)
        self.assertEqual(parsed_payload, payload)

    def test_summarize_latencies_reports_shape(self):
        summary = harness.summarize_latencies([10.0, 20.0, 30.0, 40.0])
        self.assertEqual(summary["count"], 4.0)
        self.assertAlmostEqual(summary["p50_ms"], 25.0)
        self.assertAlmostEqual(summary["p95_ms"], 38.5)
        self.assertAlmostEqual(summary["max_ms"], 40.0)

    def test_socks_udp_recv_ignores_stale_response_until_match(self):
        class FakeUDPSocket:
            def __init__(self, responses):
                self.responses = list(responses)
                self.sent = []

            def sendto(self, data, relay):
                self.sent.append((data, relay))

            def settimeout(self, timeout):
                _ = timeout

            def recvfrom(self, size):
                _ = size
                if not self.responses:
                    raise socket.timeout("timed out")
                return self.responses.pop(0), ("127.0.0.1", 0)

        target_host = "157.245.121.27"
        target_port = 7053
        expected = b"\x12\x34payload"
        stale = b"\x99\x99stale"
        stale_packet = b"\x00\x00\x00" + harness.encode_socks_addr(target_host) + target_port.to_bytes(2, "big") + stale
        good_packet = b"\x00\x00\x00" + harness.encode_socks_addr(target_host) + target_port.to_bytes(2, "big") + expected

        fake_udp = FakeUDPSocket([stale_packet, good_packet])
        reply = harness.socks5_udp_send_recv(
            fake_udp,
            relay=("127.0.0.1", 9999),
            target_host=target_host,
            target_port=target_port,
            payload=expected,
            validator=lambda payload: len(payload) >= 2 and payload[0:2] == expected[0:2],
            response_timeout=0.2,
            retries=1,
        )

        self.assertEqual(reply, expected)
        self.assertEqual(len(fake_udp.sent), 1)

    def test_build_impairment_schedule_handover(self):
        args = type(
            "Args",
            (),
            {
                "trace_profile_file": "",
                "trace_name": "",
                "handover_script": "default",
            },
        )()
        steps = harness.build_impairment_schedule("wifi", 30, args)
        self.assertGreater(len(steps), 1)
        self.assertAlmostEqual(sum(step.duration_s for step in steps), 30, places=2)
        self.assertTrue(all(step.profile in {"wifi", "lte", "5g"} for step in steps))

    def test_load_trace_steps_scales_duration(self):
        trace = {
            "steps": [
                {"duration_s": 2, "profile": "wifi"},
                {"duration_s": 1, "rate_mbit": 35, "ceil_mbit": 40, "latency_ms": 80, "jitter_ms": 20, "loss_pct": 1.2},
            ]
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            trace_path = pathlib.Path(tmp_dir) / "trace.json"
            trace_path.write_text(json.dumps(trace), encoding="utf-8")
            steps = harness.load_trace_steps(str(trace_path), "", 30, "lte")
        self.assertEqual(len(steps), 2)
        self.assertAlmostEqual(sum(step.duration_s for step in steps), 30, places=2)
        self.assertEqual(steps[0].profile, "wifi")
        self.assertIsNotNone(steps[1].custom)

    def test_ipv6_gap_reasons_disabled(self):
        reasons = harness.ipv6_gap_reasons(
            require_ipv6_data_plane=False,
            v6_host="2001:db8::10",
            traffic_hosts=["203.0.113.10", "2001:db8::10"],
            udp_hosts=["203.0.113.10"],
            dns_hosts=["203.0.113.10"],
            quic_hosts=["203.0.113.10"],
            http_hosts=["203.0.113.10"],
            realistic_enabled=True,
        )
        self.assertEqual(reasons, [])

    def test_ipv6_gap_reasons_detects_missing_lanes(self):
        reasons = harness.ipv6_gap_reasons(
            require_ipv6_data_plane=True,
            v6_host="2001:db8::10",
            traffic_hosts=["203.0.113.10", "2001:db8::10"],
            udp_hosts=["203.0.113.10"],
            dns_hosts=["203.0.113.10", "2001:db8::10"],
            quic_hosts=["203.0.113.10"],
            http_hosts=["203.0.113.10"],
            realistic_enabled=True,
        )
        self.assertEqual(
            reasons,
            ["ipv6_udp_unavailable", "ipv6_quic_unavailable", "ipv6_http_unavailable"],
        )

    def test_udp_workload_associate_failure_is_counted(self):
        original = harness.socks5_udp_associate
        try:
            def failing_associate(*_args, **_kwargs):
                raise ConnectionRefusedError("refused")

            harness.socks5_udp_associate = failing_associate
            ok, fail, _, errors = harness.run_udp_burst_workload(19090, "127.0.0.1", 7002, 0.5)
        finally:
            harness.socks5_udp_associate = original
        self.assertEqual(ok, 0)
        self.assertGreaterEqual(fail, 1)
        self.assertIn("conn_refused", errors)

    def test_direct_udp_probe_retries_before_failing(self):
        original_socket = harness.socket.socket

        class FakeSocket:
            def __init__(self, *_args, **_kwargs):
                self.calls = 0
                self._payload = b""

            def settimeout(self, _timeout):
                return None

            def sendto(self, payload, _addr):
                self._payload = payload

            def recvfrom(self, _size):
                self.calls += 1
                if self.calls < 3:
                    raise socket.timeout("timed out")
                return self._payload, ("127.0.0.1", 0)

            def close(self):
                return None

        try:
            harness.socket.socket = lambda *_args, **_kwargs: FakeSocket()
            ok = harness.direct_udp_echo_probe("127.0.0.1", 7002, payload=b"probe", timeout=0.3, attempts=3)
        finally:
            harness.socket.socket = original_socket
        self.assertTrue(ok)

    def test_memory_budget_monitor_detects_sustained_over_limit(self):
        mb = 1024 * 1024
        fake_control = self._FakeStatusControl([4 * mb, 7 * mb, 7 * mb, 7 * mb, 7 * mb])
        monitor = harness.MemoryBudgetMonitor(
            control=fake_control,
            limit_mb=5.0,
            grace_seconds=0.03,
            sample_interval_ms=10,
        )
        monitor.start()
        time.sleep(0.11)
        stats = monitor.stop()
        self.assertTrue(stats["enabled"])
        self.assertTrue(stats["limit_exceeded"])
        self.assertGreater(stats["peak_rss_mb"], 5.0)

    def test_memory_budget_monitor_ignores_short_spike(self):
        mb = 1024 * 1024
        fake_control = self._FakeStatusControl([4 * mb, 7 * mb, 4 * mb, 4 * mb, 4 * mb], socket_buffer_capped=True)
        monitor = harness.MemoryBudgetMonitor(
            control=fake_control,
            limit_mb=5.0,
            grace_seconds=0.08,
            sample_interval_ms=10,
        )
        monitor.start()
        time.sleep(0.08)
        stats = monitor.stop()
        self.assertTrue(stats["enabled"])
        self.assertFalse(stats["limit_exceeded"])
        self.assertTrue(stats["socket_buffer_capped"])


if __name__ == "__main__":
    unittest.main()
