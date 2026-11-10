import unittest

from src.analyzer import analyze_flows


class AnalyzeFlowsTests(unittest.TestCase):
    def test_flags_high_outbound_volume(self):
        rows = [{
            "timestamp": "2026-10-01T09:00:00Z",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "dst_port": "443",
            "protocol": "tcp",
            "bytes_out": "1500001",
        }]
        alerts = analyze_flows(rows)
        self.assertEqual(len(alerts), 1)
        self.assertIn("exceed threshold", alerts[0]["reason"])

    def test_flags_watchlist_port(self):
        rows = [{
            "timestamp": "2026-10-01T09:00:00Z",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "dst_port": "23",
            "protocol": "tcp",
            "bytes_out": "100",
        }]
        alerts = analyze_flows(rows)
        self.assertEqual(len(alerts), 1)
        self.assertIn("on the watchlist", alerts[0]["reason"])

    def test_does_not_flag_normal_single_flow(self):
        rows = [{
            "timestamp": "2026-10-01T09:00:00Z",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "dst_port": "443",
            "protocol": "tcp",
            "bytes_out": "100",
        }]
        self.assertEqual(analyze_flows(rows), [])

    def test_rejects_invalid_numeric_field(self):
        rows = [{
            "timestamp": "2026-10-01T09:00:00Z",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "dst_port": "443",
            "protocol": "tcp",
            "bytes_out": "not-a-number",
        }]
        with self.assertRaises(ValueError):
            analyze_flows(rows)


if __name__ == "__main__":
    unittest.main()
