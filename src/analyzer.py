"""Analyze synthetic network-flow CSV records with transparent starter rules.

This is a learning tool. It does not inspect live traffic or make definitive
malware/compromise judgments.
"""
from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Iterable

REQUIRED_FIELDS = {
    "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes_out"
}
WATCHLIST_PORTS = {23, 2323, 4444, 5555}


def load_flows(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = REQUIRED_FIELDS - fields
        if missing:
            raise ValueError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
        return list(reader)


def analyze_flows(
    rows: Iterable[dict[str, str]],
    outbound_byte_threshold: int = 1_000_000,
    watchlist_ports: set[int] | None = None,
    repeat_threshold: int = 3,
) -> list[dict[str, str]]:
    """Return one alert per flagged flow, including an explainable reason."""
    ports = WATCHLIST_PORTS if watchlist_ports is None else watchlist_ports
    records = list(rows)
    pair_counts = Counter(
        (row.get("src_ip", "").strip(), row.get("dst_ip", "").strip())
        for row in records
    )
    alerts: list[dict[str, str]] = []

    for row_number, row in enumerate(records, start=2):
        try:
            destination_port = int(row.get("dst_port", ""))
            bytes_out = int(row.get("bytes_out", ""))
        except (TypeError, ValueError):
            raise ValueError(f"Invalid numeric value in CSV row {row_number}")

        source = row.get("src_ip", "").strip()
        destination = row.get("dst_ip", "").strip()
        reasons: list[str] = []

        if bytes_out > outbound_byte_threshold:
            reasons.append(
                f"Outbound bytes {bytes_out} exceed threshold {outbound_byte_threshold}"
            )
        if destination_port in ports:
            reasons.append(f"Destination port {destination_port} is on the watchlist")
        if pair_counts[(source, destination)] >= repeat_threshold:
            reasons.append(
                f"Source-destination pair appears {pair_counts[(source, destination)]} times"
            )

        if reasons:
            alerts.append({
                "timestamp": row.get("timestamp", ""),
                "src_ip": source,
                "dst_ip": destination,
                "dst_port": str(destination_port),
                "protocol": row.get("protocol", "").strip().upper(),
                "bytes_out": str(bytes_out),
                "reason": "; ".join(reasons),
                "source_row": str(row_number),
            })
    return alerts


def write_alerts(alerts: list[dict[str, str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "timestamp", "src_ip", "dst_ip", "dst_port",
        "protocol", "bytes_out", "reason", "source_row"
    ]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze network-flow CSV records.")
    parser.add_argument("--input", required=True, type=Path, help="Input flow CSV")
    parser.add_argument("--output", required=True, type=Path, help="Output alert CSV")
    parser.add_argument(
        "--byte-threshold", type=int, default=1_000_000,
        help="Flag flows with bytes_out greater than this value (default: 1000000)"
    )
    args = parser.parse_args()

    flows = load_flows(args.input)
    alerts = analyze_flows(flows, outbound_byte_threshold=args.byte_threshold)
    write_alerts(alerts, args.output)
    print(f"Analyzed {len(flows)} flow records; wrote {len(alerts)} alerts to {args.output}")


if __name__ == "__main__":
    main()
