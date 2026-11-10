# Detection rules

All rules below are deliberately simple starter heuristics. They are designed to create investigation leads from the synthetic CSV dataset, not to identify attackers conclusively.

## NTA-001 — High outbound byte volume

- **Logic:** `bytes_out > 1,000,000` by default.
- **Why investigate:** A large outbound transfer may deserve review when it is unexpected for the host, destination, or time of day.
- **False-positive examples:** backups, software distribution, cloud synchronization, approved data exports.
- **Triage:** identify the asset owner and role; compare with normal traffic; inspect destination reputation using approved sources; correlate with proxy, DNS, endpoint, and authentication logs.
- **Tuning:** establish a baseline by host/role and time window before changing the threshold.

## NTA-002 — Destination port watchlist

- **Logic:** destination port is one of 23, 2323, 4444, or 5555.
- **Why investigate:** These ports can appear in remote-access, legacy, or unusual service activity.
- **False-positive examples:** authorized lab services, internal testing, approved legacy systems.
- **Triage:** confirm the service, destination ownership, network zone, and whether the connection is expected.
- **Caution:** a port number alone is not an indicator of compromise.

## NTA-003 — Repeated source-destination pair

- **Logic:** the same source/destination pair appears at least three times in the supplied CSV window.
- **Why investigate:** repeated connections can be relevant when investigating retries, beacon-like patterns, or scanning hypotheses.
- **False-positive examples:** normal polling, health checks, application retries, browser sessions.
- **Triage:** inspect timestamps and intervals, destination service, process telemetry, and expected application behavior.
- **Caution:** this starter rule counts records, not unique sessions or time-normalized connection rates.

## Severity and disposition

The starter script does not automatically assign severity. Analysts should consider asset criticality, exposure, event frequency, corroborating evidence, and business context. Use dispositions such as:

- **Benign / Expected** — supported by owner or baseline evidence.
- **Needs Monitoring** — unusual but insufficient evidence for escalation.
- **Escalate for Investigation** — multiple corroborating signals or meaningful business risk.
- **Insufficient Data** — required context or telemetry is unavailable.

Record evidence and reasoning for every disposition.
