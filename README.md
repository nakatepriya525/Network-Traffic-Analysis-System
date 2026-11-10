# Network Traffic Analysis & Threat Detection Lab

<p align="center">
  <strong>Entry-Level SOC Analyst Portfolio Project</strong><br/>
  A defensive, evidence-led lab for inspecting network-flow records, identifying suspicious patterns, and documenting investigation decisions.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="Security" src="https://img.shields.io/badge/Focus-SOC%20%7C%20Blue%20Team-0A7E5A">
  <img alt="Status" src="https://img.shields.io/badge/Status-Starter%20Lab-orange">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-blue">
</p>

## Project overview

This repository is a small, reproducible blue-team lab designed to demonstrate the investigation workflow expected of a junior SOC analyst:

1. Load network-flow records from a CSV file.
2. Validate and normalize fields.
3. Apply transparent, explainable detection rules.
4. Produce alert records with reasons and supporting evidence.
5. Document triage decisions and limitations.

**Important:** This is a learning project, not an enterprise SIEM, production IDS, or proof of real-world incident response experience. The included data is synthetic and the thresholds are illustrative.

## What is included

| Component | Purpose |
|---|---|
| `src/analyzer.py` | CSV validation and rule-based flow analysis |
| `sample_data/network_flows.csv` | Small synthetic dataset for repeatable testing |
| `rules/detection_rules.md` | Rule logic, rationale, and tuning caveats |
| `tests/test_analyzer.py` | Unit tests for core detection behavior |
| `docs/incident-report-template.md` | Structured investigation write-up template |
| `docs/lab-safety.md` | Scope, safety, and data-handling boundaries |

## Quick start

Requires Python 3.10 or newer. The starter implementation uses only the Python standard library.

```bash
git clone https://github.com/nakatepriya525/Network-Traffic-Analysis-System.git
cd Network-Traffic-Analysis-System
python src/analyzer.py --input sample_data/network_flows.csv --output reports/alerts.csv
python -m unittest discover -s tests -v
```

On Windows PowerShell, use `py` instead of `python` if that is how Python is configured on your machine.

## Detection logic

The starter rules flag:
- unusually high outbound byte volume for a single flow;
- connections to destination ports listed in a configurable watchlist;
- repeated connections from the same source to the same destination in the sample window.

These are **investigation leads**, not verdicts. A flag can be benign. Validate asset role, business context, baseline behavior, time window, and corroborating telemetry before assigning severity.

See [Detection rules](rules/detection_rules.md).

## Example workflow

```text
CSV flow records
      |
      v
Input validation
      |
      v
Rule evaluation
      |
      v
Alert CSV + evidence/reason
      |
      v
Analyst triage and incident notes
```

## Analyst evidence checklist

For every investigation, record:
- alert/rule identifier and timestamp;
- source and destination context;
- observed values and threshold;
- why the event was flagged;
- benign explanations considered;
- additional evidence required;
- disposition and confidence;
- remediation or escalation recommendation.

Do not claim a detection is effective until it has been tested against both positive and benign examples. Do not claim a tool integration, live packet capture, dashboard, or SIEM deployment unless you have implemented and evidenced it.

## Roadmap

- [x] Reproducible synthetic flow dataset
- [x] Explainable baseline rules
- [x] CSV analyzer and unit tests
- [x] Incident report template and lab safety notes
- [ ] Add PCAP ingestion using a documented parser
- [ ] Add Sigma-style rule examples and mapped ATT&CK techniques
- [ ] Add benign/positive test corpus and false-positive analysis
- [ ] Add screenshots of actual test runs and sample output
- [ ] Add CI workflow after local tests pass

## Portfolio positioning

This project is intended to demonstrate foundational skills relevant to junior SOC work: Python scripting, structured-data validation, network telemetry interpretation, rule-based triage, testing, and clear incident documentation.

It does not represent professional SOC employment or production security operations.

## Author

**Priya Nakate**  
Mumbai, Maharashtra, India  
[LinkedIn](https://www.linkedin.com/in/priyanakate25/) · [GitHub](https://github.com/nakatepriya525)

## License

MIT. See [LICENSE](LICENSE).
