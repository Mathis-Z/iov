# Documentation

Supplementary material for the paper: the architecture diagram, the full table of evaluated CVEs and a dashboard demo.

| Path | Contents |
|---|---|
| [`architecture.pdf`](architecture.pdf) / [`architecture.png`](architecture.png) | Architecture of the IoV system: IoV server ([`iov_server/`](../iov_server)), IoV evaluator and agent daemon ([`iov-evaluation/`](../iov-evaluation)), and the Wazuh integration ([`wazuh-integration/`](../wazuh-integration)). |
| [`cve_table.pdf`](cve_table.pdf) / [`cve_table.png`](cve_table.png) | All 66 CVEs of the evaluation: CVE set (S1–S5), reference assessment (vulnerable or not), Wazuh's finding (• reported, – not reported) and the level the IoV reported (✓ correct, × incorrect, ○ no statement). |
| [`dashboard_demo.mp4`](dashboard_demo.mp4) | Screen recording of the Wazuh dashboard demo with IoV verdicts. |

The IoVs generated for the 66 evaluated CVEs are in [`iov_server/iov_data/`](../iov_server/iov_data).
