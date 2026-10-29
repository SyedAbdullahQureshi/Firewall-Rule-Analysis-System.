# Screenshots

All images in `docs/screenshots/` were captured from the running Gradio app
(`python -m firewall_rules.ui --host 0.0.0.0 --port 7860`) at 1440 px width,
full page, on the sample policy and the two example CSV files in
`docs/examples/`. Nothing in them is mocked up.

| # | File | Screen to capture | What it demonstrates |
|---|------|-------------------|----------------------|
| 1 | `01_app_overview_sample_policy.png` | App landing state with the built-in sample policy auto-loaded | Purpose banner ("audits policy files, does not enforce traffic"), the four sections, the analysis summary (14 rules · 15 overlaps · 3 shadowed · 3 redundant · 10 conflicts) and the full validated policy table |
| 2 | `02_simulate_allow_rule1.png` | Simulated packet result — allow | Packet `10.1.2.3:3306/tcp -> 10.9.9.5` matches rule 1, is allowed, 1 of 14 rules evaluated, and the explanation names rule 3 as shadowed for this packet |
| 3 | `03_simulate_default_deny.png` | Simulated packet result — no match | `8.8.8.8:5353/udp -> 1.1.1.1` matches no rule; the documented default action DENY is applied and stated explicitly |
| 4 | `04_simulate_deny_wins.png` | Simulated packet result — deny before allow | `203.0.113.10:443/tcp -> 198.51.100.10` is denied by rule 7 before rule 8 can allow it |
| 5 | `05_simulate_invalid_input.png` | Simulator input validation | A CIDR (`10.0.0.0/8`) typed as a source IP and port `70000` are rejected with readable messages, not a traceback |
| 6 | `06_analysis_conflicts.png` | Overlap/shadowing table filtered to Conflicts | 10 conflicting pairs, each with the winner and why, plus a "confirm the order" review action |
| 7 | `07_analysis_shadowed.png` | Overlap/shadowing table filtered to Shadowed rules | Rules 3, 4 and 11 flagged as fully shadowed by rule 1 with "Remove rule N, it is fully shadowed by rule 1" |
| 8 | `08_rule_explanation.png` | Policy explanation | Rule 3 explained in plain English: position, shadowing by rule 1, and the conflicting overlap with rule 1 |
| 9 | `09_valid_custom_upload.png` | Successful upload of a user CSV | `valid_custom_policy.csv` accepted (5 rules) and re-analysed: 1 overlap, 1 redundant duplicate |
| 10 | `10_validation_errors.png` | Validation error state | `invalid_policy.csv` rejected with all 8 problems listed by row: bad CIDRs, port 70000, inverted range, bad protocol, bad action, duplicate order |

Reproduce them with `python -m firewall_rules.ui --port 7860` and the example
files in `docs/examples/`. The screenshots script used for this submission was
a headless-browser driver and is not part of the deliverable; the app itself is
the artefact.
