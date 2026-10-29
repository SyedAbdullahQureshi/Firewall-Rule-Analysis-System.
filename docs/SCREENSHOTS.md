# Screenshots

All images in `docs/screenshots/` were captured from the running app
(`python -m firewall_rules.ui --host 0.0.0.0 --port 7860`) at 1440 px width,
full page, with an headless browser driving the real controls. Nothing is
mocked up.

## The three screens required for the submission

| # | File | Screen | What it must show |
|---|------|--------|-------------------|
| 1 | `01_empty_state.png` | **Empty state** | Grey *No policy loaded* badge, the whole page in its pre-load form, a disabled *Simulate packet* button with its helper line, and the "No analysis yet. Load a policy to begin." placeholder |
| 2 | `03_loaded_findings.png` | **Loaded with findings** | Green *Policy loaded: 14 rules* badge, the segmented control with counts (All findings (28) · Shadowed (3) · Redundant (3) · Conflicts (10) · Overlapping pairs (15)), category pills, and the policy table with ALLOW/DENY pills |
| 3 | `04_simulate_allow.png` | **Simulated packet result** | Green ALLOW badge, the *Rule 1* chip, the packet line and the plain-English explanation |

## Supporting captures

| # | File | Screen to capture | What it demonstrates |
|---|------|-------------------|----------------------|
| 4 | `02_validation_errors.png` | Upload + validation error state | Red *Validation errors: 8* badge and every problem listed by row number in monospace, with analysis and simulation correctly disabled |
| 5 | `05_simulate_deny.png` | Simulated packet — deny | DENY badge with *Rule 7*, showing deny-before-allow (rule 7 wins over rule 8) |
| 6 | `06_simulate_no_match.png` | Simulated packet — no match | Amber *NO MATCH — DEFAULT DENY* badge and "no rule matched" chip |
| 7 | `07_rule_explanation.png` | Policy explanation | Rule 3 in the quoted callout with the violet accent bar: shadowed by rule 1, and the conflicting overlap |
| 8 | `08_policy_table.png` | Step 4 policy table | Collapsible panel opened after a load, monospace scope columns, right-aligned rule numbers, ALLOW/DENY pills |

Reproduce with `python -m firewall_rules.ui --port 7860`, the example files in
`docs/examples/`, and the simulator presets in the *Example packet* dropdown.
