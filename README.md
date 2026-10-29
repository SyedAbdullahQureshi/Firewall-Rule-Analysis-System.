# Firewall Rule Analysis System

An auditor for **ordered firewall policy files**. It reads a CSV of rules,
validates every field, and reports shadowed, redundant, conflicting and
overlapping rules, plus a first-match simulation of any packet you describe.

> **It audits policy files. It does not enforce real network traffic** — no
> packet capture, no firewall API, no iptables/nftables, no live traffic. The
> only input is a policy file; the only output is a report.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m unittest discover -s tests -v     # 18 acceptance tests
python -m firewall_rules.ui --port 7860     # launch the app
```

Or open `Firewall_Rule_Analysis_System.ipynb` and choose **Restart & Run All** —
it validates the sample policy, runs the analysis, launches nothing, renders
the screenshots and executes the acceptance tests end to end.

## Policy CSV format

The header must be exactly, in this order:

```csv
order,source,destination,port,protocol,action
1,10.0.0.0/8,0.0.0.0/0,any,any,allow
2,0.0.0.0/0,0.0.0.0/0,22,tcp,deny
```

| Column | Values |
|--------|--------|
| `order` | integer, unique; rules are evaluated in ascending order |
| `source`, `destination` | IPv4 CIDR, e.g. `10.0.0.0/8`, `0.0.0.0/0` |
| `port` | a port (`443`), an inclusive range (`1000-2000`), or `any` |
| `protocol` | `tcp`, `udp`, `icmp`, `any` |
| `action` | `allow`, `deny` |

## Semantics (documented assumptions)

IPv4 only · single interface · no stateful connection tracking · no NAT · no
time-based rules · one ordered list · **first match wins** · **default action
DENY** when nothing matches. See `docs/LIMITATIONS.md` for the full list.

## Layout

```
Firewall_Rule_Analysis_System.ipynb   the deliverable notebook (phases 1-4 + docs)
sample_policy.csv                     the 14-rule demo policy
firewall_rules/
    validation.py    CSV loading + field validation (Phase 1)
    engine.py        matching, overlap/shadow/redundancy/conflict analysis (Phase 2)
    ui.py            Gradio app that only renders engine output (Phase 3)
    sample_policy.py the built-in policy and example packets
    test_report.py   runs the acceptance suite and builds the test-case table
tests/test_acceptance.py              18 unittest acceptance tests (Phase 4)
docs/
    ARCHITECTURE.md       data flow and design decisions
    LIMITATIONS.md        what the simplified semantics ignore
    SCREENSHOTS.md        the ten captured screens
    screenshots/          PNG captures of the running app
    examples/             valid and invalid CSVs used for the captures
    TEST_CASES.md         generated test-case table
    SUBMISSION_CHECKLIST.md
tests/                                18 unittest acceptance tests (Phase 4)
tools/build_notebook.py               regenerates + re-executes the notebook
```

The notebook is generated from the library sources and the markdown in
`docs/`, so it cannot drift from the code:

```bash
python tools/build_notebook.py --execute   # rebuild and run every cell
```

## Programmatic use

```python
from firewall_rules import load_and_validate, analyse_policy, match_packet

result = load_and_validate("sample_policy.csv")
print(result.errors)                      # [] when valid

analysis = analyse_policy(result.policy)
print(analysis.summary())                 # counts per finding type
print(analysis.findings_frame())          # Category | Rules | Explanation | Suggested review action

decision = match_packet(result.policy, {
    "source": "10.1.2.3", "destination": "10.9.9.5",
    "port": "3306", "protocol": "tcp",
})
print(decision.action, decision.explanation)
```
