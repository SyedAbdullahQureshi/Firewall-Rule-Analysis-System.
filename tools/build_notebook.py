"""Assemble ``Firewall_Rule_Analysis_System.ipynb`` from the library sources.

Why generate the notebook instead of hand-editing JSON? The documentation
sections are the same markdown as ``docs/*.md`` and the test-case table is
produced by running the real acceptance suite, so a regenerated notebook can
never drift from the code or the docs.

Usage::

    python tools/build_notebook.py            # write the .ipynb
    python tools/build_notebook.py --execute  # write it and run every cell
"""

from __future__ import annotations

import argparse
import os
import sys

import nbformat as nbf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOTEBOOK = os.path.join(ROOT, "Firewall_Rule_Analysis_System.ipynb")


def md(text: str) -> nbf.NotebookNode:
    return nbf.v4.new_markdown_cell(text.strip("\n"))


def code(text: str) -> nbf.NotebookNode:
    return nbf.v4.new_code_cell(text.strip("\n"))


def read_doc(name: str) -> str:
    with open(os.path.join(ROOT, "docs", name), "r", encoding="utf-8") as handle:
        return handle.read().strip()


TITLE = """
# Firewall Rule Analysis System

**An auditor for ordered firewall policy files.**

This notebook is the complete, rerunnable artefact for the project: it builds
the sample policy, validates it, runs the analysis engine, launches the Gradio
app, executes the acceptance tests and carries the written documentation.

> **Scope.** The system audits a policy *file*. It does not enforce real network
> traffic: there is no packet capture, no firewall API, no iptables/nftables
> interaction and no live traffic. Input is a CSV; output is a report about that
> CSV.

**Run it:** *Kernel → Restart & Run All.* Every cell is deterministic and
offline; nothing needs to be uploaded by hand and no server is left running.

## Contents

| Section | Covers |
|---|---|
| [1 · Sample policy and validation](#1) | CSV contract, the 14-rule sample policy, validation rules and the error report |
| [2 · Analysis engine](#2) | first-match simulation, overlap, shadowing, redundancy, conflicts, explanations |
| [3 · Gradio interface](#3) | the app, the five sections and how to launch it |
| [4 · Acceptance tests](#4) | 18 automated tests and the generated test-case table |
| [5 · Limitations](#5) | exactly what the simplified semantics ignore |
| [6 · Architecture](#6) | data flow and design decisions |
| [7 · Screenshots](#7) | the ten captured screens |
| [8 · Submission checklist](#8) | deliverables and environment |
| [9 · Final check](#9) | the top-to-bottom verification, asserted in one cell |
"""

SETUP = """
# ── Environment ───────────────────────────────────────────────────────────────
# The analysis lives in the `firewall_rules` package so that the notebook, the
# Gradio app and the test suite all run the same code (no duplicated logic).
import os
import sys
import pathlib

ROOT = pathlib.Path.cwd()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import warnings

warnings.filterwarnings("ignore", message=".*IProgress not found.*")   # ipywidgets/tqdm noise
warnings.filterwarnings("ignore", category=DeprecationWarning)

import pandas as pd
from IPython.display import HTML, display

pd.set_option("display.width", 200)
pd.set_option("display.max_colwidth", 95)
pd.set_option("display.max_rows", 60)

print("python :", sys.version.split()[0])
print("pandas :", pd.__version__)
print("project:", ROOT.name)
"""

PHASE1_INTRO = """
<a id="1"></a>
## 1 · Sample policy and validation

### 1.1 The CSV contract

A policy file is a CSV whose header is exactly, **in this order**:

```csv
order,source,destination,port,protocol,action
```

| Column | Type | Accepted values | Why it exists |
|---|---|---|---|
| `order` | integer | unique whole numbers | Evaluation position. Rules are walked top to bottom in ascending `order`; the file's line order is irrelevant after validation. |
| `source` | IPv4 CIDR | `10.0.0.0/8`, `203.0.113.45/32`, `0.0.0.0/0` | The packet's source address must fall inside this range. |
| `destination` | IPv4 CIDR | as above | The packet's destination address must fall inside this range. |
| `port` | port spec | `443`, `1000-2000` (inclusive), or `any` | Destination port scope. |
| `protocol` | keyword | `tcp`, `udp`, `icmp`, `any` | `any` matches every protocol. |
| `action` | keyword | `allow`, `deny` | What happens to a packet that matches. |

Values are trimmed and compared case-insensitively (`TCP` and `Allow` are
accepted), CIDRs are canonicalised, and host bits are masked off with a warning
(`10.1.2.3/8` becomes `10.0.0.0/8`).

### 1.2 The sample policy

Fourteen rules that are deliberately *messy in the interesting ways* while
still being individually well-formed. `validation` rejects malformed files, not
sloppy ones — the engine is what finds the sloppiness.
"""

SAMPLE_CELL = """
# Writes sample_policy.csv to the project root and shows it exactly as a firewall
# engineer would see it in a text editor.
from firewall_rules.sample_policy import write_sample_policy

path = write_sample_policy("sample_policy.csv")
print(f"sample policy written to: {path}\\n")
print(pathlib.Path(path).read_text(encoding="utf-8"))
"""

SAMPLE_INTENT = """
| Rule | Intent |
|---|---|
| 1 | Broad allow: `10.0.0.0/8` → any, any port, any protocol |
| 2 | Wildcard deny of TCP/22 from anywhere, placed *after* rule 1 |
| 3 | Narrow rule fully shadowed by rule 1 (never evaluated) |
| 4 | Port-range rule, also fully shadowed by rule 1 (and redundant with it) |
| 5 | `/32` → `/32` allow on 8443, narrower than rule 6 |
| 6 | Overlapping **deny placed after** the allow in rule 5 → allow-before-deny |
| 7 | Overlapping **deny placed before** the allow in rule 8 → deny-before-allow |
| 8 | Broad destination allow that rule 7 overrides for TCP/443 |
| 9 | Wildcard ICMP deny covering every address |
| 10 | Exact duplicate of rule 9 → redundant |
| 11 | Narrow allow shadowed by rule 1 and redundant with it |
| 12 | Wide rule with a low-port range that rule 2 cuts into |
| 13 | Wildcard-port UDP allow, host direction reversed |
| 14 | Cross-direction wildcard allow for a private range |

Broad rules (`0.0.0.0/0`, `any`), narrow rules (`/32`), wildcards, a fully
shadowed rule, a duplicate, both orderings of an allow/deny conflict — all
present, as the brief requires.
"""

VALIDATE_CELL = """
# Loading and validation are two separate, individually testable functions:
#   load_policy(source)        -> I/O only  (path | bytes | text | file object)
#   validate_policy(dataframe) -> semantics only, returns errors instead of raising
from firewall_rules.validation import load_and_validate, load_policy, validate_policy

loaded = load_policy("sample_policy.csv")
print("load_policy    ->", type(loaded.dataframe).__name__, loaded.dataframe.shape,
      "| encoding:", loaded.encoding)

result = load_and_validate("sample_policy.csv")
print("valid          ->", result.ok)
print("errors         ->", result.errors)
print("warnings       ->", result.warnings)
print()
display(result.policy)
"""

SOURCE_VIEW = """
# The implementation lives in importable modules (so the UI and the tests reuse
# it). Expand either block to read the code inline without leaving the notebook.
import html
import importlib
import inspect

def show_source(module_name, summary):
    module = importlib.import_module(module_name)
    source = inspect.getsource(module)
    display(HTML(
        f"<details><summary><b>{summary}</b> "
        f"({len(source.splitlines())} lines, {module_name}.py)</summary>"
        f"<pre style='max-height:420px;overflow:auto;background:#f6f8fa;"
        f"padding:12px;border-radius:6px;font-size:12px;line-height:1.45'>"
        f"{html.escape(source)}</pre></details>"
    ))

show_source("firewall_rules.validation", "firewall_rules/validation.py — loading + validation")
show_source("firewall_rules.sample_policy", "firewall_rules/sample_policy.py — built-in policy")
"""

BAD_CELL = """
# Bad data never raises: every problem is returned as one string, prefixed with
# the CSV line number (line 1 is the header, so row index 0 is "row 2").
import pandas as pd
from firewall_rules.validation import POLICY_COLUMNS, validate_policy

broken = pd.DataFrame(
    [
        ("1", "10.0.0.0/8",  "0.0.0.0/0", "443",       "tcp",  "allow"),
        ("2", "10.0.0.0/33", "0.0.0.0/0", "443",       "tcp",  "allow"),   # prefix too long
        ("3", "256.1.1.1/24","0.0.0.0/0", "443",       "tcp",  "allow"),   # octet out of range
        ("4", "abc",         "0.0.0.0/0", "443",       "tcp",  "allow"),   # not an address
        ("5", "10.5.0.0/16", "10.6.0.0/16", "70000",   "tcp",  "allow"),   # port out of range
        ("6", "10.5.0.0/16", "10.6.0.0/16", "2000-1000","tcp", "allow"),   # inverted range
        ("7", "10.5.0.0/16", "10.6.0.0/16", "80",      "sctp", "allow"),   # bad protocol
        ("8", "10.5.0.0/16", "10.6.0.0/16", "80",      "tcp",  "permit"),  # bad action
        ("5", "10.7.0.0/16", "10.8.0.0/16", "any",     "udp",  "deny"),    # duplicate order
        ("nine", "10.9.0.0/16", "0.0.0.0/0", "any",    "any",  "allow"),   # non-integer order
    ],
    columns=list(POLICY_COLUMNS),
)

rejected = validate_policy(broken)
print(f"valid: {rejected.ok}   errors: {len(rejected.errors)}\\n")
for error in rejected.errors:
    print(" •", error)

print("\\nThe same behaviour on a real file (docs/examples/invalid_policy.csv):")
file_result = load_and_validate("docs/examples/invalid_policy.csv")
print(f"valid: {file_result.ok}   errors: {len(file_result.errors)}")
"""

VALIDATION_RULES = """
### 1.3 What each validation rule rejects, and why

| # | Check | Rejected example | Message shape | Rationale |
|---|---|---|---|---|
| 1 | **Header** — all six columns present, in order | header missing `action` | `missing required column(s): action; expected the header 'order,source,...'` | A missing column would silently make every rule ambiguous. Extra columns are only a warning, so a `comment` column does not block an audit. |
| 2 | **File shape** — not empty, not binary, not Excel, comma-separated | `b""`, `PK\\x03\\x04…`, a `.txt` note | `… is empty`, `… looks like an Excel .xlsx workbook`, `… is not a text CSV (it contains NUL bytes)` | Real uploads fail in these four ways; each gets its own sentence instead of a pandas traceback. Decoding tries UTF-8-BOM, UTF-8, cp1252, latin-1 and warns when a fallback was used. |
| 3 | **`order` is an integer** | `two`, `3.5`, empty | `row 4: order 'two' is not an integer; expected a whole number such as 1` | Rule position must be unambiguous; `"3"` and `3` are both accepted. |
| 4 | **`order` is unique** | two rows with `order = 1` | `rows 2, 3: duplicate order value 1; every rule needs a unique order` | Two rules cannot occupy the same position in a first-match list. All offending lines are named in one message. |
| 5 | **`source` / `destination` are valid IPv4 CIDR** | `10.0.0.0/33`, `256.1.1.1/24`, `abc` | `row 2: source: '10.0.0.0/33' is not a valid IPv4 CIDR (…)` | Parsed with `ipaddress.ip_network(strict=False)`. Prefix length, octet range and syntax are all covered by one parser, so validation and matching can never disagree. IPv6 is rejected explicitly (`looks like IPv6`) rather than skipped. |
| 6 | **`port` is `any`, a single port, or a range** | `abc`, `80-`, `1000-2000-3000` | `row 3: port: 'abc' is not a valid port; use an integer 0-65535, a range such as 1000-2000, or 'any'` | En-dashes are normalised to hyphens so spreadsheet autocorrect does not produce a confusing failure. |
| 7 | **`port` bounds are inside 0-65535** | `70000`, `-1` | `row 6: port: port 70000 is outside the valid range 0-65535` | Ports are 16-bit; a wider value cannot exist on the wire. |
| 8 | **`port` range is ordered** | `2000-1000` | `row 7: port: port range '2000-1000' is inverted (start 2000 > end 1000)` | An inverted range matches nothing, which silently weakens a policy. |
| 9 | **`protocol` is one of four values** | `sctp`, `TCP/IP` | `row 8: protocol: 'sctp' is not an allowed protocol; expected one of tcp, udp, icmp, any` | The engine matches protocols by equality; an unknown keyword would never match a packet. |
| 10 | **`action` is allow or deny** | `permit`, `drop` | `row 9: action: 'permit' is not an allowed action; expected one of allow, deny` | `permit`/`drop` are vendor words; normalising them silently would hide a translation bug. |
| 11 | **Row-level atomicity** | a row with two bad fields | both messages, both prefixed with the same row number | A row is accepted only if all six fields pass, so the engine never sees a half-valid rule. All errors are reported at once — you fix one file, not one error. |
| 12 | **Ordering sanity** (warning, not an error) | rows written 3, 1, 2 | `rows are not in ascending order; rules will be evaluated by the 'order' column…` | A spreadsheet sort is a common accident. Evaluation always sorts by `order`, so this is a reassurance, not a rejection. |
| 13 | **Canonical CIDR** (warning, not an error) | `10.1.2.3/8` | `row 2: source '10.1.2.3/8' was normalised to '10.0.0.0/8' (host bits are masked off)` | Masking is what a device does; the warning makes it visible instead of surprising. |
"""

PHASE2_INTRO = """
<a id="2"></a>
## 2 · Analysis engine

### 2.1 Simplified semantics — every assumption

The engine models a **static, ordered, single-device IPv4 packet filter**:

1. **First match wins.** Rules are evaluated in ascending `order`; the first rule
   whose source, destination, port and protocol all match decides the packet.
   Nothing after it is considered.
2. **Default action = DENY.** If no rule matches, the packet is denied. This is
   the module constant `DEFAULT_ACTION`; it is repeated in every explanation that
   uses it so the assumption is never hidden. Default-deny is chosen because a
   silent allow is the wrong failure mode for an audit tool.
3. **Single interface.** No zones, interfaces, directions or VRFs — a rule is a
   filter on a 4-tuple, not on a path.
4. **No connection tracking.** No `established`/`related`; return traffic needs
   its own rule; every packet is evaluated as if it were the first of a flow.
5. **No NAT.** Addresses are compared exactly as written.
6. **No time-based rules.** No schedules, rate limits, quotas or counters.
7. **IPv4 only.**
8. **A port dimension applies to every protocol.** ICMP has no ports, so rules
   with `protocol=icmp` should use `port=any` (all sample ICMP rules do).
9. **Rules are independent.** No groups, negation, inheritance or vendor objects.
10. **Ordering is explicit.** The `order` integer decides; file position does not.
11. **Redundancy is single-rule.** A rule is redundant only when one earlier rule
    alone covers it; union-cover is not detected.
12. **Audit only.** The engine reads a policy and reports on it. It never
    programs a firewall and never sees traffic.

All twelve are also written into the `firewall_rules.engine` module docstring.
"""

MATCH_CELL = """
# ── 2.2 First-match packet simulation ─────────────────────────────────────────
from firewall_rules.engine import DEFAULT_ACTION, match_packet
from firewall_rules.sample_policy import SAMPLE_PACKETS

print(f"Default action when nothing matches: {DEFAULT_ACTION.upper()} "
      f"(engine.DEFAULT_ACTION)\\n")

rows = []
for preset in SAMPLE_PACKETS:
    decision = match_packet(
        result.policy,
        {
            "source": preset["source"],
            "destination": preset["destination"],
            "port": preset["port"],
            "protocol": preset["protocol"],
        },
    )
    rows.append(
        {
            "example": preset["label"],
            "packet": decision.packet.label(),
            "matched rule": "-" if decision.rule is None else decision.rule.order,
            "action": decision.action,
            "default?": decision.is_default,
            "rules evaluated": decision.rules_evaluated,
        }
    )

print(pd.DataFrame(rows).to_string(index=False))

print("Full plain-English explanations")
print("=" * 90)
for preset in SAMPLE_PACKETS:
    decision = match_packet(
        result.policy,
        {"source": preset["source"], "destination": preset["destination"],
         "port": preset["port"], "protocol": preset["protocol"]},
    )
    print(f"\\n• {preset['label']}")
    print(f"  {decision.explanation}")
"""

ANALYSIS_CELL = """
# ── 2.3 Overlap, shadowing, redundancy and conflicts ─────────────────────────
# analyse_policy() compiles the policy once and runs all four detectors.
from firewall_rules.engine import analyse_policy

analysis = analyse_policy(result.policy)
print("counts:", analysis.summary(), "\\n")

print("OVERLAPPING PAIRS (source, destination, port and protocol all intersect)")
for overlap in analysis.overlaps:
    print(f"  rules {overlap.a.order:>2} / {overlap.b.order:<2} "
          f"({overlap.a.action}/{overlap.b.action})  "
          f"{'same action' if overlap.same_action else 'DIFFERENT actions'}")

print("\\nSHADOWED RULES (can never be the first match)")
for item in analysis.shadowed:
    shadowers = ", ".join(str(rule.order) for rule in item.shadowed_by)
    print(f"  rule {item.rule.order:>2} shadowed by rule {shadowers}")
    print(f"       {item.explanation()}")

print("\\nREDUNDANT RULES (removal would not change any packet outcome)")
for item in analysis.redundant:
    print(f"  rule {item.rule.order:>2} ({item.kind}) "
          f"redundant with rule {', '.join(str(r.order) for r in item.redundant_with)}")

print("\\nCONFLICTS (overlapping rules with different actions)")
for conflict in analysis.conflicts:
    print(f"  rule {conflict.winner.order:>2} ({conflict.winner.action}) beats "
          f"rule {conflict.loser.order:>2} ({conflict.loser.action})")
"""

FINDINGS_CELL = """
# The same findings shaped for the UI: one row per issue, with a suggested
# review action an analyst can act on.
findings = analysis.findings_frame()
print(f"{len(findings)} findings\\n")
display(findings.head(10))
print("\\nCategory counts:")
print(findings["Category"].value_counts().to_string())
"""

EXPLAIN_CELL = """
# ── 2.4 Plain-English policy explanation ─────────────────────────────────────
from firewall_rules.engine import explain_policy, explain_rule

print(explain_policy(result.policy), "\\n")
print("=" * 90)

for order in (1, 3, 5, 10):
    print(f"\\n{explain_rule(result.policy, order)}")

print("\\n" + "=" * 90)
print("\\nWhy rule 7 wins over rule 8 for 203.0.113.10:443/tcp -> 198.51.100.10:")
decision = match_packet(result.policy, {"source": "203.0.113.10",
                                        "destination": "198.51.100.10",
                                        "port": "443", "protocol": "tcp"})
print(" ", decision.explanation)
"""

PHASE3_INTRO = """
<a id="3"></a>
## 3 · Gradio interface

The app is a renderer: every control calls a function from phases 1 and 2 and
formats the result. It contains no CIDR arithmetic, no port parsing and no
notion of shadowing, so there is exactly one implementation of the semantics.

| Section | Control | Calls |
|---|---|---|
| 1 · Upload | `Validate uploaded CSV`, `Load built-in sample policy` | `load_and_validate` → `analyse_policy` |
| 2 · Simulate | IP / port / protocol inputs, `Simulate packet`, example presets | `match_packet` (+ `parse_packet` for input validation) |
| 3 · Analysis | category filter, findings table | `analyse_policy(...).findings_frame()` |
| 4 · Policy | the validated policy table | the validated DataFrame |
| 5 · Explain | rule dropdown, `Explain rule` | `explain_rule` |

**Robustness:** empty files, Excel workbooks, binary uploads, wrong encodings,
missing columns and non-CSV text all produce a message in the error panel. An
invalid packet input produces a message, not a traceback.

### Launching

From a terminal (recommended):

```bash
python -m firewall_rules.ui --host 0.0.0.0 --port 7860
# then open http://localhost:7860
```

From this notebook, run the cell below with `LAUNCH = True` (it blocks, which is
why it is off during *Restart & Run All*). Use `inline=True` to render the app
inside the notebook, or `share=True` for a temporary public link.
"""

LAUNCH_CELL = """
# ── 3.1 Build the app (no server started) ────────────────────────────────────
from firewall_rules.ui import build_app, launch_app

demo = build_app()
print("Gradio app built:", type(demo).__name__)

INSTRUCTIONS = '''
Launch it in either of these ways:

  1. Terminal (recommended)
         python -m firewall_rules.ui --host 0.0.0.0 --port 7860
     then open http://localhost:7860

  2. From this notebook - set LAUNCH = True below
         demo.launch(server_name="0.0.0.0", server_port=7860, inline=True)
     "inline=True" renders the UI inside the notebook output; drop it to open a
     new tab. Add share=True for a temporary public link (needs internet).

The app loads the built-in sample policy on start-up, so every section works
without uploading anything. Upload docs/examples/invalid_policy.csv to see the
validation error state and docs/examples/valid_custom_policy.csv for a clean,
user-supplied policy.
'''
print(INSTRUCTIONS)

LAUNCH = False          # set to True to start the server from the notebook
if LAUNCH:
    demo.queue()
    demo.launch(server_name="0.0.0.0", server_port=7860, inline=True)
print("No server started (LAUNCH = False) — nothing is left running.")
"""

SCREENSHOTS_CELL = """
# ── 3.2 The captured screens (docs/screenshots) ──────────────────────────────
# Real captures from the running app, not mock-ups. See docs/SCREENSHOTS.md.
from IPython.display import Image

CAPTIONS = [
    ("01_app_overview_sample_policy.png", "1 · Landing state — sample policy auto-loaded, summary and policy table"),
    ("10_validation_errors.png",          "2 · Upload + validation error state — 8 problems listed by row"),
    ("02_simulate_allow_rule1.png",       "3 · Simulated packet — allow by rule 1, rule 3 shadowed for it"),
    ("03_simulate_default_deny.png",      "4 · Simulated packet — no match, documented default DENY"),
    ("04_simulate_deny_wins.png",         "5 · Simulated packet — deny (rule 7) before allow (rule 8)"),
    ("05_simulate_invalid_input.png",     "6 · Simulated packet — invalid CIDR/port rejected with a message"),
    ("06_analysis_conflicts.png",         "7 · Analysis table — conflicts, with the winner and why"),
    ("07_analysis_shadowed.png",          "8 · Analysis table — shadowed rules and suggested review actions"),
    ("08_rule_explanation.png",           "9 · Policy explanation — rule 3 explained in plain English"),
    ("09_valid_custom_upload.png",        "10 · A user CSV (5 rules) validated and re-analysed"),
]

for filename, caption in CAPTIONS:
    path = pathlib.Path("docs/screenshots") / filename
    if path.exists():
        print(caption)
        display(Image(filename=str(path), width=900))
    else:
        print(f"[missing] {path}")
"""

PHASE4_INTRO = """
<a id="4"></a>
## 4 · Acceptance tests

Eighteen `unittest` cases. The eight required acceptance tests map to T01-T08;
T09-T18 cover the validation and robustness rules the brief also demands.

| Requirement | Test |
|---|---|
| allow-before-deny: the allow above the overlapping deny wins | T01 |
| deny-before-allow: the reverse order gives the opposite outcome | T02 |
| wildcard scopes: `0.0.0.0/0` and `any` port/protocol match | T03 |
| invalid CIDR rejected with a clear error | T04 |
| shadowing: a fully covered later rule is flagged | T05 |
| redundancy: a duplicate rule is flagged | T06 |
| first-match: the first matching rule is returned, not a later one | T07 |
| no-match: the documented default action is applied | T08 |
| ports out of range / inverted / non-numeric | T09 |
| protocol and action outside the allowed values | T10 |
| duplicate and non-integer order values | T11 |
| missing column header | T12 |
| empty / non-CSV / Excel uploads | T13 |
| overlap detection finds intersecting pairs only | T14 |
| conflicts name the earlier rule as the winner | T15 |
| simulator input validation (CIDR as IP, port 99999, protocol any) | T16 |
| normalisation: sorted by order, lowercased, CIDR masked | T17 |
| end-to-end pipeline feeding the UI tables | T18 |
"""

TEST_CELL = """
# ── 4.1 Run the suite (unittest, no mocks) ───────────────────────────────────
import unittest
import importlib
import firewall_rules.test_report as test_report

importlib.reload(test_report)                 # pick up edits without a restart
suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
outcome = runner.run(suite)

print(f"\\nran {outcome.testsRun} tests · failures {len(outcome.failures)} · "
      f"errors {len(outcome.errors)}")
assert outcome.wasSuccessful(), "acceptance suite failed — see the output above"
print("ALL ACCEPTANCE TESTS PASSED")
"""

TABLE_CELL = """
# ── 4.2 Test-case table, generated from the run above ────────────────────────
# "Actual result" is what each test observed; pass/fail comes from unittest.
from firewall_rules.test_report import run_acceptance_suite, test_case_rows

records = run_acceptance_suite()
passed = sum(1 for record in records.values() if record["status"] == "PASS")
print(f"{passed}/{len(records)} passed\\n")

table = pd.DataFrame(test_case_rows()[1:], columns=test_case_rows()[0])
display(table)

markdown = test_report.markdown_table()
pathlib.Path("docs").mkdir(exist_ok=True)
pathlib.Path("docs/TEST_CASES.md").write_text(
    "# Test cases\\n\\nGenerated by `firewall_rules.test_report.markdown_table()`; "
    "the *actual result* column is what each test observed.\\n\\n" + markdown + "\\n",
    encoding="utf-8",
)
print("written to docs/TEST_CASES.md")
"""

FINAL_CELL = """
# ── 9. Final check: everything a reviewer needs, asserted in one cell ───────
from firewall_rules.engine import DEFAULT_ACTION, find_conflicts, find_redundant, find_shadowed
from firewall_rules.sample_policy import SAMPLE_POLICY_CSV

checks = []

def check(label, condition, detail=""):
    checks.append((label, bool(condition), detail))

# Phase 1
check("sample policy loads and validates", result.ok, f"{len(result.policy)} rules")
check("sample CSV on disk matches the built-in constant",
      pathlib.Path("sample_policy.csv").read_text(encoding="utf-8").strip()
      == SAMPLE_POLICY_CSV.strip())
check("invalid CSV is rejected with row-numbered errors",
      not load_and_validate("docs/examples/invalid_policy.csv").ok,
      f"{len(load_and_validate('docs/examples/invalid_policy.csv').errors)} errors")

# Phase 2
check("shadowed rules found", len(find_shadowed(result.policy)) >= 1,
      f"rules {[item.rule.order for item in find_shadowed(result.policy)]}")
check("redundant rules found", len(find_redundant(result.policy)) >= 1,
      f"rules {[item.rule.order for item in find_redundant(result.policy)]}")
check("conflicts found", len(find_conflicts(result.policy)) >= 1,
      f"{len(find_conflicts(result.policy))} pairs")
allow_first = match_packet(result.policy, {"source": "10.1.2.3", "destination": "10.9.9.5",
                                           "port": "3306", "protocol": "tcp"})
check("first match is rule 1 for 10.1.2.3:3306/tcp", allow_first.rule.order == 1)
check("default action is deny and is applied on no match",
      DEFAULT_ACTION == "deny"
      and match_packet(result.policy, {"source": "8.8.8.8", "destination": "1.1.1.1",
                                       "port": "5353", "protocol": "udp"}).is_default)

# Phase 3
check("Gradio app builds without a server", demo is not None,
      f"{len(demo.blocks)} blocks")

# Phase 4
check("acceptance suite is green", outcome.wasSuccessful(), f"{outcome.testsRun} tests")
check("screenshots present", len(list(pathlib.Path("docs/screenshots").glob("*.png"))) == 10,
      f"{len(list(pathlib.Path('docs/screenshots').glob('*.png')))} images")
check("docs present",
      all(pathlib.Path("docs", name).exists()
          for name in ("ARCHITECTURE.md", "LIMITATIONS.md", "SCREENSHOTS.md",
                       "SUBMISSION_CHECKLIST.md", "TEST_CASES.md")))

for label, ok, detail in checks:
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  [{detail}]" if detail else ""))

assert all(ok for _, ok, _ in checks), "final check failed"
print(f"\\nFINAL CHECK PASSED — {len(checks)} checks, {outcome.testsRun} acceptance tests, "
      f"{len(analysis.findings())} findings on the sample policy.")
"""

ABOUT_RENDER = """
### 3.3 What the UI deliberately does *not* do

* It does not re-implement matching, overlap or shadowing logic.
* It does not modify the policy — the table and the findings are read-only.
* It does not persist anything, and it does not leave a server running unless
  you explicitly launch it.
"""


def build() -> nbf.NotebookNode:
    notebook = nbf.v4.new_notebook()
    cells = [
        md(TITLE),
        md("### 0 · Environment"),
        code(SETUP),
        md(PHASE1_INTRO),
        code(SAMPLE_CELL),
        md(SAMPLE_INTENT),
        md("### 1.3 Loading and validating"),
        code(VALIDATE_CELL),
        code(SOURCE_VIEW),
        code(BAD_CELL),
        md(VALIDATION_RULES),
        md(PHASE2_INTRO),
        code(MATCH_CELL),
        code(ANALYSIS_CELL),
        code(FINDINGS_CELL),
        code(EXPLAIN_CELL),
        md(PHASE3_INTRO),
        code(LAUNCH_CELL),
        code(SCREENSHOTS_CELL),
        md(ABOUT_RENDER),
        md(PHASE4_INTRO),
        code(TEST_CELL),
        code(TABLE_CELL),
        md("<a id=\"5\"></a>\n## 5 · Limitations\n\n" + read_doc("LIMITATIONS.md")),
        md("<a id=\"6\"></a>\n## 6 · Architecture\n\n" + read_doc("ARCHITECTURE.md")),
        md("<a id=\"7\"></a>\n## 7 · Screenshots to capture\n\n" + read_doc("SCREENSHOTS.md")),
        md("<a id=\"8\"></a>\n## 8 · Submission checklist\n\n" + read_doc("SUBMISSION_CHECKLIST.md")),
        md("<a id=\"9\"></a>\n## 9 · Final check\n\nOne cell that asserts every deliverable "
           "is present and correct. It is the machine-readable version of the checklist above."),
        code(FINAL_CELL),
    ]
    notebook["cells"] = cells
    notebook["metadata"] = {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11"},
        "title": "Firewall Rule Analysis System",
    }
    return notebook


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true",
                        help="run every cell and store the outputs in the .ipynb")
    args = parser.parse_args()

    notebook = build()
    with open(NOTEBOOK, "w", encoding="utf-8") as handle:
        nbf.write(notebook, handle)
    print(f"wrote {NOTEBOOK} ({len(notebook['cells'])} cells)")

    if args.execute:
        import nbclient

        with open(NOTEBOOK, "r", encoding="utf-8") as handle:
            notebook = nbf.read(handle, as_version=4)
        client = nbclient.NotebookClient(
            notebook,
            timeout=600,
            kernel_name="python3",
            resources={"metadata": {"path": ROOT}},
            allow_errors=False,
        )
        client.execute()
        with open(NOTEBOOK, "w", encoding="utf-8") as handle:
            nbf.write(notebook, handle)
        print("executed all cells and saved outputs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
