# Architecture

## 1. What the system does

The Firewall Rule Analysis System is a static auditor for ordered firewall
policy files. It reads a CSV whose rows are firewall rules, validates every
field, and answers three questions a reviewer actually asks: *what would happen
to this packet*, *which rules can never take effect*, and *which rules
contradict each other*. It never touches a live firewall. There is no packet
capture, no vendor API, no iptables/nftables interaction and no traffic
enforcement: the only input is a file and the only output is a report.

The project is split into four layers, each with one job:

```
CSV file / upload / DataFrame
        │
        ▼
firewall_rules/validation.py     load_policy()      read bytes → DataFrame
                                 validate_policy()  DataFrame → errors | clean policy
        │
        ▼
firewall_rules/engine.py         compile_policy()   clean policy → list[Rule]
                                 match_packet()     packet → first match + action
                                 find_overlaps()    pairwise scope intersection
                                 find_shadowed()    rules that can never win
                                 find_redundant()   rules that can be deleted safely
                                 find_conflicts()   overlapping rules that disagree
                                 analyse_policy()   all of the above, once
        │
        ├──────────────► tests/test_acceptance.py  18 automated acceptance tests
        │
        ▼
firewall_rules/ui.py             Gradio handlers    render findings, never decide them
```

## 2. Data flow, stage by stage

**Stage 1 — ingestion (`load_policy`).** The upload can arrive as a path, raw
bytes (what a Gradio `gr.File(type="binary")` hands over), CSV text, or a
file-like object; the loader normalises all four to bytes and gives them a
display name. It then fails *softly* on the four ways real uploads go wrong:
an empty or whitespace-only file, an Excel workbook (`PK\x03\x04` magic bytes),
binary content (NUL bytes), and a non-CSV text file. Text decoding tries
UTF-8 with BOM, then UTF-8, then cp1252, then latin-1, and the encoding that
worked is carried forward so the UI can warn about it. The header is sniffed
before pandas is invoked, so "this is not comma-separated" produces our
message rather than a pandas traceback. Reading is deliberately done with
`dtype=str` and `keep_default_na=False`, so nothing is silently coerced to NaN
or a float — every downstream decision is made on the exact text the user
wrote. The result is a `LoadResult` that holds either a raw DataFrame or a list
of human-readable errors.

**Stage 2 — validation (`validate_policy`).** Validation is pure: it takes a
DataFrame and never raises for bad user data. It checks the header (six
columns, exact names, extras warned and ignored), then walks each row and
validates `order` (integer, unique), `source` and `destination` (IPv4 CIDR via
`ipaddress.ip_network(..., strict=False)`), `port` (`any`, a single port, or an
inclusive `start-end` range inside 0-65535 with `start <= end`), `protocol`
(tcp/udp/icmp/any) and `action` (allow/deny). Every problem becomes one string
prefixed with the *CSV line number*, computed as DataFrame index + 2 so the
number matches what the user sees in a text editor with the header on line 1.
A row is only accepted when all six of its fields pass, which prevents the
engine from ever seeing a half-valid rule. On success the returned policy is
normalised — trimmed strings, lowercase keywords, canonical CIDRs, integer
order — and sorted by `order`, because file position is not evaluation order.

The field-level parsers (`parse_cidr`, `parse_port_spec`, `parse_protocol`,
`parse_action`, `parse_order`) live in this module and are imported by the
engine. That single definition is why validation and analysis can never
disagree about what `1000-2000` or `10.1.2.3/8` means.

**Stage 3 — compilation (`compile_policy`).** The engine does not re-parse
strings on every comparison. `compile_policy` turns each row into a frozen
`Rule` dataclass holding both the display strings and the parsed
`IPv4Network` / `PortRange` objects. Compiling once and reusing the result is
what keeps `analyse_policy` cheap: the O(n²) pair loop compares already-parsed
scopes instead of re-parsing CIDR text 182 times for a 14-rule policy.

**Stage 4 — analysis.** `match_packet` walks the compiled rules in order and
returns the first whose source, destination, port and protocol all match, plus
the action and a generated explanation. If nothing matches it applies the
module constant `DEFAULT_ACTION = "deny"` and says so in the explanation; the
default is default-deny because a silent allow is the wrong failure mode for
an audit tool. `find_overlaps` compares every unordered rule pair on all four
dimensions (address-bound comparison for CIDRs, interval intersection for
ports, equality-or-`any` for protocol). `find_shadowed` reuses that coverage
relation with a direction: rule *j* is shadowed when some earlier rule *i*
covers it entirely. `find_redundant` looks for exact duplicates and for rules
covered by an earlier rule with the same action. `find_conflicts` is the
overlap set filtered to pairs whose actions differ, with the earlier rule
reported as the winner since first-match evaluation stops there.
`analyse_policy` runs all four and returns one `AnalysisResult`, each finding
carrying both its explanation and a suggested review action.

**Stage 5 — presentation.** The Gradio app holds one `gr.State` cell: the
validated policy DataFrame. Every interaction — upload, load sample, change
the category filter, simulate, explain a rule — calls a library function and
formats the returned objects as Markdown or as a DataFrame. The UI contains no
CIDR arithmetic, no port-range parsing and no notion of shadowing; it decides
layout, wording and colour only. Both the "load sample" button and the
on-load handler call the same `load_policy_source` function, so the demo path
and the upload path cannot drift apart.

## 3. Design decisions and why the engine is separate from the UI

**Testability.** The acceptance tests exercise `match_packet`, `find_shadowed`
and friends directly, with no browser, no server and no Gradio import. All 18
run in well under a second. If the analysis logic lived in the event handlers,
every test would need a UI harness, and the tests would be testing Gradio as
much as the firewall semantics.

**One source of truth.** Shadowing is subtle enough that two implementations
will disagree within a week. The engine owns the definition; the UI only
renders `Shadowed.explanation()` and `Shadowed.suggested_action()`, which means
the table, the rule explainer and the packet explanation all say the same
thing. The same argument applies to validation: the sample button, the upload
path and the CSV fixtures all go through `validate_policy`.

**Reusability.** The functions take a DataFrame or a `Policy`, not a file
handle and not a request. The same engine can therefore back a CLI, a REST
endpoint or a CI check ("fail the build if a policy has shadowed deny rules")
without touching the UI, and it can be used inside a notebook cell for
exploration, which is exactly how phases 1 and 2 were developed.

**Determinism and error handling.** Parsers return errors; handlers return
messages. No user-supplied value is allowed to raise out of a callback. The
only exceptions that escape are deliberate: `parse_packet` raises `ValueError`
with a UI-safe message, and the simulation handler catches it and renders the
text, so an invalid IP or a port of 99999 produces an explanation, not a stack
trace. This is why the app survives empty files, Excel uploads and wrong
encodings instead of crashing.

**Honest scope.** Every simplification — IPv4 only, single interface, no
connection tracking, no NAT, no time-based rules, first match wins, a single
default action — is stated in the engine docstrings, repeated in the UI
description and listed in the limitations section. The analysis is exact
within that model and silent about anything outside it, which is the most
useful thing an audit tool can be: a reviewer can trust a finding and can see
exactly what was not modelled.

**Ordering matters everywhere.** Rules are sorted by `order` on validation, by
`order` on compilation, and every comparison uses `order` rather than list
position, so a policy file whose rows were reshuffled in a spreadsheet still
analyses according to the numbers a firewall would actually use.
