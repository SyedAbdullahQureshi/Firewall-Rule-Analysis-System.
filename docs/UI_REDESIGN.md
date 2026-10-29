# UI redesign — changes and verification

Presentation-only work: layout, styling, component arrangement, labels and
feedback messages. **No engine logic, function name, argument or return
structure changed.** Every handler still calls `load_and_validate`,
`analyse_policy`, `match_packet`, `explain_rule` and `parse_packet`, and the 18
acceptance tests were not touched and still pass.

## 1. What changed, and why

| # | Element | Before | After | Why |
|---|---|---|---|---|
| 1 | **Header** | A Markdown `#` heading followed by a paragraph of prose | A header band: title, one subtitle line (*Policy audit tool · Does not enforce traffic · read-only analysis*), and a live status badge on the right | A reviewer must learn what the tool does and does not do in five seconds; the badge makes the current state impossible to miss |
| 2 | **Status badge** | Did not exist | Grey *No policy loaded* → green *Policy loaded: N rules* → red *Validation errors: N*, driven from the load handler | The old page had no persistent indication of what was loaded |
| 3 | **Upload box** | Three overlapping default labels ("Drop File Here", "- or -", "Click to Upload") colliding with the icon and the block label | One sentence, "Drop a policy CSV here, or click to browse", stacked under a single icon; the stock label and `- or -` are removed and the box height is fixed so nothing overflows | Directly fixes the reported overlap; removes the ambiguity of two competing instructions |
| 4 | **Required columns** | Mentioned in a paragraph above the uploader | Monospace chips directly under the dropzone: `order source destination port protocol action` | The schema belongs next to the thing that must match it |
| 5 | **Button row** | Two default-width buttons with ragged edges, misaligned with the upload area | Equal-width (`flex: 1 1 0`) primary *Validate uploaded CSV* and secondary *Load built-in sample policy* in one row | Aligns with the dropzone, and states the primary action first |
| 6 | **Validation feedback** | A bold "VALID/INVALID" pill plus a plain bullet list | Green ✓ panel with the rule count (and any warnings), or a red ✗ panel listing each error with its row number in a monospace chip | Errors are the product of this tool; they deserve structure and scannability |
| 7 | **Simulator fields** | Rows that expanded to different widths, no grouping, default fonts | A labelled 2×2 grid inside the Step 2 card, monospace inside IP and port fields, a full-width primary button | Consistent widths make four related values read as one packet |
| 8 | **Simulator empty state** | Italic "Load a policy, then press Simulate packet" | A dedicated decision panel reading "No packet yet" + "Load a policy, then enter a packet to see the decision." | The result area should look like a result area before it has a result |
| 9 | **Simulate button** | Always enabled; failed with "load a policy first" *after* the click | Disabled until a policy loads, with a helper line explaining why, which then changes to explain the default DENY | Prevents a dead-end interaction and teaches the default at the same time |
| 10 | **Decision result** | A Markdown heading plus labelled lines | Large ALLOW / DENY / *NO MATCH — DEFAULT DENY* verdict badge, a monospace matched-rule chip, the packet line, and the explanation as a paragraph | The verdict is the single most important pixel on the page |
| 11 | **Field errors** | One banner for the whole packet | Inline message under the offending field ("→ port 99999 is outside the valid range 0-65535"), attributed using the engine's own `parse_packet` | Points at the fix, not just at the problem — and adds no new validation logic |
| 12 | **Analysis tabs** | A radio group labelled "Show" | A segmented control with counts on every tab: *All findings (28) · Shadowed (3) · Redundant (3) · Conflicts (10) · Overlapping pairs (15)* | Counts let a reviewer triage before clicking |
| 13 | **Findings table** | Plain text cells, no separation, category as words | Category as a coloured pill, rule pairs in monospace with an arrow (`3 → 1`, `1 vs 2`), wrapped monospace-free explanation, and a bold first sentence for the review action; zebra striping and row hover | The table is the audit output; it must be scannable at a glance |
| 14 | **Analysis empty states** | A single italic line | "No analysis yet. Load a policy to begin." with a CSS-only table skeleton (no icons, no images), and "No issues found in this category." when a tab is clean | Distinguishes *nothing loaded* from *nothing wrong* — an important difference in an audit tool |
| 15 | **Section numbering** | `## 1`, `## 2` headings sitting in the flow | Numbered circles in card headers and numbered section heads with a top rule | Steps now read as a sequence rather than five unrelated blocks |
| 16 | **Policy table** | Full-width table with no visual hierarchy, opened by default | Its own Step 4 section, collapsible, opened automatically after a load; monospace scope columns, right-aligned rule numbers, ALLOW/DENY pills | Restores the required step order and makes the action column scannable |
| 17 | **Explain a rule** | Button beside a dropdown, output as bold text | Same row layout, output in a quoted callout with a violet left accent bar and a *Rule N* chip | A quoted explanation reads as commentary, not as another heading |
| 18 | **Limitations footer** | One dense paragraph of dot-separated clauses | A card titled "Simplified semantics and limits" with modelled ✓ / not-modelled ✗ lists in two columns, closing with the bold "This tool audits the policy file and never enforces traffic." | The scope statement is a selling point for an audit tool, not fine print |
| 19 | **Theme** | Gradio default grey on white | `gr.themes.Base()` re-coloured through its own variables (137 tokens, light + dark slots) *and* a single custom CSS string | Fixing it at the theme level is why panels, inputs and tables are dark at the source rather than patched one selector at a time |
| 20 | **Responsiveness** | Two columns squeezed below 900 px | Columns stack under 900 px; the header and footer reflow | Usable on a laptop half-screen |
| 21 | **Stale-doc fix** | The Gradio 6 `css=`/`theme=` move to `launch()` meant a bare `demo.launch()` from the notebook would lose all styling | The stylesheet is injected by the app itself (`gr.HTML("<style>…</style>")`), and also passed to `launch` for Gradio 6 | "Runnable from the notebook with Restart and Run All" now yields the styled app, not the default one |

### Colour semantics (used consistently everywhere)

| Meaning | Token | Where |
|---|---|---|
| ALLOW / valid / loaded | `--fr-allow` `#2dd4a7` | action pills, decision badge, status badge, success panel |
| DENY / error / invalid | `--fr-deny` `#ff5d62` | action pills, decision badge, error panel, error badge |
| SHADOWED / default-deny | `--fr-shadowed` `#f5b942` | category pill, no-match decision, warnings |
| REDUNDANT | `--fr-redundant` `#a8b8cd` | category pill |
| CONFLICT | `--fr-conflict` `#ff8a4c` | category pill |
| OVERLAP | `--fr-overlap` `#b39cff` | category pill, explanation callout bar |
| Action / focus | `--fr-accent` `#4c8dff` | primary buttons, focus rings, step markers |

Every colour is paired with a text label (`ALLOW`, `DENY`, `SHADOWED`, …), so
colour is never the only signal. All 20 foreground/background pairs were
measured: the lowest contrast is **5.33:1**, above the WCAG AA 4.5:1 threshold.

## 2. Before / after checklist

Tick each row against the running app (`python -m firewall_rules.ui --port 7860`).

| ✔ | Check | Before (old UI) | After (redesigned) |
|---|-------|-----------------|--------------------|
| ☐ | **Empty state** on first paint | Plain heading + paragraph; no state indicator | Header band with grey *No policy loaded* badge; simulator disabled with a helper line; "No analysis yet. Load a policy to begin." with the CSS skeleton; policy section collapsed |
| ☐ | **Valid upload** (`docs/examples/valid_custom_policy.csv`) | "VALID" pill + a text line | Green ✓ panel "Policy valid — uploaded file · 5 rules accepted, validated and analysed"; badge flips to green *Policy loaded: 5 rules*; analysis switches to *All findings*; policy table opens automatically |
| ☐ | **Invalid upload** (`docs/examples/invalid_policy.csv`) | Bullet list of errors | Red ✗ panel "8 validation problem(s) — nothing was analysed" with each row number in a monospace chip; badge flips to red *Validation errors: 8*; simulate disabled and findings cleared |
| ☐ | **Sample policy button** | Loaded the sample | Loads the sample through the same handler; badge *Policy loaded: 14 rules*; tabs show (28) (3) (3) (10) (15) |
| ☐ | **Simulation → ALLOW** (`10.1.2.3 → 10.9.9.5`, port `3306`, tcp) | Heading + bold labels | Green **ALLOW** verdict, `Rule 1` chip, packet line, explanation paragraph |
| ☐ | **Simulation → DENY** (preset *Deny before allow (rules 7 and 8)*) | Same plain layout | Red **DENY** verdict with `Rule 7`, explanation naming why rule 7 wins over rule 8 |
| ☐ | **Simulation → no match** (`8.8.8.8 → 1.1.1.1`, port `5353`, udp) | Bold "DEFAULT DENY" line | Amber **NO MATCH — DEFAULT DENY** verdict with a `no rule matched` chip |
| ☐ | **Invalid packet input** (port `99999`, or a CIDR as source) | One combined banner | Inline **→ port 99999 is outside the valid range 0-65535** directly under the Port field, plus the red *Invalid input* panel |
| ☐ | **Explanation panel** (Rule 3 + *Explain rule*) | Bold paragraph | Quoted callout with a violet accent bar, a `Rule 3` chip, and the shadowing explanation |
| ☐ | **Analysis tabs** | Radio buttons without counts | Segmented pills with counts; clicking one filters the table; a clean category shows "No issues found in this category." |
| ☐ | **Policy table** | Always visible, plain | Its own Step 4 section, opens after a load, monospace columns, ALLOW/DENY pills, right-aligned rule numbers |
| ☐ | **Limitations footer** | Dense paragraph | Card with modelled ✓ / not-modelled ✗ two-column lists and the bold never-enforces line |
| ☐ | **Narrow screen** (< 900 px wide) | Columns squeezed | Cards stack; header and footer reflow; no horizontal scrolling of the page |
| ☐ | **Restart & Run All** | Notebook ran, but a bare `demo.launch()` lost the styling | Notebook runs top to bottom; the final cell prints `FINAL CHECK PASSED`; the app launched from the notebook is styled, because the CSS is injected by the app itself |

## 3. How to reproduce the verification

```bash
python -m unittest discover -s tests -v      # 18 engine tests, unchanged, still green
python -m firewall_rules.ui --port 7860      # the redesigned app
python tools/build_notebook.py --execute     # notebook: runs top to bottom, 0 errors
```

The notebook's section 9 asserts the redesign is wired: the palette tokens exist
in one place, the theme carries the dark surfaces, simulation starts disabled,
the screenshots are present, and the acceptance suite is green.
