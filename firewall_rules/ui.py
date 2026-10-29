"""Gradio interface for the Firewall Rule Analysis System (Phase 3).

The UI is a *renderer*. It never decides whether a rule is shadowed, never
compares CIDRs and never parses a port range itself — it calls
:mod:`firewall_rules.validation` and :mod:`firewall_rules.engine` and formats
the objects they return. That keeps exactly one implementation of the semantics,
which is what the automated tests in ``tests/test_acceptance.py`` exercise.

Launch from the notebook::

    from firewall_rules.ui import build_app
    demo = build_app()
    demo.launch()

Launch from a terminal::

    python -m firewall_rules.ui --port 7860

Modules used: gradio, pandas, ipaddress (via the engine). Nothing else.
"""

from __future__ import annotations

import argparse
from typing import Any, Optional

import gradio as gr
import pandas as pd

from .engine import (
    DEFAULT_ACTION,
    analyse_policy,
    explain_rule,
    match_packet,
)
from .sample_policy import SAMPLE_PACKETS, SAMPLE_POLICY_CSV
from .validation import POLICY_COLUMNS, load_and_validate

FINDING_COLUMNS = ["Category", "Rules", "Explanation", "Suggested review action"]
POLICY_DISPLAY_COLUMNS = list(POLICY_COLUMNS)

CATEGORY_ALL = "All findings"
CATEGORY_MAP = {
    "Shadowed rules": "Shadowed rule",
    "Redundant rules": "Redundant rule",
    "Conflicts": "Conflict",
    "Overlapping pairs": "Overlap",
}
CATEGORY_CHOICES = [CATEGORY_ALL, *CATEGORY_MAP]

DESCRIPTION = """
# Firewall Rule Analysis System

**This app audits firewall *policy files*. It does not enforce real network
traffic, does not connect to a firewall, and does not see live packets.**

Upload an ordered policy CSV (columns: `order, source, destination, port,
protocol, action`), or load the built-in sample policy, then:

* **upload** — the file is validated and every problem is reported by row;
* **simulate** — walk a synthetic packet through the policy with first-match
  semantics and read the plain-English decision;
* **analyse** — review overlapping, shadowed, redundant and conflicting rules,
  each with a suggested review action.

Simplified semantics: IPv4 only, single interface, no connection tracking, no
NAT, no time-based rules, first match wins, and when nothing matches the
documented **default action is DENY**.
"""

PALETTE = {
    "allow": ("#dcfce7", "#14532d", "#bbf7d0"),
    "deny": ("#fee2e2", "#7f1d1d", "#fecaca"),
    "neutral": ("#f1f5f9", "#0f172a", "#e2e8f0"),
    "warn": ("#fef3c7", "#78350f", "#fde68a"),
}


def badge(text: str, tone: str = "neutral") -> str:
    """Inline pill used in the Markdown panels (presentation only)."""
    background, colour, border = PALETTE.get(tone, PALETTE["neutral"])
    return (
        f'<span style="background:{background};color:{colour};border:1px solid '
        f'{border};border-radius:999px;padding:2px 10px;font-size:0.85em;'
        f'font-weight:600;letter-spacing:0.02em">{text}</span>'
    )


EMPTY_FINDINGS_HELP = (
    "_Load a policy (upload a CSV or click **Load built-in sample policy**) to "
    "see the overlap, shadowing, redundancy and conflict analysis._"
)


# ---------------------------------------------------------------------------
# Formatting helpers (pure presentation — no policy logic)
# ---------------------------------------------------------------------------
def _empty_policy_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=POLICY_DISPLAY_COLUMNS)


def _findings_frame(findings: list[dict[str, Any]], category: str) -> pd.DataFrame:
    """Filter the engine's findings list for the requested category."""
    if not findings:
        return pd.DataFrame(columns=FINDING_COLUMNS)
    wanted = CATEGORY_MAP.get(category)
    rows = [row for row in findings if wanted is None or row["Category"] == wanted]
    if not rows:
        return pd.DataFrame(
            [["—", "—", f"No findings in this category ({category}).", "Nothing to review here."]],
            columns=FINDING_COLUMNS,
        )
    return pd.DataFrame(rows, columns=FINDING_COLUMNS)


def _summary_markdown(analysis, origin: str) -> str:
    counts = analysis.summary()
    return (
        f"### Analysis of {origin}\n"
        f"**{counts['rules']} rules** · "
        f"**{counts['overlaps']}** overlapping pair(s) · "
        f"**{counts['shadowed']}** shadowed · "
        f"**{counts['redundant']}** redundant · "
        f"**{counts['conflicts']}** conflicting pair(s)\n\n"
        f"Default action when no rule matches: **{DEFAULT_ACTION.upper()}** "
        "(documented default-deny posture)."
    )


def _status_ok(result, origin: str) -> str:
    warning_text = ""
    if result.warnings:
        warning_text = "\n\n**Warnings**\n" + "\n".join(
            f"- {warning}" for warning in result.warnings
        )
    return (
        f"### {badge('VALID', 'allow')} Policy loaded — {origin}\n"
        f"{len(result.policy)} rules accepted and analysed." + warning_text
    )


def _errors_markdown(errors: list[str]) -> str:
    listing = "\n".join(f"- {error}" for error in errors)
    return (
        f"### {badge('INVALID', 'deny')} Validation failed — {len(errors)} problem(s)\n"
        "Fix these rows and upload again. Nothing was analysed.\n\n"
        f"{listing}"
    )


def _clear_errors() -> str:
    return ""


def _rule_choices(policy: Optional[pd.DataFrame]) -> Any:
    """Dropdown choices for the rule explainer."""
    if policy is None or policy.empty:
        return gr.Dropdown(choices=[], value=None, interactive=False)
    orders = [int(value) for value in policy["order"].tolist()]
    return gr.Dropdown(
        choices=[(f"Rule {order}", order) for order in orders],
        value=orders[0],
        interactive=True,
    )


# ---------------------------------------------------------------------------
# Event handlers (every one of them calls the engine / validator)
# ---------------------------------------------------------------------------
def load_policy_source(source: Any, origin: str, category: str = CATEGORY_ALL):
    """Validate + analyse a CSV source and refresh every policy view.

    Used by both the uploader and the "load sample" button, so the two paths can
    never drift apart. Returns the nine component updates the layout expects.
    """
    try:
        result = load_and_validate(source)
    except Exception as exc:  # pragma: no cover - defensive, e.g. odd uploads
        return (
            f"### {badge('UNREADABLE', 'deny')} Could not read the file",
            _errors_markdown([f"unexpected problem while reading the file: {exc}"]),
            _empty_policy_frame(),
            pd.DataFrame(columns=FINDING_COLUMNS),
            None,
            EMPTY_FINDINGS_HELP,
            gr.Dropdown(choices=[], value=None, interactive=False),
            "",
            "",
        )

    if not result.ok:
        return (
            f"### {badge('NOT LOADED', 'deny')} Policy not loaded",
            _errors_markdown(result.errors),
            _empty_policy_frame(),
            pd.DataFrame(columns=FINDING_COLUMNS),
            None,
            EMPTY_FINDINGS_HELP,
            gr.Dropdown(choices=[], value=None, interactive=False),
            "",
            "",
        )

    analysis = analyse_policy(result.policy)
    return (
        _status_ok(result, origin),
        _clear_errors(),
        result.policy.loc[:, POLICY_DISPLAY_COLUMNS],
        _findings_frame(analysis.findings(), category),
        result.policy,
        _summary_markdown(analysis, origin),
        _rule_choices(result.policy),
        "",
        "",
    )


def handle_upload(file_bytes: Any):
    """Handler for the CSV uploader (also covers empty / non-CSV / Excel)."""
    if file_bytes is None:
        return (
            f"### {badge('NO FILE', 'warn')} No file selected",
            "Choose a `.csv` file above, or click **Load built-in sample "
            "policy** to explore the app with the 14-rule demo policy.",
            _empty_policy_frame(),
            pd.DataFrame(columns=FINDING_COLUMNS),
            None,
            EMPTY_FINDINGS_HELP,
            gr.Dropdown(choices=[], value=None, interactive=False),
            "",
            "",
        )
    return load_policy_source(file_bytes, "uploaded file")


def handle_load_sample(category: str = CATEGORY_ALL):
    """Handler for the built-in sample policy button."""
    return load_policy_source(SAMPLE_POLICY_CSV, "built-in sample policy", category)


def handle_filter(policy: Optional[pd.DataFrame], category: str):
    """Re-render the findings table for a different category filter."""
    if policy is None or policy.empty:
        return pd.DataFrame(columns=FINDING_COLUMNS), EMPTY_FINDINGS_HELP
    analysis = analyse_policy(policy)
    return _findings_frame(analysis.findings(), category), _summary_markdown(
        analysis, "the loaded policy"
    )


def handle_simulate(
    policy: Optional[pd.DataFrame],
    source: str,
    destination: str,
    port: Any,
    protocol: str,
):
    """Run one packet through the policy and render the decision.

    All input validation and matching happens inside
    :func:`firewall_rules.engine.match_packet`; a ``ValueError`` from there is a
    user-facing message, not a crash.
    """
    if policy is None or getattr(policy, "empty", True):
        return (
            f"### {badge('NO POLICY', 'warn')} Load a policy first\n"
            "Upload a CSV or click **Load built-in sample policy** in the upload "
            "section, then simulate again."
        )
    try:
        decision = match_packet(
            policy,
            {
                "source": source,
                "destination": destination,
                "port": port,
                "protocol": protocol,
            },
        )
    except ValueError as exc:
        return (
            f"### {badge('INVALID INPUT', 'deny')} Packet rejected\n"
            f"{exc}\n\n"
            "Example: source `10.1.2.3`, destination `10.9.9.5`, port `3306`, "
            "protocol `tcp`."
        )

    if decision.is_default:
        verdict = (
            f"### {badge('DEFAULT DENY', 'neutral')} No rule matched\n"
            f"**Action:** `{decision.action.upper()}` (the documented default)\n\n"
        )
        rule_line = f"**Matched rule:** none of the {len(policy)} rules\n\n"
    else:
        tone = "allow" if decision.action == "allow" else "deny"
        verdict = (
            f"### {badge(decision.action.upper(), tone)} Matched rule "
            f"{decision.rule.order}\n"
            f"**Action:** `{decision.action.upper()}`\n\n"
        )
        rule_line = f"**Matched rule:** {decision.rule.label()}\n\n"

    return (
        verdict
        + f"**Packet:** `{decision.packet.label()}`\n\n"
        + rule_line
        + f"**Rules evaluated:** {decision.rules_evaluated} of {len(policy)}\n\n"
        + f"**Explanation:** {decision.explanation}"
    )


def handle_preset(label: str) -> tuple:
    """Fill the simulator inputs from an example packet (no analysis run)."""
    for preset in SAMPLE_PACKETS:
        if preset["label"] == label:
            return (
                preset["source"],
                preset["destination"],
                str(preset["port"]),
                preset["protocol"],
                f"_Example: {preset['note']}_",
            )
    return gr.update(), gr.update(), gr.update(), gr.update(), gr.update()


def handle_explain_rule(policy: Optional[pd.DataFrame], order: Any):
    """Render the plain-English explanation for one rule."""
    if policy is None or getattr(policy, "empty", True) or order in (None, ""):
        return "_Load a policy and choose a rule to explain._"
    try:
        return f"**Rule {int(order)} explained**\n\n{explain_rule(policy, int(order))}"
    except (KeyError, ValueError, TypeError) as exc:
        return f"{badge('ERROR', 'deny')} {exc}"


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
def build_app() -> gr.Blocks:
    """Construct the Gradio app and wire every control to the engine."""
    presets = [preset["label"] for preset in SAMPLE_PACKETS]
    default_preset = SAMPLE_PACKETS[0]

    with gr.Blocks(title="Firewall Rule Analysis System") as demo:
        gr.Markdown(DESCRIPTION)

        policy_state = gr.State(None)

        with gr.Row(equal_height=False):
            # ---------------- Section 1: upload ----------------
            with gr.Column(scale=1):
                gr.Markdown("## 1 · Upload policy")
                policy_file = gr.File(
                    label="Firewall policy CSV",
                    file_types=[".csv", ".txt"],
                    type="binary",
                    height=150,
                )
                with gr.Row():
                    upload_button = gr.Button(
                        "Validate uploaded CSV", variant="primary"
                    )
                    sample_button = gr.Button("Load built-in sample policy")
                status_md = gr.Markdown("_No policy loaded yet._")
                errors_md = gr.Markdown("")

            # ---------------- Section 2: simulate ----------------
            with gr.Column(scale=1):
                gr.Markdown("## 2 · Simulate a packet")
                preset_dropdown = gr.Dropdown(
                    choices=presets,
                    value=default_preset["label"],
                    label="Example packets (fills the fields below)",
                )
                with gr.Row():
                    source_input = gr.Textbox(
                        label="Source IP", value=default_preset["source"],
                        placeholder="10.1.2.3",
                    )
                    destination_input = gr.Textbox(
                        label="Destination IP", value=default_preset["destination"],
                        placeholder="10.9.9.5",
                    )
                with gr.Row():
                    port_input = gr.Textbox(
                        label="Port", value=str(default_preset["port"]),
                        placeholder="443",
                    )
                    protocol_input = gr.Dropdown(
                        choices=["tcp", "udp", "icmp"],
                        value=default_preset["protocol"],
                        label="Protocol",
                        allow_custom_value=False,
                    )
                simulate_button = gr.Button("Simulate packet", variant="primary")
                decision_md = gr.Markdown(
                    "_Load a policy, then press **Simulate packet**._"
                )

        # ---------------- Section 3: analysis ----------------
        with gr.Column():
            gr.Markdown("## 3 · Overlap, shadowing and redundancy analysis")
            summary_md = gr.Markdown(EMPTY_FINDINGS_HELP)
            category_filter = gr.Radio(
                choices=CATEGORY_CHOICES,
                value=CATEGORY_ALL,
                label="Show",
            )
            findings_table = gr.Dataframe(
                value=pd.DataFrame(columns=FINDING_COLUMNS),
                headers=FINDING_COLUMNS,
                datatype=["str"] * len(FINDING_COLUMNS),
                type="pandas",
                wrap=True,
                max_height=None,  # render every row; the page scrolls instead of an inner scroller
                label="Findings and suggested review actions",
                interactive=False,
                column_widths=["12%", "12%", "46%", "30%"],
            )

        # ---------------- Section 4: policy table ----------------
        with gr.Accordion("4 · Validated policy table", open=True):
            policy_table = gr.Dataframe(
                value=_empty_policy_frame(),
                headers=POLICY_DISPLAY_COLUMNS,
                datatype=["number"] + ["str"] * (len(POLICY_DISPLAY_COLUMNS) - 1),
                type="pandas",
                label="Rules in evaluation order",
                interactive=False,
                max_height=None,
                show_search="search",
            )

        # ---------------- Section 5: rule explainer ----------------
        with gr.Accordion("5 · Explain a rule", open=False):
            with gr.Row():
                rule_dropdown = gr.Dropdown(
                    choices=[], value=None, label="Rule", interactive=False
                )
                explain_button = gr.Button("Explain rule")
            explanation_md = gr.Markdown("_Load a policy and choose a rule to explain._")

        gr.Markdown(
            "---\n"
            "**Limitations:** IPv4 only · single interface · no stateful "
            "connection tracking · no NAT · no time-based rules · one ordered "
            "list with a single default action · cannot model vendor-specific "
            "behaviour. This tool audits the policy file and **never enforces "
            "traffic**."
        )

        # ---------------- Wiring ----------------
        policy_outputs = [
            status_md,
            errors_md,
            policy_table,
            findings_table,
            policy_state,
            summary_md,
            rule_dropdown,
            decision_md,
            explanation_md,
        ]
        upload_button.click(
            handle_upload, inputs=[policy_file], outputs=policy_outputs
        )
        policy_file.upload(
            handle_upload, inputs=[policy_file], outputs=policy_outputs
        )
        sample_button.click(
            handle_load_sample,
            inputs=[category_filter],
            outputs=policy_outputs,
        )
        category_filter.change(
            handle_filter,
            inputs=[policy_state, category_filter],
            outputs=[findings_table, summary_md],
        )
        simulate_button.click(
            handle_simulate,
            inputs=[
                policy_state,
                source_input,
                destination_input,
                port_input,
                protocol_input,
            ],
            outputs=[decision_md],
        )
        preset_dropdown.change(
            handle_preset,
            inputs=[preset_dropdown],
            outputs=[
                source_input,
                destination_input,
                port_input,
                protocol_input,
                decision_md,
            ],
        )
        explain_button.click(
            handle_explain_rule,
            inputs=[policy_state, rule_dropdown],
            outputs=[explanation_md],
        )

        # Show the sample policy's analysis on first paint so the app is
        # demonstrable without any upload (this also exercises the same handler).
        demo.load(
            handle_load_sample,
            inputs=[category_filter],
            outputs=policy_outputs,
        )

    return demo


def launch_app(
    server_name: str = "0.0.0.0",
    server_port: int = 7860,
    share: bool = False,
    inline: bool = False,
    **kwargs: Any,
):
    """Build and launch the app.

    Parameters
    ----------
    server_name:
        ``"0.0.0.0"`` so the app is reachable from outside the container
        (needed for hosted/remote notebooks and the Arena preview).
    server_port:
        Port to bind.
    share:
        Ask Gradio for a temporary public link. Off by default; it requires
        outbound internet access.
    inline:
        Render the app inside the notebook output instead of a new tab.

    Returns
    -------
    The Gradio ``Blocks`` object (already launched).
    """
    demo = build_app()
    demo.queue()
    demo.launch(
        server_name=server_name,
        server_port=server_port,
        share=share,
        inline=inline,
        show_error=True,
        **kwargs,
    )
    return demo


def main() -> None:  # pragma: no cover - CLI entry point
    parser = argparse.ArgumentParser(description="Firewall Rule Analysis System UI")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7860)
    parser.add_argument("--share", action="store_true")
    args = parser.parse_args()
    launch_app(server_name=args.host, server_port=args.port, share=args.share)


if __name__ == "__main__":  # pragma: no cover
    main()
