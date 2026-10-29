"""Gradio interface for the Firewall Rule Analysis System (Phase 3).

Presentation only. This module never decides whether a rule is shadowed, never
compares CIDRs and never parses a port range: it calls
:mod:`firewall_rules.validation` and :mod:`firewall_rules.engine` and formats
the objects they return. The engine's function names, arguments and return
structures are untouched by the redesign.

Design language: a "technical audit console" — a dark-neutral base, one
restrained accent for primary actions, and four semantic colours reused
everywhere (allow / deny / shadow / conflict / overlap). Every colour is paired
with a text label so colour is never the only signal, and the palette is
declared once in the ``CSS`` string as custom properties.

Launch from the notebook::

    from firewall_rules.ui import build_app
    demo = build_app()
    demo.launch()          # styling is injected by the app itself

Launch from a terminal::

    python -m firewall_rules.ui --port 7860

Modules used: gradio, pandas, ipaddress (via the engine). Nothing else.
"""

from __future__ import annotations

import argparse
import html as html_module
from typing import Any, Callable, Optional, Sequence

import gradio as gr
import pandas as pd

from .engine import (
    DEFAULT_ACTION,
    analyse_policy,
    explain_rule,
    match_packet,
    parse_packet,
)
from .sample_policy import SAMPLE_PACKETS, SAMPLE_POLICY_CSV
from .validation import POLICY_COLUMNS, load_and_validate

# ---------------------------------------------------------------------------
# Section / category vocabulary
# ---------------------------------------------------------------------------
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

#: One category filter value -> (short tab label, count key in analysis.summary()).
CATEGORY_META: dict[str, tuple[str, str]] = {
    CATEGORY_ALL: ("All findings", "rules"),
    "Shadowed rules": ("Shadowed", "shadowed"),
    "Redundant rules": ("Redundant", "redundant"),
    "Conflicts": ("Conflicts", "conflicts"),
    "Overlapping pairs": ("Overlapping pairs", "overlaps"),
}

#: Finding category (engine vocabulary) -> colour token used by the pill CSS.
PILL_TONE = {
    "Shadowed rule": "shadowed",
    "Redundant rule": "redundant",
    "Conflict": "conflict",
    "Overlap": "overlap",
}
CATEGORY_WORD = {
    "Shadowed rule": "SHADOWED",
    "Redundant rule": "REDUNDANT",
    "Conflict": "CONFLICT",
    "Overlap": "OVERLAP",
}

#: Baseline packet used only to attribute an error message to one field.
_BASELINE_PACKET = {
    "source": "10.0.0.1",
    "destination": "10.0.0.2",
    "port": "80",
    "protocol": "tcp",
}

#: Placeholder shown before any policy is loaded.
EMPTY_ANALYSIS_HTML = ""  # replaced below once the helpers exist


# ---------------------------------------------------------------------------
# Styling — one string, palette declared once at the top
# ---------------------------------------------------------------------------
CSS = """
/* ── Design tokens ─────────────────────────────────────────────────────────
   Change the whole app's palette here. Semantic colours are intentionally
   saturated so that near-black "ink" text on top keeps WCAG AA contrast
   (>= 4.5:1) on every pill.                                            */
:root,
.gradio-container {
  --fr-bg:            #0e1116;
  --fr-surface:       #151a21;
  --fr-surface-2:     #1a2029;
  --fr-surface-3:     #202836;
  --fr-border:        #263040;
  --fr-border-strong: #3a475d;

  --fr-text:          #e8eef7;
  --fr-text-muted:    #9fb0c4;
  --fr-text-dim:      #8395a9;

  --fr-ink:           #0b0f14;   /* text on a saturated pill          */
  --fr-accent:        #4c8dff;   /* the one restrained action colour  */
  --fr-accent-ink:    #06101f;

  --fr-allow:         #2dd4a7;   /* ALLOW      green-teal             */
  --fr-deny:          #ff5d62;   /* DENY       red                    */
  --fr-shadowed:      #f5b942;   /* SHADOWED   amber                  */
  --fr-redundant:     #a8b8cd;   /* REDUNDANT  slate / blue-grey      */
  --fr-conflict:      #ff8a4c;   /* CONFLICT   orange-red             */
  --fr-overlap:       #b39cff;   /* OVERLAP    violet                 */

  --fr-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
             "Liberation Mono", monospace;
  --fr-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
             "Helvetica Neue", Arial, sans-serif;
  --fr-radius: 12px;
}

/* ── Page shell ─────────────────────────────────────────────────────────── */
body, .gradio-container {
  background: var(--fr-bg) !important;
  color: var(--fr-text) !important;
  font-family: var(--fr-sans);
}
.gradio-container {
  max-width: 1320px !important;
  padding: 18px 20px 48px !important;
}
footer, .footer { opacity: .65; }
.gradio-container .prose { color: var(--fr-text) !important; }
.gradio-container .prose p,
.gradio-container .prose li { color: var(--fr-text-muted) !important; }

/* Generic surfaces: every Gradio block becomes a console panel */
.gradio-container .block,
.gradio-container .form {
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
}

/* ── 1. Header band ─────────────────────────────────────────────────────── */
.fr-header {
  display: flex; align-items: center; justify-content: space-between;
  gap: 24px; flex-wrap: wrap;
  padding: 22px 26px;
  background: linear-gradient(180deg, #171d26 0%, #131922 100%);
  border: 1px solid var(--fr-border);
  border-left: 3px solid var(--fr-accent);
  border-radius: var(--fr-radius);
  margin-bottom: 18px;
}
.fr-header-main { display: flex; flex-direction: column; gap: 6px; min-width: 280px; }
.fr-title {
  margin: 0; font-size: 25px; line-height: 1.15; letter-spacing: -0.015em;
  font-weight: 650; color: var(--fr-text);
}
.fr-subtitle {
  margin: 0; font-size: 13.5px; color: var(--fr-text-muted);
  letter-spacing: .01em;
}
.fr-subtitle .sep { color: var(--fr-border-strong); margin: 0 8px; }
.fr-subtitle .never { color: var(--fr-deny); font-weight: 600; }

.fr-badge {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 8px 14px; border-radius: 999px;
  font-family: var(--fr-sans); font-size: 12.5px; font-weight: 650;
  letter-spacing: .02em; white-space: nowrap;
  border: 1px solid var(--fr-border-strong);
  background: var(--fr-surface-2); color: var(--fr-text-muted);
}
.fr-badge .dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: currentColor; box-shadow: 0 0 0 3px rgba(255,255,255,.05);
}
.fr-badge.is-empty { color: var(--fr-text-muted); }
.fr-badge.is-loaded {
  color: var(--fr-allow); border-color: rgba(45,212,167,.45);
  background: rgba(45,212,167,.10);
}
.fr-badge.is-error {
  color: var(--fr-deny); border-color: rgba(255,93,98,.45);
  background: rgba(255,93,98,.10);
}

/* ── 2. Cards ───────────────────────────────────────────────────────────── */
/* gr.Group renders an outer .block plus an inner .form: the wrapper is
   transparent and the inner form is the visible card, so no double borders. */
.fr-card.block {
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
  padding: 0 !important;
}
.fr-card .form,
.fr-card > div {
  background: var(--fr-surface) !important;
}
.fr-card {
  background: var(--fr-surface) !important;
  border: 1px solid var(--fr-border) !important;
  border-radius: var(--fr-radius) !important;
  padding: 20px 22px 22px !important;
  box-shadow: 0 1px 0 rgba(255,255,255,.02) inset !important;
}
.fr-card-head { display: flex; gap: 14px; align-items: flex-start; margin-bottom: 16px; }
.fr-step {
  flex: 0 0 auto; width: 26px; height: 26px; border-radius: 50%;
  display: inline-flex; align-items: center; justify-content: center;
  font-family: var(--fr-mono); font-size: 13px; font-weight: 700;
  color: var(--fr-accent-ink); background: var(--fr-accent);
  border: 1px solid rgba(255,255,255,.18);
  margin-top: 1px;
}
.fr-card-title {
  margin: 0; font-size: 16px; font-weight: 640; color: var(--fr-text);
  letter-spacing: -.01em;
}
.fr-card-sub {
  margin: 3px 0 0; font-size: 12.5px; line-height: 1.5;
  color: var(--fr-text-dim);
}

/* ── 3. Upload dropzone (single, non-overlapping label) ─────────────────── */
.fr-upload.block {
  border: 1px dashed var(--fr-border-strong) !important;
  border-radius: 10px !important;
  background: var(--fr-surface-2) !important;
  overflow: hidden;
}
.fr-upload.block:hover { border-color: var(--fr-accent) !important; }
.fr-upload .upload-container {
  background: transparent !important;
  border: none !important;
  border-radius: 10px !important;
  height: 132px !important;
  min-height: 0 !important;
  padding: 10px 14px !important;
  display: flex !important; align-items: center !important;
  justify-content: center !important;
  overflow: hidden !important;
}
.fr-upload .upload-container:hover { background: rgba(76,141,255,.06) !important; }
/* the stock block label is hidden entirely (no overlap with the icon) */
.fr-upload label[data-testid="block-label"],
.fr-upload .label-wrap { display: none !important; }
/* collapse the built-in "Drop File Here - or - Click to Upload" copy and
   replace it with one clear sentence, stacked under the icon */
.fr-upload .upload-text,
.fr-upload [data-testid="upload-text"] {
  font-size: 0 !important; line-height: 0 !important;
  height: auto !important; min-height: 0 !important;
  display: flex !important; flex-direction: column !important;
  align-items: center !important; justify-content: center !important;
  gap: 9px !important; padding: 0 !important;
  color: var(--fr-text-muted) !important;
}
.fr-upload .upload-text .or,
.fr-upload [data-testid="upload-text"] .or { display: none !important; }
.fr-upload .upload-text::after,
.fr-upload [data-testid="upload-text"]::after {
  content: "Drop a policy CSV here, or click to browse";
  font-size: 13px !important; line-height: 1.4 !important;
  font-family: var(--fr-sans) !important;
  color: var(--fr-text-muted) !important;
  letter-spacing: .01em;
}
.fr-upload [data-testid="upload-icon"],
.fr-upload .icon-wrap { color: var(--fr-accent) !important; opacity: .9; }
.fr-upload [data-testid="upload-icon"] svg,
.fr-upload .icon-wrap svg { width: 26px !important; height: 26px !important; }
.fr-upload .file-preview { background: var(--fr-surface-3) !important; }

/* ── 4. Small helpers: chips, hints, panels ─────────────────────────────── */
.fr-chips-label {
  font-size: 11px; text-transform: uppercase; letter-spacing: .08em;
  color: var(--fr-text-dim); font-weight: 700; margin: 14px 0 7px;
}
.fr-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.fr-chip {
  font-family: var(--fr-mono); font-size: 11.5px;
  color: var(--fr-text-muted);
  background: var(--fr-surface-3);
  border: 1px solid var(--fr-border);
  border-radius: 6px; padding: 3px 8px;
}

.fr-hint {
  display: flex; gap: 8px; align-items: flex-start;
  font-size: 12.5px; line-height: 1.5; color: var(--fr-text-dim);
  margin-top: 10px;
}
.fr-hint strong { color: var(--fr-text-muted); font-weight: 650; }
.fr-hint .key {
  font-family: var(--fr-mono); font-size: 11.5px; color: var(--fr-deny);
  background: rgba(255,93,98,.10); border: 1px solid rgba(255,93,98,.35);
  border-radius: 5px; padding: 1px 6px; white-space: nowrap;
}

.fr-panel {
  border-radius: 10px; padding: 12px 14px; margin-top: 14px;
  border: 1px solid var(--fr-border); background: var(--fr-surface-2);
  font-size: 13px; line-height: 1.55; color: var(--fr-text-muted);
}
.fr-panel-head {
  display: flex; align-items: center; gap: 8px;
  font-weight: 650; font-size: 13px; margin-bottom: 6px;
  color: var(--fr-text);
}
.fr-panel.is-ok { border-color: rgba(45,212,167,.40); background: rgba(45,212,167,.08); }
.fr-panel.is-ok .fr-panel-head { color: var(--fr-allow); }
.fr-panel.is-err { border-color: rgba(255,93,98,.42); background: rgba(255,93,98,.08); }
.fr-panel.is-err .fr-panel-head { color: var(--fr-deny); }
.fr-panel.is-warn { border-color: rgba(245,185,66,.42); background: rgba(245,185,66,.08); }
.fr-panel.is-warn .fr-panel-head { color: var(--fr-shadowed); }
.fr-panel.is-info { border-color: var(--fr-border); background: var(--fr-surface-2); }
.fr-panel.is-info .fr-panel-head { color: var(--fr-text-muted); }

.fr-errors { margin: 6px 0 0; padding: 0; list-style: none; }
.fr-errors li {
  display: flex; gap: 9px; align-items: flex-start;
  padding: 5px 0; border-top: 1px solid rgba(255,255,255,.05);
  font-size: 12.5px; line-height: 1.5; color: var(--fr-text-muted);
}
.fr-errors li:first-child { border-top: none; }
.fr-errors .rowno {
  flex: 0 0 auto; font-family: var(--fr-mono); font-size: 11px;
  color: var(--fr-deny); background: rgba(255,93,98,.12);
  border: 1px solid rgba(255,93,98,.35); border-radius: 5px;
  padding: 1px 6px; margin-top: 1px; white-space: nowrap;
}
.fr-errors .msg { flex: 1 1 auto; }
.fr-errors .msg code {
  font-family: var(--fr-mono); font-size: 11.5px;
  background: var(--fr-surface-3); border-radius: 4px; padding: 0 4px;
  color: var(--fr-text); word-break: break-word;
}
.fr-warnings { margin: 8px 0 0; padding-left: 16px; list-style: square; }
.fr-warnings li { font-size: 12px; color: var(--fr-text-dim); }

/* ── 5. Buttons ─────────────────────────────────────────────────────────── */
.gradio-container button.primary,
.gradio-container button.lg.primary,
.gradio-container button.primary.lg,
.gradio-container .fr-btn-primary {
  background: var(--fr-accent) !important;
  -webkit-text-fill-color: var(--fr-accent-ink) !important;
  color: var(--fr-accent-ink) !important;
  text-shadow: none !important;
  border: 1px solid #6ba3ff !important;
  font-weight: 650 !important;
  box-shadow: 0 1px 0 rgba(255,255,255,.18) inset !important;
}
.gradio-container button.primary:hover { filter: brightness(1.07); }
.gradio-container button.primary:disabled,
.gradio-container button:disabled {
  background: var(--fr-surface-3) !important;
  color: var(--fr-text-dim) !important;
  border-color: var(--fr-border) !important;
  box-shadow: none !important; cursor: not-allowed !important;
}
.gradio-container button.secondary,
.gradio-container button.lg.secondary {
  background: var(--fr-surface-2) !important;
  -webkit-text-fill-color: var(--fr-text) !important;
  color: var(--fr-text) !important;
  border: 1px solid var(--fr-border-strong) !important;
  font-weight: 600 !important;
}
.gradio-container button.secondary:hover {
  border-color: var(--fr-accent) !important; color: #fff !important;
}
.fr-btn-row { gap: 10px !important; }
.fr-btn-row button { flex: 1 1 0 !important; min-width: 0 !important; }

/* inline field errors hug the field they belong to */
.fr-fieldwrap.block { padding: 0 !important; margin: 0 !important;
                      background: transparent !important; border: none !important; }
.fr-fieldwrap.block .form { padding: 0 !important; background: transparent !important;
                            border: none !important; gap: 0 !important; }
.fr-fieldwrap.block input[type="text"] { margin-bottom: 0 !important; }
.fr-fieldwrap .fr-field-err { margin: 4px 0 12px !important; }

/* ── 6. Inputs ──────────────────────────────────────────────────────────── */
.gradio-container input[type="text"],
.gradio-container textarea,
.gradio-container .wrap-inner,
.gradio-container .secondary-wrap,
.gradio-container input[type="number"] {
  background: var(--fr-bg) !important;
  color: var(--fr-text) !important;
  border-color: var(--fr-border) !important;
  font-family: var(--fr-sans);
}
.gradio-container input[type="text"]:focus,
.gradio-container textarea:focus {
  border-color: var(--fr-accent) !important;
  box-shadow: 0 0 0 2px rgba(76,141,255,.22) !important;
}
.gradio-container .block label > span,
.gradio-container label > span,
.gradio-container .block-label {
  color: var(--fr-text-muted) !important;
  font-size: 12px !important; font-weight: 600 !important;
  letter-spacing: .01em;
}
.fr-mono input[type="text"] { font-family: var(--fr-mono) !important; font-size: 13px !important; }
.fr-mono input[type="text"]::placeholder { color: var(--fr-text-dim) !important; }
/* select / dropdown styling */
.gradio-container .wrap-inner input,
.gradio-container ul.options,
.gradio-container .options { background: var(--fr-surface-2) !important; }
.gradio-container ul.options li:hover { background: var(--fr-surface-3) !important; }

.fr-field-err {
  display: block; min-height: 0; margin-top: 5px;
  font-size: 11.5px; line-height: 1.45; color: var(--fr-deny);
  font-family: var(--fr-sans);
}
.fr-field-err:empty { display: none; }
.fr-field-err .arrow { color: var(--fr-deny); margin-right: 4px; }

/* ── 7. Segmented control (analysis tabs) ───────────────────────────────── */
.fr-segmented .wrap,
.fr-segmented > div {
  gap: 6px !important; background: transparent !important;
  border: none !important; display: flex !important; flex-wrap: wrap !important;
}
.fr-segmented label {
  background: var(--fr-surface-2) !important;
  border: 1px solid var(--fr-border) !important;
  border-radius: 999px !important;
  padding: 6px 13px !important;
  font-size: 12.5px !important; font-weight: 600 !important;
  color: var(--fr-text-muted) !important;
  transition: all .12s ease;
}
.fr-segmented label:hover { border-color: var(--fr-border-strong) !important; }
.fr-segmented label:has(input:checked),
.fr-segmented label.selected {
  background: rgba(76,141,255,.14) !important;
  border-color: var(--fr-accent) !important;
  color: #dbe8ff !important;
}
.fr-segmented input[type="radio"] { display: none !important; }
.fr-segmented label > span { color: inherit !important; font-size: 12.5px !important; }

/* ── 8. Tables (findings + policy) ──────────────────────────────────────── */
.fr-table .table-wrap,
.fr-table .table-container { border-radius: 10px !important; }
.fr-table table { border-collapse: separate !important; border-spacing: 0 !important; }
.fr-table thead th {
  background: var(--fr-surface-3) !important;
  color: var(--fr-text-muted) !important;
  font-family: var(--fr-sans) !important;
  font-size: 10.6px !important; font-weight: 700 !important;
  letter-spacing: .08em !important; text-transform: uppercase;
  border-bottom: 1px solid var(--fr-border-strong) !important;
  padding: 9px 12px !important;
  position: sticky; top: 0; z-index: 2;
}
.fr-table tbody td,
.fr-table [role="gridcell"] {
  background: transparent !important;
  color: var(--fr-text-muted) !important;
  font-size: 12.6px !important; line-height: 1.55 !important;
  border-bottom: 1px solid var(--fr-border) !important;
  border-right: 1px solid rgba(38,48,64,.55) !important;
  padding: 10px 12px !important;
  vertical-align: top !important;
}
.fr-table tbody td:last-child,
.fr-table [role="gridcell"]:last-child { border-right: none !important; }
.fr-table tbody tr:nth-child(even) td,
.fr-table [role="row"]:nth-child(even) [role="gridcell"] {
  background: rgba(255,255,255,.018) !important;
}
.fr-table tbody tr:hover td,
.fr-table [role="row"]:hover [role="gridcell"] {
  background: rgba(76,141,255,.07) !important;
}
.fr-table .cell-wrap, .fr-table .table-wrap { background: var(--fr-surface) !important; }

/* pills used inside table cells (and anywhere else) */
.fr-pill {
  display: inline-block; padding: 2px 9px; border-radius: 999px;
  font-family: var(--fr-sans); font-size: 10.4px; font-weight: 750;
  letter-spacing: .07em; text-transform: uppercase; line-height: 1.6;
  color: var(--fr-ink); border: 1px solid rgba(0,0,0,.28); white-space: nowrap;
}
.fr-pill.is-allow     { background: var(--fr-allow); }
.fr-pill.is-deny      { background: var(--fr-deny); color: #180507; }
.fr-pill.is-shadowed  { background: var(--fr-shadowed); }
.fr-pill.is-redundant { background: var(--fr-redundant); }
.fr-pill.is-conflict  { background: var(--fr-conflict); }
.fr-pill.is-overlap   { background: var(--fr-overlap); }
.fr-pill.is-muted     { background: var(--fr-surface-3); color: var(--fr-text-dim);
                        border-color: var(--fr-border-strong); }
.fr-mono-text { font-family: var(--fr-mono); font-size: 12.2px; color: var(--fr-text); }
.fr-arrow { color: var(--fr-text-dim); padding: 0 3px; }
.fr-review { color: var(--fr-text); }
.fr-review b, .fr-review strong { color: #fff; font-weight: 700; }

/* policy table specifics: numbers right, text left */
.fr-policy td:first-child, .fr-policy [role="gridcell"]:first-child {
  text-align: right !important;
}
.fr-policy td:first-child .fr-mono-text { color: var(--fr-text-muted); }

/* hidden components must not reserve space */
.fr-hidden { display: none !important; }

/* ── 9. Empty states ────────────────────────────────────────────────────── */
.fr-empty {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 14px; text-align: center;
  padding: 46px 20px 50px;
  border: 1px dashed var(--fr-border-strong); border-radius: 10px;
  background: var(--fr-surface-2);
}
.fr-empty-art { width: 168px; opacity: .55; }
.fr-empty-art .bar {
  height: 9px; border-radius: 3px; margin-bottom: 7px;
  background: linear-gradient(90deg, var(--fr-surface-3), var(--fr-border));
}
.fr-empty-art .bar:nth-child(1) { width: 100%; }
.fr-empty-art .bar:nth-child(2) { width: 78%; margin-left: 0; }
.fr-empty-art .bar:nth-child(3) { width: 90%; }
.fr-empty-art .bar:nth-child(4) { width: 62%; }
.fr-empty-title { font-size: 14px; font-weight: 650; color: var(--fr-text-muted); }
.fr-empty-sub { font-size: 12.5px; color: var(--fr-text-dim); max-width: 380px; line-height: 1.55; }

/* ── 10. Decision panel ─────────────────────────────────────────────────── */
.fr-decision {
  margin-top: 14px; border-radius: 10px; padding: 16px 18px;
  background: var(--fr-surface-2); border: 1px solid var(--fr-border);
}
.fr-decision.is-allow { border-color: rgba(45,212,167,.45); background: rgba(45,212,167,.07); }
.fr-decision.is-deny  { border-color: rgba(255,93,98,.45); background: rgba(255,93,98,.07); }
.fr-decision.is-default { border-color: rgba(245,185,66,.42); background: rgba(245,185,66,.07); }
.fr-decision.is-error { border-color: rgba(255,93,98,.45); background: rgba(255,93,98,.07); }
.fr-decision-top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.fr-verdict {
  font-family: var(--fr-sans); font-size: 15px; font-weight: 800;
  letter-spacing: .10em; text-transform: uppercase;
  padding: 5px 13px; border-radius: 7px; color: var(--fr-ink);
  border: 1px solid rgba(0,0,0,.30);
}
.fr-verdict.is-allow { background: var(--fr-allow); }
.fr-verdict.is-deny  { background: var(--fr-deny); color: #180507; }
.fr-verdict.is-default { background: var(--fr-shadowed); }
.fr-rule-chip {
  font-family: var(--fr-mono); font-size: 12px; font-weight: 650;
  color: var(--fr-text); background: var(--fr-surface-3);
  border: 1px solid var(--fr-border-strong); border-radius: 6px;
  padding: 4px 9px;
}
.fr-decision-meta {
  margin: 10px 0 0; font-size: 11.6px; font-family: var(--fr-mono);
  color: var(--fr-text-dim); letter-spacing: .01em;
}
.fr-decision-body {
  margin: 10px 0 0; font-size: 13.2px; line-height: 1.65;
  color: var(--fr-text); font-family: var(--fr-sans);
}
.fr-decision-body .mono { font-family: var(--fr-mono); color: var(--fr-text); }

/* ── 11. Rule explanation callout ───────────────────────────────────────── */
.fr-callout {
  margin-top: 12px; padding: 14px 16px 14px 18px;
  background: var(--fr-surface-2);
  border: 1px solid var(--fr-border);
  border-left: 3px solid var(--fr-overlap);
  border-radius: 8px;
  font-size: 13px; line-height: 1.68; color: var(--fr-text-muted);
}
.fr-callout-head { display: flex; align-items: center; gap: 9px; margin-bottom: 7px; }
.fr-callout-label {
  font-size: 10.6px; letter-spacing: .09em; text-transform: uppercase;
  color: var(--fr-text-dim); font-weight: 750;
}
.fr-callout .quote { color: var(--fr-border-strong); font-size: 18px; line-height: 1; }
.fr-callout .mono { font-family: var(--fr-mono); color: var(--fr-text); }

/* ── 12. Sections / accordions ──────────────────────────────────────────── */
.fr-section-head { display: flex; align-items: baseline; gap: 12px; margin: 34px 0 14px;
                    border-top: 1px solid var(--fr-border); padding-top: 20px; }
.fr-section-head h2 {
  margin: 0; font-size: 16px; font-weight: 640; color: var(--fr-text);
  letter-spacing: -.01em;
}
.fr-section-head .kicker {
  font-family: var(--fr-mono); font-size: 11px; color: var(--fr-text-dim);
  border: 1px solid var(--fr-border); border-radius: 5px; padding: 1px 7px;
}
.fr-analysis-meta {
  font-size: 12.5px; color: var(--fr-text-dim); margin: 0 0 12px;
}
.fr-analysis-meta .mono { font-family: var(--fr-mono); color: var(--fr-text-muted); }

.gradio-container .accordion {
  background: var(--fr-surface) !important;
  border: 1px solid var(--fr-border) !important;
  border-radius: var(--fr-radius) !important;
  overflow: hidden;
}
.gradio-container .accordion > .label-wrap,
.gradio-container .accordion button.label-wrap {
  background: var(--fr-surface-2) !important;
  color: var(--fr-text) !important; font-weight: 620 !important;
  padding: 12px 16px !important;
}
.gradio-container .accordion .label-wrap span { color: var(--fr-text) !important; }

/* ── 13. Footer limitations card ────────────────────────────────────────── */
.fr-footer {
  margin-top: 30px; padding: 20px 22px;
  background: var(--fr-surface); border: 1px solid var(--fr-border);
  border-radius: var(--fr-radius);
}
.fr-footer h3 {
  margin: 0 0 4px; font-size: 14px; font-weight: 650; color: var(--fr-text);
  letter-spacing: .01em;
}
.fr-footer .sub { margin: 0 0 14px; font-size: 12.2px; color: var(--fr-text-muted); }
.fr-limits { display: grid; grid-template-columns: 1fr 1fr; gap: 18px 28px; }
.fr-limits h4 {
  margin: 0 0 8px; font-size: 10.8px; letter-spacing: .09em;
  text-transform: uppercase; color: var(--fr-text-dim); font-weight: 750;
}
.fr-limits ul { margin: 0; padding: 0; list-style: none; }
.fr-limits li {
  display: flex; gap: 8px; align-items: flex-start;
  font-size: 12.6px; line-height: 1.55; color: #c3d2e4;
  padding: 3px 0;
}
.fr-limits .mark { font-family: var(--fr-mono); font-weight: 700; flex: 0 0 auto; }
.fr-limits .mark.yes { color: var(--fr-allow); }
.fr-limits .mark.no  { color: var(--fr-deny); }
.fr-footer .final {
  margin: 16px 0 0; padding-top: 13px; border-top: 1px solid var(--fr-border);
  font-size: 13px; font-weight: 750; color: var(--fr-text); letter-spacing: .01em;
}
.fr-footer .final .mono { font-family: var(--fr-mono); }

/* ── 14. Responsive: stack below ~900px ─────────────────────────────────── */
@media (max-width: 900px) {
  .fr-workspace { flex-direction: column !important; }
  .fr-workspace > .column,
  .fr-workspace > div { min-width: 100% !important; flex-basis: 100% !important; }
  .fr-limits { grid-template-columns: 1fr; }
  .fr-header { padding: 18px; }
  .fr-title { font-size: 21px; }
  .fr-chip { font-size: 11px; }
}
"""

#: Theme variables, applied to both the light and dark slots so the console
#: looks identical whatever the browser's colour-scheme preference is. These are
#: what Gradio actually uses to paint panels, inputs, buttons and tables; the
#: CSS string above then refines structure and the custom components.
_TOKENS: dict[str, str] = {
    "body_background_fill": "#0e1116",
    "body_text_color": "#e8eef7",
    "body_text_color_subdued": "#9fb0c4",
    "background_fill_primary": "#151a21",
    "background_fill_secondary": "#1a2029",
    "block_background_fill": "#151a21",
    "block_border_color": "#263040",
    "block_border_width": "1px",
    "block_label_background_fill": "#1a2029",
    "block_label_border_color": "#263040",
    "block_label_text_color": "#cbd8e8",
    "block_title_background_fill": "#1a2029",
    "block_title_text_color": "#e8eef7",
    "block_info_text_color": "#8395a9",
    "block_shadow": "none",
    "panel_background_fill": "#151a21",
    "panel_border_color": "#263040",
    "panel_border_width": "1px",
    "border_color_primary": "#263040",
    "border_color_accent": "#4c8dff",
    "border_color_accent_subdued": "#2b3a52",
    "color_accent": "#4c8dff",
    "color_accent_soft": "#1b2740",
    "input_background_fill": "#0e1116",
    "input_background_fill_focus": "#111722",
    "input_background_fill_hover": "#111722",
    "input_border_color": "#263040",
    "input_border_color_focus": "#4c8dff",
    "input_border_color_hover": "#3a475d",
    "input_placeholder_color": "#8395a9",
    "input_shadow": "none",
    "input_shadow_focus": "0 0 0 2px rgba(76,141,255,.20)",
    "button_primary_background_fill": "#4c8dff",
    "button_primary_background_fill_hover": "#6ba3ff",
    "button_primary_text_color": "#06101f",
    "button_primary_text_color_hover": "#06101f",
    "button_primary_border_color": "#6ba3ff",
    "button_primary_border_color_hover": "#8bb8ff",
    "button_primary_shadow": "0 1px 0 rgba(255,255,255,.18) inset",
    "button_primary_shadow_hover": "0 1px 0 rgba(255,255,255,.22) inset",
    "button_secondary_background_fill": "#1a2029",
    "button_secondary_background_fill_hover": "#202836",
    "button_secondary_text_color": "#e8eef7",
    "button_secondary_text_color_hover": "#ffffff",
    "button_secondary_border_color": "#3a475d",
    "button_secondary_border_color_hover": "#4c8dff",
    "button_secondary_shadow": "none",
    "table_text_color": "#c3d2e4",
    "table_border_color": "#263040",
    "table_even_background_fill": "#151a21",
    "table_odd_background_fill": "#171d26",
    "table_row_focus": "#1b2740",
    "checkbox_background_color": "#0e1116",
    "checkbox_background_color_selected": "#4c8dff",
    "checkbox_border_color": "#3a475d",
    "checkbox_border_color_selected": "#4c8dff",
    "checkbox_label_background_fill": "#1a2029",
    "checkbox_label_background_fill_hover": "#202836",
    "checkbox_label_background_fill_selected": "#1b2740",
    "checkbox_label_border_color": "#263040",
    "checkbox_label_border_color_selected": "#4c8dff",
    "checkbox_label_text_color": "#9fb0c4",
    "checkbox_label_text_color_selected": "#dbe8ff",
    "slider_color": "#4c8dff",
    "loader_color": "#4c8dff",
    "link_text_color": "#7fb0ff",
    "link_text_color_hover": "#a8c8ff",
    "link_text_color_visited": "#b39cff",
    "shadow_drop": "none",
    "shadow_drop_lg": "none",
}

def _theme_kwargs() -> dict[str, str]:
    """Mirror each token into the ``*_dark`` slot when Gradio exposes one.

    Not every theme variable has a dark variant, so the valid parameter names
    are read from ``Base.set`` instead of being assumed.
    """
    import inspect

    valid = set(inspect.signature(gr.themes.Base().set).parameters)
    kwargs: dict[str, str] = {}
    for key, value in _TOKENS.items():
        if key in valid:
            kwargs[key] = value
        dark_key = f"{key}_dark"
        if dark_key in valid:
            kwargs[dark_key] = value
    return kwargs


THEME = gr.themes.Base(
    font=["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto",
          "Helvetica Neue", "Arial", "sans-serif"],
    font_mono=["ui-monospace", "SFMono-Regular", "SF Mono", "Menlo", "Consolas",
               "Liberation Mono", "monospace"],
    radius_size=gr.themes.sizes.radius_md,
    spacing_size=gr.themes.sizes.spacing_md,
    text_size=gr.themes.sizes.text_md,
).set(**_theme_kwargs())


# ---------------------------------------------------------------------------
# HTML helpers — formatting only, no policy logic
# ---------------------------------------------------------------------------
def esc(text: Any) -> str:
    """Escape text for safe interpolation into an HTML string."""
    return html_module.escape(str(text), quote=True)


def pill(text: str, tone: str) -> str:
    """A coloured pill. Always carries its own label, so colour is never the
    only signal."""
    return f'<span class="fr-pill is-{tone}">{esc(text)}</span>'


def mono(text: Any) -> str:
    return f'<span class="fr-mono-text">{esc(text)}</span>'


def _style_block() -> str:
    """Inject the palette early so styling never depends on launch kwargs.

    ``gr.Blocks(css=...)`` was removed in Gradio 6 (it now belongs to
    ``launch``), and a notebook may call ``demo.launch()`` directly, so the
    stylesheet ships inside the app itself.
    """
    return f"<style>{CSS}</style>"


def header_html(state: str = "empty", count: int = 0) -> str:
    """Header band with the live status badge on the right.

    ``state`` is one of ``empty`` / ``loaded`` / ``error``.
    """
    if state == "loaded":
        badge_cls, badge_text = "is-loaded", f"Policy loaded: {count} rules"
    elif state == "error":
        badge_cls, badge_text = "is-error", f"Validation errors: {count}"
    else:
        badge_cls, badge_text = "is-empty", "No policy loaded"

    return f"""
<div class="fr-header">
  <div class="fr-header-main">
    <h1 class="fr-title">Firewall Rule Analysis System</h1>
    <p class="fr-subtitle">
      Policy audit tool<span class="sep">|</span>Does not enforce traffic
      <span class="sep">|</span><span class="never">read-only analysis</span>
    </p>
  </div>
  <div class="fr-badge {badge_cls}" role="status" aria-live="polite">
    <span class="dot" aria-hidden="true"></span>{esc(badge_text)}
  </div>
</div>
"""


def card_head_html(step: int, title: str, subtitle: str) -> str:
    return f"""
<div class="fr-card-head">
  <span class="fr-step" aria-hidden="true">{step}</span>
  <div>
    <h3 class="fr-card-title">{esc(title)}</h3>
    <p class="fr-card-sub">{esc(subtitle)}</p>
  </div>
</div>
"""


def columns_helper_html() -> str:
    chips = "".join(f'<span class="fr-chip">{esc(name)}</span>'
                    for name in POLICY_COLUMNS)
    return f"""
<div>
  <div class="fr-chips-label">Required columns, in this order</div>
  <div class="fr-chips">{chips}</div>
</div>
"""


def hint_html(text: str) -> str:
    return f'<div class="fr-hint">{text}</div>'


def empty_analysis_html(message: str = "No analysis yet. Load a policy to begin.",
                        sub: str = "Upload a policy CSV or load the built-in sample "
                                   "policy, and the overlap, shadowing, redundancy "
                                   "and conflict findings appear here.") -> str:
    """Icon-free empty state: a CSS skeleton of a table plus a message."""
    return f"""
<div class="fr-empty">
  <div class="fr-empty-art" aria-hidden="true">
    <div class="bar"></div><div class="bar"></div>
    <div class="bar"></div><div class="bar"></div>
  </div>
  <div class="fr-empty-title">{esc(message)}</div>
  <div class="fr-empty-sub">{esc(sub)}</div>
</div>
"""


def empty_decision_html() -> str:
    return (
        '<div class="fr-decision is-info">'
        '<div class="fr-decision-top">'
        '<span class="fr-verdict" style="background:var(--fr-surface-3);'
        'color:var(--fr-text-dim)">No packet yet</span>'
        "</div>"
        '<p class="fr-decision-body">Load a policy, then enter a packet to see '
        "the decision.</p>"
        "</div>"
    )


def _split_row_prefix(message: str) -> tuple[str, str]:
    """Turn ``row 4: source: 'x' is invalid`` into ``("row 4", "source: 'x' …")``.

    Purely cosmetic: validation already produced the full sentence, this only
    lifts the line number into its own monospace chip.
    """
    text = str(message)
    if text.lower().startswith("row "):
        head, _, tail = text.partition(":")
        if tail:
            return head.strip(), tail.strip()
    if text.lower().startswith("rows "):
        head, _, tail = text.partition(":")
        if tail:
            return head.strip(), tail.strip()
    return "", text


def upload_ok_html(result: Any, origin: str) -> str:
    """Green confirmation line for a validated policy."""
    warnings = ""
    if getattr(result, "warnings", None):
        items = "".join(f"<li>{esc(warning)}</li>" for warning in result.warnings)
        warnings = f'<ul class="fr-warnings">{items}</ul>'
    return f"""
<div class="fr-panel is-ok">
  <div class="fr-panel-head"><span aria-hidden="true">&#10003;</span>
    Policy valid &mdash; {esc(origin)}</div>
  <div><strong>{len(result.policy)}</strong> rules accepted, validated and analysed.</div>
  {warnings}
</div>
"""


def upload_error_html(errors: Sequence[str], origin: str = "uploaded file") -> str:
    """Red panel listing every error with its row number in monospace."""
    items = []
    for error in errors:
        rowno, message = _split_row_prefix(error)
        badge = f'<span class="rowno">{esc(rowno)}</span>' if rowno else ""
        items.append(f'<li>{badge}<span class="msg">{esc(message)}</span></li>')
    return f"""
<div class="fr-panel is-err">
  <div class="fr-panel-head"><span aria-hidden="true">&#10007;</span>
    {len(errors)} validation problem(s) &mdash; nothing was analysed</div>
  <div>{esc(origin)} could not be loaded. Fix these rows and try again:</div>
  <ul class="fr-errors">{''.join(items)}</ul>
</div>
"""


def upload_warning_html(message: str, detail: str) -> str:
    return f"""
<div class="fr-panel is-warn">
  <div class="fr-panel-head"><span aria-hidden="true">!</span>{esc(message)}</div>
  <div>{esc(detail)}</div>
</div>
"""


def analysis_meta_html(origin: str, counts: dict[str, int]) -> str:
    return (
        f'<p class="fr-analysis-meta">Analysed <span class="mono">{esc(origin)}</span>'
        f' &middot; <span class="mono">{counts["rules"]}</span> rules &middot; '
        f'default action <span class="mono">{DEFAULT_ACTION.upper()}</span> when no '
        "rule matches</p>"
    )


def decision_html(decision: Any, total_rules: int) -> str:
    """Render a MatchResult as the decision panel."""
    packet = (
        f'<p class="fr-decision-meta">{esc(decision.packet.source)}'
        f' &rarr; {esc(decision.packet.destination)}:'
        f'{esc(decision.packet.port)}/{esc(decision.packet.protocol)}'
        f' &nbsp;&middot;&nbsp; {decision.rules_evaluated} of {total_rules} rules '
        "evaluated</p>"
    )
    if decision.is_default:
        return f"""
<div class="fr-decision is-default">
  <div class="fr-decision-top">
    <span class="fr-verdict is-default">No match &mdash; default deny</span>
    <span class="fr-rule-chip">no rule matched</span>
  </div>
  {packet}
  <p class="fr-decision-body">{esc(decision.explanation)}</p>
</div>
"""
    tone = "is-allow" if decision.action == "allow" else "is-deny"
    return f"""
<div class="fr-decision {tone}">
  <div class="fr-decision-top">
    <span class="fr-verdict {tone}">{esc(decision.action)}</span>
    <span class="fr-rule-chip">Rule {decision.rule.order}</span>
  </div>
  {packet}
  <p class="fr-decision-body">{esc(decision.explanation)}</p>
</div>
"""


def decision_error_html(message: str) -> str:
    return f"""
<div class="fr-decision is-error">
  <div class="fr-decision-top">
    <span class="fr-verdict is-deny">Invalid input</span>
  </div>
  <p class="fr-decision-body">{esc(message)}</p>
</div>
"""


def field_error_html(message: str) -> str:
    if not message:
        return '<span class="fr-field-err"></span>'
    return f'<span class="fr-field-err"><span class="arrow">&rarr;</span>{esc(message)}</span>'


def callout_html(body: str) -> str:
    return (
        '<div class="fr-callout"><span class="quote" aria-hidden="true">&ldquo;</span> '
        f"{body}</div>"
    )


# ---------------------------------------------------------------------------
# Dataframe builders (engine objects -> display frames)
# ---------------------------------------------------------------------------
def _empty_findings_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=FINDING_COLUMNS)


def _empty_policy_frame() -> pd.DataFrame:
    return pd.DataFrame(columns=POLICY_DISPLAY_COLUMNS)


def _normalise_finding(row: dict[str, Any]) -> dict[str, str]:
    """Map any engine finding row onto the four display columns.

    ``AnalysisResult.findings()`` returns two shapes: shadowed / redundant /
    conflict rows carry ``Rules`` already, while overlap rows carry ``Rule A``
    and ``Rule B`` separately. Normalising here keeps the engine's structures
    untouched while giving the table one consistent set of columns.
    """
    rules = row.get("Rules")
    if not rules:
        rule_a, rule_b = row.get("Rule A", "?"), row.get("Rule B", "?")
        rules = f"{rule_a} vs {rule_b}"
    return {
        "Category": str(row.get("Category", "")),
        "Rules": str(rules),
        "Explanation": str(row.get("Explanation", "")),
        "Suggested review action": str(row.get("Suggested review action", "")),
    }


def findings_frame(findings: list[dict[str, Any]], category: str) -> pd.DataFrame:
    """Filter the engine's findings and render each column for display.

    Only formatting happens here: the category becomes a pill, the rule numbers
    a monospace pair, and the first sentence of the suggested action is bolded.
    """
    if not findings:
        return _empty_findings_frame()
    wanted = CATEGORY_MAP.get(category)
    rows = [
        _normalise_finding(row)
        for row in findings
        if wanted is None or row.get("Category") == wanted
    ]
    if not rows:
        return _empty_findings_frame()

    rendered = []
    for row in rows:
        category_name = row["Category"]
        tone = PILL_TONE.get(category_name, "muted")
        word = CATEGORY_WORD.get(category_name, category_name)
        rules = esc(row["Rules"]).replace(" vs ", '<span class="fr-arrow">vs</span>')
        rules = rules.replace(" (by ", ' <span class="fr-arrow">&rarr;</span> ')
        suggestion = _bold_first_sentence(row["Suggested review action"])
        rendered.append([
            pill(word, tone),
            f'<span class="fr-mono-text">{rules}</span>',
            esc(row["Explanation"]),
            suggestion,
        ])
    return pd.DataFrame(rendered, columns=FINDING_COLUMNS)


def _bold_first_sentence(text: str) -> str:
    """Bold the first sentence of a suggestion, escape the rest."""
    cleaned = str(text)
    cut = cleaned.find(". ")
    if cut == -1:
        return f'<span class="fr-review"><b>{esc(cleaned.rstrip("."))}</b>.</span>'
    first, rest = cleaned[: cut + 1], cleaned[cut + 2:]
    return (f'<span class="fr-review"><b>{esc(first)}</b> {esc(rest)}</span>')


def policy_frame(policy: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Render the validated policy with monospace scope cells and action pills."""
    if policy is None or getattr(policy, "empty", True):
        return _empty_policy_frame()
    rendered = []
    for row in policy.loc[:, POLICY_DISPLAY_COLUMNS].itertuples(index=False):
        action = str(row.action)
        tone = "allow" if action == "allow" else "deny"
        rendered.append([
            mono(row.order),
            mono(row.source) if row.source != "0.0.0.0/0" else mono("any"),
            mono(row.destination) if row.destination != "0.0.0.0/0" else mono("any"),
            mono(row.port),
            mono(row.protocol),
            pill(action.upper(), tone),
        ])
    return pd.DataFrame(rendered, columns=POLICY_DISPLAY_COLUMNS)


def category_choices(counts: Optional[dict[str, int]],
                     total_findings: Optional[int] = None) -> list[tuple[str, str]]:
    """Segmented-control choices with count badges, e.g. ``Shadowed (3)``.

    ``All findings`` counts the rows the table actually shows (the engine's
    flattened findings list), while each tab counts its own category.
    """
    if not counts:
        return [(label, value) for value, (label, _) in CATEGORY_META.items()]
    choices: list[tuple[str, str]] = []
    for value, (label, key) in CATEGORY_META.items():
        if value == CATEGORY_ALL:
            count = total_findings if total_findings is not None else 0
        else:
            count = counts.get(key, 0) or 0
        choices.append((f"{label} ({count})", value))
    return choices


def rule_choices(policy: Optional[pd.DataFrame]) -> list[tuple[str, int]]:
    if policy is None or getattr(policy, "empty", True):
        return []
    return [(f"Rule {int(order)}", int(order))
            for order in policy["order"].tolist()]


# ---------------------------------------------------------------------------
# Event handlers — same names as before, all delegating to the engine
# ---------------------------------------------------------------------------
load_policy_source: Callable[..., dict[str, Any]]


def _load_updates(
    *,
    header: str,
    upload_panel: str,
    policy_table: pd.DataFrame,
    findings_table: pd.DataFrame,
    findings_empty: str,
    findings_empty_visible: bool,
    policy_state: Any,
    category_update: Any,
    rule_update: Any,
    simulate_button: Any,
    simulate_hint: str,
    accordion: Any,
    decision: str,
    explanation: str,
) -> dict[str, Any]:
    return {
        "header": header,
        "upload_panel": upload_panel,
        "policy_table": policy_table,
        "findings_table": gr.update(value=findings_table,
                                    visible=not findings_empty_visible),
        "findings_empty": gr.update(value=findings_empty,
                                    visible=findings_empty_visible),
        "policy_state": policy_state,
        "category_filter": category_update,
        "rule_dropdown": rule_update,
        "simulate_button": simulate_button,
        "simulate_hint": simulate_hint,
        "policy_accordion": accordion,
        "decision_panel": decision,
        "explanation_panel": explanation,
    }


def _reset_updates(header: str, upload_panel: str) -> dict[str, Any]:
    """Everything the app shows when no policy is loaded."""
    return _load_updates(
        header=header,
        upload_panel=upload_panel,
        policy_table=_empty_policy_frame(),
        findings_table=_empty_findings_frame(),
        findings_empty=empty_analysis_html(),
        findings_empty_visible=True,
        policy_state=None,
        category_update=gr.update(
            choices=category_choices(None), value=CATEGORY_ALL, interactive=False
        ),
        rule_update=gr.update(choices=[], value=None, interactive=False),
        simulate_button=gr.update(interactive=False),
        simulate_hint=hint_html(
            "<span>Load a policy first &mdash; simulation is disabled until the "
            "rule set validates.</span>"
        ),
        accordion=gr.update(open=False),
        decision=empty_decision_html(),
        explanation='<div class="fr-hint">Choose a rule after loading a policy '
                    "to read its plain-English explanation.</div>",
    )


def load_policy_source(source: Any, origin: str,
                       category: str = CATEGORY_ALL) -> dict[str, Any]:  # noqa: F811
    """Validate + analyse a CSV source and refresh every policy view.

    Shared by the uploader and the "load sample" button, so both paths behave
    identically. Validation and analysis are the engine's; this function only
    decides what the panels display.
    """
    try:
        result = load_and_validate(source)
    except Exception as exc:  # pragma: no cover - defensive
        updates = _reset_updates(
            header_html("empty"),
            upload_error_html([f"unexpected problem while reading the file: {exc}"]),
        )
        updates["header"] = header_html("error", 1)
        return updates

    if not result.ok:
        updates = _reset_updates(
            header_html("error", len(result.errors)),
            upload_error_html(result.errors, origin),
        )
        return updates

    analysis = analyse_policy(result.policy)
    counts = analysis.summary()
    return _load_updates(
        header=header_html("loaded", len(result.policy)),
        upload_panel=upload_ok_html(result, origin),
        policy_table=policy_frame(result.policy),
        findings_table=findings_frame(analysis.findings(), CATEGORY_ALL),
        findings_empty=empty_analysis_html(),
        findings_empty_visible=False,
        policy_state=result.policy,
        category_update=gr.update(
            choices=category_choices(counts, len(analysis.findings())),
            value=CATEGORY_ALL,
            interactive=True,
        ),
        rule_update=gr.update(
            choices=rule_choices(result.policy),
            value=(rule_choices(result.policy)[0][1] if len(result.policy) else None),
            interactive=True,
        ),
        simulate_button=gr.update(interactive=True),
        simulate_hint=hint_html(
            f"<span>First match wins. If nothing matches, the documented default "
            f"action <span class='key'>{DEFAULT_ACTION.upper()}</span> applies.</span>"
        ),
        accordion=gr.update(open=True),
        decision=(
            '<div class="fr-decision is-info"><div class="fr-decision-top">'
            '<span class="fr-verdict" style="background:var(--fr-surface-3);'
            'color:var(--fr-text-dim)">Ready</span></div>'
            '<p class="fr-decision-body">Enter a packet and press '
            "<strong>Simulate packet</strong> to see the first-match decision."
            "</p></div>"
        ),
        explanation='<div class="fr-hint">Choose a rule above and press '
                    "<strong>Explain rule</strong>.</div>",
    )


def handle_upload(file_bytes: Any) -> dict[str, Any]:
    """Handler for the CSV uploader (also covers empty / non-CSV / Excel)."""
    if file_bytes is None:
        updates = _reset_updates(
            header_html("empty"),
            upload_warning_html(
                "No file selected",
                "Choose a .csv file above, or click “Load built-in sample "
                "policy” to explore the app with the 14-rule demo policy.",
            ),
        )
        return updates
    return load_policy_source(file_bytes, "uploaded file")


def handle_load_sample(category: str = CATEGORY_ALL) -> dict[str, Any]:
    """Handler for the built-in sample policy button."""
    return load_policy_source(SAMPLE_POLICY_CSV, "built-in sample policy", category)


def handle_filter(policy: Optional[pd.DataFrame], category: str) -> dict[str, Any]:
    """Re-render the findings table for a different segmented-control tab."""
    if policy is None or getattr(policy, "empty", True):
        return {
            "findings_table": gr.update(value=_empty_findings_frame(),
                                        visible=False),
            "findings_empty": gr.update(
                value=empty_analysis_html(), visible=True
            ),
        }
    analysis = analyse_policy(policy)
    frame = findings_frame(analysis.findings(), category)
    if frame.empty:
        return {
            "findings_table": gr.update(value=_empty_findings_frame(),
                                        visible=False),
            "findings_empty": gr.update(
                value=empty_analysis_html(
                    "No issues found in this category.",
                    "This category is clean for the loaded policy. Switch tabs to "
                    "review the other finding types.",
                ),
                visible=True,
            ),
        }
    return {
        "findings_table": gr.update(value=frame, visible=True),
        "findings_empty": gr.update(value=empty_analysis_html(), visible=False),
    }


def _field_errors(source: Any, destination: Any, port: Any) -> dict[str, str]:
    """Attribute a validation message to the field that caused it.

    The check itself is the engine's own :func:`parse_packet` — each field is
    substituted into an otherwise valid baseline packet, so the only possible
    error is about that field. No validation rules are re-implemented here.
    """
    errors = {"source": "", "destination": "", "port": ""}
    for field in errors:
        candidate = dict(_BASELINE_PACKET)
        candidate[field] = {"source": source, "destination": destination,
                            "port": port}[field]
        try:
            parse_packet(**candidate)
        except ValueError as exc:
            message = str(exc)
            if field == "port" and message.lower().startswith("port: "):
                message = message[len("port: "):]
            errors[field] = message
    return errors


def handle_simulate(
    policy: Optional[pd.DataFrame],
    source: str,
    destination: str,
    port: Any,
    protocol: str,
) -> dict[str, Any]:
    """Run one packet through the policy and render the decision panel."""
    if policy is None or getattr(policy, "empty", True):
        return {
            "decision_panel": decision_error_html(
                "No policy is loaded. Load a policy CSV (or the built-in sample) "
                "before simulating a packet."
            ),
            "source_error": field_error_html(""),
            "destination_error": field_error_html(""),
            "port_error": field_error_html(""),
        }

    errors = _field_errors(source, destination, port)
    if any(errors.values()):
        first = next(message for message in errors.values() if message)
        return {
            "decision_panel": decision_error_html(first),
            "source_error": field_error_html(errors["source"]),
            "destination_error": field_error_html(errors["destination"]),
            "port_error": field_error_html(errors["port"]),
        }

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
    except ValueError as exc:  # defensive: engine messages are UI-safe
        return {
            "decision_panel": decision_error_html(str(exc)),
            "source_error": field_error_html(""),
            "destination_error": field_error_html(""),
            "port_error": field_error_html(""),
        }

    return {
        "decision_panel": decision_html(decision, len(policy)),
        "source_error": field_error_html(""),
        "destination_error": field_error_html(""),
        "port_error": field_error_html(""),
    }


def handle_preset(label: Optional[str]) -> dict[str, Any]:
    """Fill the simulator inputs from an example packet (no analysis run)."""
    for preset in SAMPLE_PACKETS:
        if preset["label"] == label:
            return {
                "source": preset["source"],
                "destination": preset["destination"],
                "port": str(preset["port"]),
                "protocol": preset["protocol"],
            }
    return {
        "source": gr.update(),
        "destination": gr.update(),
        "port": gr.update(),
        "protocol": gr.update(),
    }


def handle_explain_rule(policy: Optional[pd.DataFrame], order: Any) -> str:
    """Render the plain-English explanation for one rule in a callout."""
    if policy is None or getattr(policy, "empty", True) or order in (None, ""):
        return ('<div class="fr-hint">Choose a rule after loading a policy to read '
                "its plain-English explanation.</div>")
    try:
        body = esc(explain_rule(policy, int(order)))
    except (KeyError, ValueError, TypeError) as exc:
        return f'<div class="fr-panel is-err"><div class="fr-panel-head">' \
               f"Could not explain that rule</div>{esc(exc)}</div>"
    heading = (f'<div class="fr-callout-head"><span class="fr-rule-chip">Rule '
               f'{int(order)}</span><span class="fr-callout-label">plain-English '
               "explanation</span></div>")
    return callout_html(heading + body)


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
#: Component keys the load handlers write to, in a stable order.
LOAD_OUTPUTS = (
    "header",
    "upload_panel",
    "policy_table",
    "findings_table",
    "findings_empty",
    "policy_state",
    "category_filter",
    "rule_dropdown",
    "simulate_button",
    "simulate_hint",
    "policy_accordion",
    "decision_panel",
    "explanation_panel",
)


def _adapt(names: Sequence[str], fn: Callable[..., dict[str, Any]]) -> Callable[..., tuple]:
    """Wrap a dict-returning handler into a Gradio positional output tuple."""

    def wrapped(*args: Any) -> tuple:
        updates = fn(*args)
        return tuple(updates.get(name) for name in names)

    return wrapped


def footer_html() -> str:
    modeled = [
        "Ordered first-match evaluation",
        "IPv4 CIDR source / destination",
        "Port ranges and port <span class='mono'>any</span>",
        "Protocol filtering (tcp / udp / icmp)",
        "Documented default action when nothing matches",
    ]
    not_modeled = [
        "IPv6 (rejected by validation)",
        "Stateful connection tracking",
        "NAT / address translation",
        "Time-based and rate-based rules",
        "Interfaces, zones and directions",
        "Vendor-specific behaviour",
    ]
    yes = "".join(f'<li><span class="mark yes">&#10003;</span><span>{item}</span></li>'
                  for item in modeled)
    no = "".join(f'<li><span class="mark no">&#10007;</span><span>{item}</span></li>'
                 for item in not_modeled)
    return f"""
<div class="fr-footer">
  <h3>Simplified semantics and limits</h3>
  <p class="sub">What this engine does and does not reason about. Analysis is
    exact inside the modelled scope and silent outside it.</p>
  <div class="fr-limits">
    <div>
      <h4>Modeled</h4>
      <ul>{yes}</ul>
    </div>
    <div>
      <h4>Not modeled</h4>
      <ul>{no}</ul>
    </div>
  </div>
  <p class="final">This tool audits the policy file and never enforces traffic.</p>
</div>
"""


def build_app() -> gr.Blocks:
    """Construct the redesigned Gradio app and wire every control to the engine."""
    preset_labels = [preset["label"] for preset in SAMPLE_PACKETS]

    import warnings as _warnings

    with _warnings.catch_warnings():
        # Gradio 6 moved css/theme to launch(); passing the theme here keeps a
        # bare demo.launch() from the notebook styled as well.
        _warnings.filterwarnings("ignore", message=".*moved from the Blocks constructor.*")
        blocks_cm = gr.Blocks(title="Firewall Rule Analysis System", theme=THEME)

    with blocks_cm as demo:
        gr.HTML(_style_block(), elem_id="fr-style")

        policy_state = gr.State(None)
        header = gr.HTML(header_html("empty"))

        # ── 1 + 2: workspace ────────────────────────────────────────────────
        with gr.Row(equal_height=False, elem_classes=["fr-workspace"]):
            # ---------------- Step 1: load policy ----------------
            with gr.Column(scale=1, min_width=320):
                with gr.Group(elem_classes=["fr-card"]):
                    gr.HTML(card_head_html(
                        1, "Load policy",
                        "Upload an ordered firewall policy CSV, or start from the "
                        "built-in sample.",
                    ))
                    policy_file = gr.File(
                        label="",
                        show_label=False,
                        file_types=[".csv", ".txt"],
                        type="binary",
                        height=132,
                        elem_classes=["fr-upload"],
                    )
                    gr.HTML(columns_helper_html())
                    with gr.Row(elem_classes=["fr-btn-row"]):
                        upload_button = gr.Button(
                            "Validate uploaded CSV", variant="primary", scale=1,
                            min_width=0,
                        )
                        sample_button = gr.Button(
                            "Load built-in sample policy", variant="secondary",
                            scale=1, min_width=0,
                        )
                    upload_panel = gr.HTML(
                        '<div class="fr-panel is-info"><div class="fr-panel-head">'
                        "No policy loaded</div>Upload a CSV or load the sample "
                        "policy to begin the audit.</div>"
                    )


            # ---------------- Step 2: simulate ----------------
            with gr.Column(scale=1, min_width=320):
                with gr.Group(elem_classes=["fr-card"]):
                    gr.HTML(card_head_html(
                        2, "Simulate a packet",
                        "Walk a synthetic packet through the policy with "
                        "first-match semantics.",
                    ))
                    preset_dropdown = gr.Dropdown(
                        choices=preset_labels,
                        value=None,
                        label="Example packet",
                        info="Choose an example or enter values manually",
                        elem_classes=["fr-preset"],
                    )
                    with gr.Row():
                        with gr.Column(min_width=0, elem_classes=["fr-fieldwrap"]):
                            source_input = gr.Textbox(
                                label="Source IP", value="", placeholder="10.1.2.3",
                                elem_classes=["fr-mono"],
                            )
                            source_error = gr.HTML(field_error_html(""))
                        with gr.Column(min_width=0, elem_classes=["fr-fieldwrap"]):
                            destination_input = gr.Textbox(
                                label="Destination IP", value="",
                                placeholder="10.9.9.5", elem_classes=["fr-mono"],
                            )
                            destination_error = gr.HTML(field_error_html(""))
                    with gr.Row():
                        with gr.Column(min_width=0, elem_classes=["fr-fieldwrap"]):
                            port_input = gr.Textbox(
                                label="Port", value="", placeholder="443",
                                elem_classes=["fr-mono"],
                            )
                            port_error = gr.HTML(field_error_html(""))
                        with gr.Column(min_width=0):
                            protocol_input = gr.Dropdown(
                                choices=["tcp", "udp", "icmp"],
                                value="tcp",
                                label="Protocol",
                                allow_custom_value=False,
                            )
                    simulate_button = gr.Button(
                        "Simulate packet", variant="primary",
                        interactive=False, elem_classes=["fr-btn-primary"],
                    )
                    simulate_hint = gr.HTML(hint_html(
                        "<span>Load a policy first &mdash; simulation is disabled "
                        "until the rule set validates.</span>"
                    ))
                    decision_panel = gr.HTML(empty_decision_html())

        # ── 3: analysis ─────────────────────────────────────────────────────
        gr.HTML(
            '<div class="fr-section-head"><h2>Overlap, shadowing and redundancy '
            'analysis</h2><span class="kicker">step 3</span></div>'
        )
        category_filter = gr.Radio(
            choices=category_choices(None),
            value=CATEGORY_ALL,
            label="",
            show_label=False,
            interactive=False,
            elem_classes=["fr-segmented"],
        )
        findings_empty = gr.HTML(empty_analysis_html(), visible=True)
        findings_table = gr.Dataframe(
            value=_empty_findings_frame(),
            headers=FINDING_COLUMNS,
            datatype=["html", "html", "str", "html"],
            type="pandas",
            label="Findings and suggested review actions",
            show_label=False,
            interactive=False,
            wrap=True,
            max_height=None,
            show_search="none",
            elem_classes=["fr-table", "fr-findings"],
            column_widths=["13%", "11%", "44%", "32%"],
            visible=False,
        )

        # ── 4: validated policy table (full width) ──────────────────────────
        gr.HTML(
            '<div class="fr-section-head"><h2>Validated policy table</h2>'
            '<span class="kicker">step 4</span></div>'
        )
        policy_accordion = gr.Accordion(
            "Show the 6 policy columns in evaluation order",
            open=False,
            elem_classes=["fr-table-wrap"],
        )
        with policy_accordion:
            policy_table = gr.Dataframe(
                value=_empty_policy_frame(),
                headers=POLICY_DISPLAY_COLUMNS,
                datatype=["html"] * len(POLICY_DISPLAY_COLUMNS),
                type="pandas",
                label="Rules in evaluation order",
                show_label=False,
                interactive=False,
                wrap=False,
                max_height=None,
                show_search="none",
                elem_classes=["fr-table", "fr-policy"],
                column_widths=["10%", "24%", "24%", "12%", "14%", "12%"],
            )

        # ── 5: explain a rule ───────────────────────────────────────────────
        gr.HTML(
            '<div class="fr-section-head"><h2>Explain a rule</h2>'
            '<span class="kicker">step 5</span></div>'
        )
        with gr.Row(elem_classes=["fr-btn-row"]):
            rule_dropdown = gr.Dropdown(
                choices=[], value=None, label="Rule", interactive=False, scale=3,
                min_width=0,
            )
            explain_button = gr.Button("Explain rule", variant="secondary", scale=1,
                                       min_width=0)
        explanation_panel = gr.HTML(
            '<div class="fr-hint">Choose a rule after loading a policy to read its '
            "plain-English explanation.</div>"
        )

        # ── footer ──────────────────────────────────────────────────────────
        gr.HTML(footer_html())

        # ── wiring ──────────────────────────────────────────────────────────
        components: dict[str, Any] = {
            "header": header,
            "upload_panel": upload_panel,
            "policy_table": policy_table,
            "findings_table": findings_table,
            "findings_empty": findings_empty,
            "policy_state": policy_state,
            "category_filter": category_filter,
            "rule_dropdown": rule_dropdown,
            "simulate_button": simulate_button,
            "simulate_hint": simulate_hint,
            "policy_accordion": policy_accordion,
            "decision_panel": decision_panel,
            "explanation_panel": explanation_panel,
        }

        load_outputs = [components[name] for name in LOAD_OUTPUTS]
        upload_button.click(
            _adapt(LOAD_OUTPUTS, handle_upload),
            inputs=[policy_file],
            outputs=load_outputs,
            show_progress="full",
        )
        policy_file.upload(
            _adapt(LOAD_OUTPUTS, handle_upload),
            inputs=[policy_file],
            outputs=load_outputs,
            show_progress="full",
        )
        sample_button.click(
            _adapt(LOAD_OUTPUTS, handle_load_sample),
            inputs=[category_filter],
            outputs=load_outputs,
            show_progress="full",
        )
        category_filter.change(
            _adapt(["findings_table", "findings_empty"], handle_filter),
            inputs=[policy_state, category_filter],
            outputs=[findings_table, findings_empty],
            show_progress="minimal",
        )
        simulate_button.click(
            _adapt(["decision_panel", "source_error", "destination_error",
                    "port_error"], handle_simulate),
            inputs=[policy_state, source_input, destination_input, port_input,
                    protocol_input],
            outputs=[decision_panel, source_error, destination_error, port_error],
            show_progress="minimal",
        )
        preset_dropdown.change(
            _adapt(["source", "destination", "port", "protocol"], handle_preset),
            inputs=[preset_dropdown],
            outputs=[source_input, destination_input, port_input, protocol_input],
            show_progress="hidden",
        )
        explain_button.click(
            _adapt(["explanation_panel"], lambda policy, order: {
                "explanation_panel": handle_explain_rule(policy, order)}),
            inputs=[policy_state, rule_dropdown],
            outputs=[explanation_panel],
            show_progress="minimal",
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

    ``server_name="0.0.0.0"`` keeps the app reachable from outside the
    container (hosted notebooks and the Arena preview). The stylesheet is
    injected by the app itself, so launching with plain ``demo.launch()`` gets
    the same look; it is also passed to ``launch`` for Gradio 6, where ``css``
    moved from ``Blocks`` to ``launch``.
    """
    demo = build_app()
    demo.queue()
    launch_kwargs: dict[str, Any] = {
        "server_name": server_name,
        "server_port": server_port,
        "share": share,
        "inline": inline,
        "show_error": True,
        "css": CSS,
        "theme": THEME,
    }
    launch_kwargs.update(kwargs)
    demo.launch(**launch_kwargs)
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
