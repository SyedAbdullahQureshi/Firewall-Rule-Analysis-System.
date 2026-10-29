"""Firewall Rule Analysis System — audit library for ordered firewall policy files.

This package audits firewall *policy files*. It never touches real network
traffic: there is no packet capture, no iptables/nftables/Netfilter interaction
and no vendor API integration. Everything is a static analysis of an ordered
list of rules.

Public surface
--------------
``firewall_rules.sample_policy``
    The built-in sample policy (14 rules) plus :func:`sample_policy_path` and
    :func:`sample_policy_dataframe`.
``firewall_rules.validation``
    ``load_policy`` / ``validate_policy`` / ``load_and_validate`` and the small
    parsers (``parse_cidr``, ``parse_port_spec``) shared with the engine.
``firewall_rules.engine``
    First-match packet simulation, overlap / shadowing / redundancy / conflict
    detection, and plain-English explanations.
``firewall_rules.ui``
    The Gradio app. It only calls engine functions and never re-implements
    analysis logic.
"""

from .validation import (
    ALLOWED_ACTIONS,
    ALLOWED_PROTOCOLS,
    LoadResult,
    POLICY_COLUMNS,
    ValidationResult,
    load_and_validate,
    load_policy,
    parse_cidr,
    parse_port_spec,
    validate_policy,
)
from .engine import (
    DEFAULT_ACTION,
    AnalysisResult,
    MatchResult,
    Packet,
    Policy,
    analyse_policy,
    compile_policy,
    explain_packet_decision,
    explain_rule,
    find_conflicts,
    find_overlaps,
    find_redundant,
    find_shadowed,
    match_packet,
    parse_packet,
)
from .sample_policy import (
    SAMPLE_POLICY_CSV,
    sample_policy_dataframe,
    sample_policy_path,
    write_sample_policy,
)

__all__ = [
    "ALLOWED_ACTIONS",
    "ALLOWED_PROTOCOLS",
    "AnalysisResult",
    "DEFAULT_ACTION",
    "LoadResult",
    "MatchResult",
    "POLICY_COLUMNS",
    "Packet",
    "Policy",
    "SAMPLE_POLICY_CSV",
    "ValidationResult",
    "analyse_policy",
    "compile_policy",
    "explain_packet_decision",
    "explain_rule",
    "find_conflicts",
    "find_overlaps",
    "find_redundant",
    "find_shadowed",
    "load_and_validate",
    "load_policy",
    "match_packet",
    "parse_cidr",
    "parse_packet",
    "parse_port_spec",
    "sample_policy_dataframe",
    "sample_policy_path",
    "validate_policy",
    "write_sample_policy",
]

__version__ = "1.0.0"
