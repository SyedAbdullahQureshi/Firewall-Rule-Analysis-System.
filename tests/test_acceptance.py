"""Acceptance tests for the Firewall Rule Analysis System (Phase 4).

Run directly::

    python -m unittest discover -s tests -v

or via the notebook, which also turns the ``RECORDS`` collected here into the
markdown test-case table.

Every test records what it actually observed through :func:`record`, so the
table in the report is generated from the same run that proves the assertions —
there is no second, hand-written copy of the results.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall_rules.engine import (  # noqa: E402
    DEFAULT_ACTION,
    analyse_policy,
    compile_policy,
    explain_packet_decision,
    explain_policy,
    explain_rule,
    find_conflicts,
    find_overlaps,
    find_redundant,
    find_shadowed,
    match_packet,
    parse_packet,
)
from firewall_rules.sample_policy import SAMPLE_POLICY_CSV  # noqa: E402
from firewall_rules.validation import (  # noqa: E402
    POLICY_COLUMNS,
    load_and_validate,
    load_policy,
    validate_policy,
)

#: Observed result per case id, filled in while the tests run.
RECORDS: dict[str, str] = {}

#: Case metadata used to build the markdown test-case table.
CASES: list[dict[str, str]] = [
    {
        "id": "T01",
        "method": "test_T01_allow_before_deny",
        "description": "Allow above an overlapping deny: the allow wins",
        "input": "Rule 1 allow 10.0.0.0/8 -> any 443/tcp; rule 2 deny any -> any 443/tcp. "
                 "Packet 10.1.2.3 -> 8.8.8.8:443/tcp",
        "expected": "action = allow, matched rule 1",
    },
    {
        "id": "T02",
        "method": "test_T02_deny_before_allow",
        "description": "Deny above an overlapping allow: the deny wins",
        "input": "Same two rules with the order swapped (deny first). "
                 "Packet 10.1.2.3 -> 8.8.8.8:443/tcp",
        "expected": "action = deny, matched rule 1",
    },
    {
        "id": "T03",
        "method": "test_T03_wildcard_scopes",
        "description": "Wildcard scopes 0.0.0.0/0, port any and protocol any match",
        "input": "Rule 0.0.0.0/0 -> 0.0.0.0/0, port any, protocol any, allow. "
                 "Packets 8.8.8.8 -> 1.1.1.1:5353/udp and 203.0.113.9 -> 10.0.0.1:443/tcp",
        "expected": "both packets match the rule and are allowed",
    },
    {
        "id": "T04",
        "method": "test_T04_invalid_cidr",
        "description": "Invalid CIDR notation is rejected with a clear error",
        "input": "Rows with source = 10.0.0.0/33, 256.1.1.1/24 and abc",
        "expected": "3 errors naming rows 2, 3 and 4 with an IPv4 CIDR message",
    },
    {
        "id": "T05",
        "method": "test_T05_shadowing",
        "description": "A fully covered later rule is flagged as shadowed",
        "input": "Built-in sample policy (rule 3 sits under rule 1)",
        "expected": "rule 3 reported shadowed by rule 1",
    },
    {
        "id": "T06",
        "method": "test_T06_redundancy",
        "description": "A duplicate rule is flagged as redundant",
        "input": "Built-in sample policy (rule 10 duplicates rule 9)",
        "expected": "rule 10 reported redundant, duplicate of rule 9",
    },
    {
        "id": "T07",
        "method": "test_T07_first_match",
        "description": "The first matching rule is returned, not a later one",
        "input": "Rule 1 allow 10.0.0.0/8 443/tcp; rule 2 allow any 443/tcp. "
                 "Packet 10.1.2.3 -> 8.8.8.8:443/tcp",
        "expected": "matched rule 1 and only 1 rule evaluated",
    },
    {
        "id": "T08",
        "method": "test_T08_no_match_default",
        "description": "No match applies the documented default action",
        "input": "Sample policy, packet 8.8.8.8 -> 1.1.1.1:5353/udp",
        "expected": "action = deny (default), rule = None, is_default = True",
    },
    {
        "id": "T09",
        "method": "test_T09_invalid_ports",
        "description": "Out-of-range, inverted and non-numeric ports are rejected",
        "input": "port = 70000, 2000-1000, abc",
        "expected": "3 errors with range and malformed-range messages",
    },
    {
        "id": "T10",
        "method": "test_T10_invalid_protocol_action",
        "description": "Unknown protocol and action values are rejected",
        "input": "protocol = sctp, action = permit",
        "expected": "2 errors naming the allowed values",
    },
    {
        "id": "T11",
        "method": "test_T11_invalid_order",
        "description": "Duplicate and non-integer order values are rejected",
        "input": "order column = 1, 1, two",
        "expected": "duplicate-order error plus a non-integer error",
    },
    {
        "id": "T12",
        "method": "test_T12_missing_columns",
        "description": "A policy with missing columns is rejected, not crashed on",
        "input": "CSV header order,source,destination,port,protocol",
        "expected": "error listing the missing 'action' column",
    },
    {
        "id": "T13",
        "method": "test_T13_bad_files",
        "description": "Empty, non-CSV and Excel uploads fail gracefully",
        "input": "b'' ; 'name,team\\nalice,sec' ; b'PK\\x03\\x04...'",
        "expected": "one clear error each, no exception raised",
    },
    {
        "id": "T14",
        "method": "test_T14_overlap_detection",
        "description": "Overlap detection finds intersecting pairs only",
        "input": "Sample policy",
        "expected": "pair (5,6) overlaps; pair (3,5) does not",
    },
    {
        "id": "T15",
        "method": "test_T15_conflicts",
        "description": "Conflicts name the earlier rule as the winner",
        "input": "Sample policy pair 5/6 (allow/deny) and 7/8 (deny/allow)",
        "expected": "5 wins over 6; 7 wins over 8",
    },
    {
        "id": "T16",
        "method": "test_T16_packet_input_validation",
        "description": "Invalid simulator input is rejected with a UI-safe message",
        "input": "source 10.0.0.0/8; port 99999; protocol any",
        "expected": "ValueError for each with an explanatory message",
    },
    {
        "id": "T17",
        "method": "test_T17_normalisation",
        "description": "Valid but untidy input is normalised and sorted by order",
        "input": "Rows out of order, protocol 'TCP', host bits set, extra column",
        "expected": "sorted by order, lowercased, CIDR masked, extra column warned",
    },
    {
        "id": "T18",
        "method": "test_T18_end_to_end",
        "description": "The full pipeline feeds the UI tables without crashing",
        "input": "Sample CSV bytes through load_and_validate + analyse_policy",
        "expected": "findings frame with the 4 UI columns and non-zero rows",
    },
]


def record(case_id: str, actual: str) -> None:
    """Store the observed result for the test-case table."""
    RECORDS[case_id] = actual


def _policy(*rows: tuple) -> pd.DataFrame:
    """Build a policy DataFrame from tuples in column order."""
    return pd.DataFrame(list(rows), columns=list(POLICY_COLUMNS), dtype=str)


class AcceptanceTests(unittest.TestCase):
    """The eight required acceptance tests plus ten supporting checks."""

    # -- 1. ordering ------------------------------------------------------
    def test_T01_allow_before_deny(self) -> None:
        policy = _policy(
            ("1", "10.0.0.0/8", "0.0.0.0/0", "443", "tcp", "allow"),
            ("2", "0.0.0.0/0", "0.0.0.0/0", "443", "tcp", "deny"),
        )
        result = match_packet(policy, {
            "source": "10.1.2.3", "destination": "8.8.8.8",
            "port": "443", "protocol": "tcp",
        })
        record("T01", f"action = {result.action}, matched rule {result.rule.order}")
        self.assertEqual("allow", result.action)
        self.assertEqual(1, result.rule.order)
        self.assertFalse(result.is_default)

    def test_T02_deny_before_allow(self) -> None:
        policy = _policy(
            ("1", "0.0.0.0/0", "0.0.0.0/0", "443", "tcp", "deny"),
            ("2", "10.0.0.0/8", "0.0.0.0/0", "443", "tcp", "allow"),
        )
        result = match_packet(policy, {
            "source": "10.1.2.3", "destination": "8.8.8.8",
            "port": "443", "protocol": "tcp",
        })
        record("T02", f"action = {result.action}, matched rule {result.rule.order}")
        self.assertEqual("deny", result.action)
        self.assertEqual(1, result.rule.order)

    # -- 2. wildcards -----------------------------------------------------
    def test_T03_wildcard_scopes(self) -> None:
        policy = _policy(("1", "0.0.0.0/0", "0.0.0.0/0", "any", "any", "allow"))
        first = match_packet(policy, {
            "source": "8.8.8.8", "destination": "1.1.1.1",
            "port": "5353", "protocol": "udp",
        })
        second = match_packet(policy, {
            "source": "203.0.113.9", "destination": "10.0.0.1",
            "port": "443", "protocol": "tcp",
        })
        record("T03", f"udp/5353 -> {first.action} rule {first.rule.order}; "
                      f"tcp/443 -> {second.action} rule {second.rule.order}")
        for result in (first, second):
            self.assertEqual("allow", result.action)
            self.assertEqual(1, result.rule.order)
            self.assertFalse(result.is_default)

    # -- 3. validation ----------------------------------------------------
    def test_T04_invalid_cidr(self) -> None:
        policy = _policy(
            ("1", "10.0.0.0/33", "0.0.0.0/0", "443", "tcp", "allow"),
            ("2", "256.1.1.1/24", "0.0.0.0/0", "443", "tcp", "allow"),
            ("3", "abc", "0.0.0.0/0", "443", "tcp", "allow"),
        )
        result = validate_policy(policy)
        joined = " | ".join(result.errors)
        record("T04", f"{len(result.errors)} errors: {joined[:160]}")
        self.assertFalse(result.ok)
        self.assertIsNone(result.policy)
        self.assertEqual(3, len(result.errors))
        for line, error in zip((2, 3, 4), result.errors):
            self.assertIn(f"row {line}: source", error)
            self.assertIn("IPv4 CIDR", error)
        self.assertIn("/33", joined)
        self.assertIn("256.1.1.1", joined)

    def test_T09_invalid_ports(self) -> None:
        policy = _policy(
            ("1", "10.0.0.0/8", "0.0.0.0/0", "70000", "tcp", "allow"),
            ("2", "10.0.0.0/8", "0.0.0.0/0", "2000-1000", "tcp", "allow"),
            ("3", "10.0.0.0/8", "0.0.0.0/0", "abc", "tcp", "allow"),
        )
        result = validate_policy(policy)
        record("T09", f"{len(result.errors)} errors: " + " | ".join(result.errors)[:160])
        self.assertFalse(result.ok)
        self.assertEqual(3, len(result.errors))
        self.assertIn("outside the valid range 0-65535", result.errors[0])
        self.assertIn("inverted", result.errors[1])
        self.assertIn("not a valid port", result.errors[2])

    def test_T10_invalid_protocol_action(self) -> None:
        policy = _policy(
            ("1", "10.0.0.0/8", "0.0.0.0/0", "443", "sctp", "allow"),
            ("2", "10.0.0.0/8", "0.0.0.0/0", "443", "tcp", "permit"),
        )
        result = validate_policy(policy)
        record("T10", " | ".join(result.errors))
        self.assertFalse(result.ok)
        self.assertIn("protocol", result.errors[0])
        self.assertIn("tcp, udp, icmp, any", result.errors[0])
        self.assertIn("action", result.errors[1])
        self.assertIn("allow, deny", result.errors[1])

    def test_T11_invalid_order(self) -> None:
        policy = _policy(
            ("1", "10.0.0.0/8", "0.0.0.0/0", "443", "tcp", "allow"),
            ("1", "10.1.0.0/16", "0.0.0.0/0", "80", "tcp", "allow"),
            ("two", "10.2.0.0/16", "0.0.0.0/0", "80", "tcp", "allow"),
        )
        result = validate_policy(policy)
        joined = " | ".join(result.errors)
        record("T11", joined)
        self.assertFalse(result.ok)
        self.assertIn("duplicate order value 1", joined)
        self.assertIn("not an integer", joined)

    def test_T12_missing_columns(self) -> None:
        csv_text = "order,source,destination,port,protocol\n1,10.0.0.0/8,0.0.0.0/0,443,tcp\n"
        result = load_and_validate(csv_text.encode("utf-8"))
        record("T12", " | ".join(result.errors))
        self.assertFalse(result.ok)
        self.assertTrue(
            any("missing required column(s): action" in error for error in result.errors)
        )

    def test_T13_bad_files(self) -> None:
        empty = load_and_validate(b"")
        not_csv = load_and_validate(b"name,team\nalice,sec\nbob,ops\n")
        excel = load_and_validate(b"PK\x03\x04" + b"\x00" * 64)
        header_only = load_and_validate(b"order,source,destination,port,protocol,action\n")
        record(
            "T13",
            f"empty -> {empty.errors[0][:40]!r}; not-csv -> {not_csv.errors[0][:40]!r}; "
            f"excel -> {excel.errors[0][:40]!r}; header-only -> {header_only.errors[0][:40]!r}",
        )
        self.assertFalse(empty.ok)
        self.assertFalse(not_csv.ok)
        self.assertFalse(excel.ok)
        self.assertFalse(header_only.ok)
        self.assertIn("empty", empty.errors[0].lower())
        self.assertIn("missing required column", " ".join(not_csv.errors))
        self.assertIn("Excel", excel.errors[0])
        self.assertIn("no rule rows", header_only.errors[0])

    # -- 4. analysis ------------------------------------------------------
    def test_T05_shadowing(self) -> None:
        result = load_and_validate(SAMPLE_POLICY_CSV)
        self.assertTrue(result.ok, result.errors)
        shadowed = {item.rule.order: item for item in find_shadowed(result.policy)}
        record(
            "T05",
            "shadowed rules "
            + ", ".join(str(order) for order in sorted(shadowed))
            + (" (rule 3 by rule 1)" if 3 in shadowed else ""),
        )
        self.assertIn(3, shadowed)
        self.assertEqual([1], [rule.order for rule in shadowed[3].shadowed_by])
        self.assertIn("shadowed by rule 1", shadowed[3].suggested_action())

    def test_T06_redundancy(self) -> None:
        result = load_and_validate(SAMPLE_POLICY_CSV)
        redundant = {item.rule.order: item for item in find_redundant(result.policy)}
        record(
            "T06",
            "redundant rules "
            + ", ".join(f"{order} ({item.kind})" for order, item in sorted(redundant.items())),
        )
        self.assertIn(10, redundant)
        self.assertEqual("duplicate", redundant[10].kind)
        self.assertEqual([9], [rule.order for rule in redundant[10].redundant_with])

    def test_T07_first_match(self) -> None:
        policy = _policy(
            ("1", "10.0.0.0/8", "0.0.0.0/0", "443", "tcp", "allow"),
            ("2", "0.0.0.0/0", "0.0.0.0/0", "443", "tcp", "allow"),
        )
        result = match_packet(policy, {
            "source": "10.1.2.3", "destination": "8.8.8.8",
            "port": "443", "protocol": "tcp",
        })
        record("T07", f"matched rule {result.rule.order}, "
                      f"{result.rules_evaluated} rule(s) evaluated")
        self.assertEqual(1, result.rule.order)
        self.assertEqual(1, result.rules_evaluated)

    def test_T08_no_match_default(self) -> None:
        result = load_and_validate(SAMPLE_POLICY_CSV)
        decision = match_packet(result.policy, {
            "source": "8.8.8.8", "destination": "1.1.1.1",
            "port": "5353", "protocol": "udp",
        })
        record(
            "T08",
            f"action = {decision.action} (default), rule = {decision.rule}, "
            f"is_default = {decision.is_default}",
        )
        self.assertEqual("deny", DEFAULT_ACTION)
        self.assertEqual(DEFAULT_ACTION, decision.action)
        self.assertIsNone(decision.rule)
        self.assertTrue(decision.is_default)
        self.assertIn("DEFAULT ACTION", decision.explanation)
        self.assertEqual(len(result.policy), decision.rules_evaluated)

    def test_T14_overlap_detection(self) -> None:
        result = load_and_validate(SAMPLE_POLICY_CSV)
        pairs = {(item.a.order, item.b.order) for item in find_overlaps(result.policy)}
        record("T14", f"{len(pairs)} overlapping pairs, e.g. {sorted(pairs)[:6]}")
        self.assertIn((5, 6), pairs)
        self.assertIn((7, 8), pairs)
        self.assertNotIn((3, 5), pairs)
        self.assertNotIn((4, 5), pairs)
        self.assertNotIn((5, 7), pairs)

    def test_T15_conflicts(self) -> None:
        result = load_and_validate(SAMPLE_POLICY_CSV)
        conflicts = {(item.winner.order, item.loser.order) for item in find_conflicts(result.policy)}
        record("T15", f"{len(conflicts)} conflicting pairs, including (5,6) and (7,8)")
        self.assertIn((5, 6), conflicts)
        self.assertIn((7, 8), conflicts)
        self.assertNotIn((5, 8), conflicts)  # same action, so not a conflict

    # -- 5. input handling ------------------------------------------------
    def test_T16_packet_input_validation(self) -> None:
        messages: list[str] = []
        for kwargs in (
            {"source": "10.0.0.0/8", "destination": "10.0.0.1", "port": "443", "protocol": "tcp"},
            {"source": "10.0.0.1", "destination": "10.0.0.2", "port": "99999", "protocol": "tcp"},
            {"source": "10.0.0.1", "destination": "10.0.0.2", "port": "443", "protocol": "any"},
            {"source": "not-an-ip", "destination": "10.0.0.2", "port": "443", "protocol": "tcp"},
        ):
            with self.assertRaises(ValueError) as context:
                parse_packet(**kwargs)
            messages.append(str(context.exception))
        record("T16", " | ".join(message[:52] for message in messages))
        self.assertIn("CIDR", messages[0])
        self.assertIn("outside the valid range", messages[1])
        self.assertIn("'any' describes a rule", messages[2])
        self.assertIn("not a valid IPv4 address", messages[3])

    def test_T17_normalisation(self) -> None:
        csv_text = (
            "order,source,destination,port,protocol,action,comment\n"
            "2,10.1.2.3/8,0.0.0.0/0,443,TCP,Allow,second\n"
            "1,10.2.0.0/16,0.0.0.0/0,any,Any,DENY,first\n"
        )
        result = load_and_validate(csv_text.encode("utf-8"))
        self.assertTrue(result.ok, result.errors)
        orders = result.policy["order"].tolist()
        sources = result.policy["source"].tolist()
        record(
            "T17",
            f"orders {orders}, source {sources[1]}, protocol "
            f"{result.policy['protocol'].tolist()}, warning about 'comment' column",
        )
        self.assertEqual([1, 2], orders)
        self.assertEqual("10.0.0.0/8", sources[1])
        self.assertEqual(["any", "tcp"], result.policy["protocol"].tolist())
        self.assertEqual(["deny", "allow"], result.policy["action"].tolist())
        self.assertTrue(any("comment" in warning for warning in result.warnings))

    def test_T18_end_to_end(self) -> None:
        validation = load_and_validate(SAMPLE_POLICY_CSV.encode("utf-8"))
        analysis = analyse_policy(validation.policy)
        frame = analysis.findings_frame()
        explanation = explain_packet_decision(
            validation.policy,
            {"source": "10.1.2.3", "destination": "10.9.9.5",
             "port": "3306", "protocol": "tcp"},
        )
        rule_text = explain_rule(validation.policy, 3)
        summary = explain_policy(validation.policy)
        record(
            "T18",
            f"findings frame {frame.shape[0]}x{frame.shape[1]}, "
            f"summary '{summary[:60]}...'",
        )
        self.assertTrue(validation.ok)
        self.assertEqual(
            ["Category", "Rules", "Explanation", "Suggested review action"],
            frame.columns.tolist(),
        )
        self.assertGreater(len(frame), 5)
        self.assertIn("rule 1", explanation)
        self.assertIn("shadowed by rule 1", rule_text)
        self.assertIn("default DENY", summary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
