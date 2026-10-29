"""Analysis engine for the Firewall Rule Analysis System (Phase 2).

No UI code lives here. The Gradio layer calls these functions and renders what
they return, so the same logic is exercised by the notebook, the automated tests
and the app.

Simplified semantics (all documented assumptions)
-------------------------------------------------
The engine models a **static, ordered, single-device IPv4 packet filter**:

1. **First match wins.** Rules are evaluated in ascending ``order``; the first
   rule whose source, destination, port and protocol all match decides the
   packet. Nothing after it is evaluated.
2. **Default action.** If no rule matches, the packet is **DENY**ed
   (:data:`DEFAULT_ACTION`). This is a *default-deny* posture, the common
   hardening baseline; a real policy that ends in ``allow any`` would express
   that intent as an explicit last rule instead. The value is a module constant
   and is repeated in every explanation that uses it, so the assumption is
   never hidden.
3. **Single interface.** Zones, interfaces, directions (in/out/forward) and
   VRFs are not modelled; a rule is a filter on a 4-tuple, not on a path.
4. **No connection tracking.** There is no ``established``/``related`` state.
   Return traffic must be permitted by its own rule. A rule therefore applies
   to every packet equally, not just the first packet of a flow.
5. **No NAT.** Addresses are compared as written. Pre-NAT and post-NAT address
   spaces are not distinguished, and no rule is rewritten by a translation.
6. **No time-based rules.** No schedules, no rate limits, no quotas, no
   counters.
7. **IPv4 only.** IPv6 CIDRs are rejected by validation.
8. **A port dimension applies to every protocol.** Real ICMP has no ports; a
   rule with ``protocol=icmp`` should therefore use ``port=any`` (all sample
   ICMP rules do). The engine still evaluates the port field uniformly so that
   overlap maths stays symmetric; a packet's "port" for ICMP is simply a value
   that must be supplied by the caller.
9. **Rules are independent.** No rule inherits or negates another, no groups,
   no negated addresses, no "except" clauses, no vendor-specific implicit
   services. ``0.0.0.0/0`` means "every IPv4 address" and nothing else.
10. **Ordering is explicit.** The file's line order is irrelevant after
    validation; only the ``order`` integer counts.
11. **Analysis is over-approximate where stated.** Overlap/shadow detection is
    exact for the 4-tuple model. Redundancy is checked against *single* earlier
    rules (a rule covered only by the union of several earlier rules is not
    flagged) — see :func:`find_redundant`.
12. **Audit only.** The engine reads a policy file and reports on it. It never
    programs a firewall, never sees live traffic, and never enforces anything.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional, Sequence, Union

import pandas as pd

from .validation import (
    POLICY_COLUMNS,
    PortRange,
    PolicyFieldError,
    parse_action,
    parse_cidr,
    parse_port_spec,
    parse_protocol,
    validate_policy,
)

#: Action taken when no rule matches. Documented, and used verbatim by
#: :func:`match_packet` and every explanation that mentions a default.
DEFAULT_ACTION: str = "deny"

_ANY_CIDR = "0.0.0.0/0"


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Packet:
    """A simulated packet.

    Attributes
    ----------
    source, destination:
        IPv4 addresses (single hosts; CIDRs are not accepted as packets).
    port:
        Destination port, 0-65535. Required even for ICMP because the port
        dimension is modelled uniformly (assumption 8 in the module docstring).
    protocol:
        ``tcp``, ``udp``, ``icmp`` or ``any``.
    """

    source: str
    destination: str
    port: int
    protocol: str

    def label(self) -> str:
        """Compact human label, e.g. ``10.1.2.3:3306/tcp -> 10.9.9.5``."""
        return f"{self.source}:{self.port}/{self.protocol} -> {self.destination}"


@dataclass(frozen=True)
class Rule:
    """One validated policy rule, with its scope pre-parsed.

    ``source``/``destination``/``port`` keep the user's original strings for
    display; ``src_net``/``dst_net``/``port_range`` hold the parsed forms used
    for matching and overlap maths.
    """

    order: int
    source: str
    destination: str
    port: str
    protocol: str
    action: str
    src_net: ipaddress.IPv4Network
    dst_net: ipaddress.IPv4Network
    port_range: PortRange

    # -- display helpers ---------------------------------------------------
    @property
    def allow(self) -> bool:
        return self.action == "allow"

    def label(self) -> str:
        """``rule 1 (allow 10.0.0.0/8 to any, any port, any protocol)``."""
        return f"rule {self.order} ({self.action} {self.scope_text()})"

    def scope_text(self) -> str:
        source = "any" if self.source == _ANY_CIDR else self.source
        destination = "any" if self.destination == _ANY_CIDR else self.destination
        port = "any port" if self.port_range.is_any else f"port {self.port}"
        return f"{source} to {destination}, {port}, {self.protocol} protocol"

    def as_row(self) -> dict[str, Any]:
        """The rule as it appears in the original CSV columns."""
        return {
            "order": self.order,
            "source": self.source,
            "destination": self.destination,
            "port": self.port,
            "protocol": self.protocol,
            "action": self.action,
        }

    # -- scope predicates --------------------------------------------------
    def covers_source(self, other: "Rule") -> bool:
        return _network_covers(self.src_net, other.src_net)

    def covers_destination(self, other: "Rule") -> bool:
        return _network_covers(self.dst_net, other.dst_net)

    def covers_port(self, other: "Rule") -> bool:
        return self.port_range.covers(other.port_range)

    def covers_protocol(self, other: "Rule") -> bool:
        return self.protocol == "any" or self.protocol == other.protocol

    def covers(self, other: "Rule") -> bool:
        """True when every packet matching ``other`` also matches ``self``."""
        return (
            self.covers_source(other)
            and self.covers_destination(other)
            and self.covers_port(other)
            and self.covers_protocol(other)
        )

    def overlaps_source(self, other: "Rule") -> bool:
        return _network_overlaps(self.src_net, other.src_net)

    def overlaps_destination(self, other: "Rule") -> bool:
        return _network_overlaps(self.dst_net, other.dst_net)

    def overlaps_port(self, other: "Rule") -> bool:
        return self.port_range.overlaps(other.port_range)

    def overlaps_protocol(self, other: "Rule") -> bool:
        return (
            self.protocol == "any"
            or other.protocol == "any"
            or self.protocol == other.protocol
        )

    def overlaps(self, other: "Rule") -> bool:
        """True when at least one packet can match both rules."""
        return (
            self.overlaps_source(other)
            and self.overlaps_destination(other)
            and self.overlaps_port(other)
            and self.overlaps_protocol(other)
        )

    def matches(self, packet: Packet) -> bool:
        """True when ``packet`` falls inside this rule's scope."""
        return (
            ipaddress.ip_address(packet.source) in self.src_net
            and ipaddress.ip_address(packet.destination) in self.dst_net
            and self.port_range.contains(packet.port)
            and (self.protocol == "any" or self.protocol == packet.protocol)
        )


@dataclass
class Policy:
    """A compiled, ordered policy: a list of :class:`Rule` plus its DataFrame."""

    rules: list[Rule] = field(default_factory=list)
    dataframe: Optional[pd.DataFrame] = None

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def get(self, order: int) -> Rule:
        """Return the rule with this ``order`` value; raises ``KeyError``."""
        for rule in self.rules:
            if rule.order == order:
                return rule
        raise KeyError(f"no rule with order {order}")

    def as_frame(self) -> pd.DataFrame:
        """The policy as a DataFrame in the original six columns."""
        return pd.DataFrame([rule.as_row() for rule in self.rules],
                            columns=list(POLICY_COLUMNS))


@dataclass
class MatchResult:
    """Result of :func:`match_packet`.

    ``rule`` is the first matching :class:`Rule` or ``None``. ``action`` is
    always set. ``is_default`` is True only when nothing matched and
    :data:`DEFAULT_ACTION` was applied.
    """

    packet: Packet
    rule: Optional[Rule]
    action: str
    is_default: bool
    rules_evaluated: int
    explanation: str
    shadowed_overlaps: list[Rule] = field(default_factory=list)


@dataclass
class Overlap:
    """Two rules whose four scope dimensions all intersect."""

    a: Rule
    b: Rule
    same_action: bool

    def as_dict(self) -> dict[str, str]:
        return {
            "Rule A": self.a.order,
            "Rule B": self.b.order,
            "Overlapping scope": self.a.scope_text(),
            "Actions": f"{self.a.action} / {self.b.action}",
            "Explanation": self.explanation(),
            "Suggested review action": self.suggested_action(),
        }

    def explanation(self) -> str:
        relation = (
            f"rule {self.a.order} fully covers rule {self.b.order}"
            if self.a.covers(self.b)
            else f"rule {self.b.order} fully covers rule {self.a.order}"
            if self.b.covers(self.a)
            else "the scopes partially overlap"
        )
        effect = (
            "both rules have the same action, so no packet outcome depends on order"
            if self.same_action
            else "the actions differ, so which rule comes first decides the outcome"
        )
        return (
            f"Rule {self.a.order} and rule {self.b.order} can match the same "
            f"traffic because their source, destination, port and protocol "
            f"scopes intersect; {relation}, and {effect}."
        )

    def suggested_action(self) -> str:
        if self.same_action:
            return (
                f"Optional tidy-up: rules {self.a.order} and {self.b.order} share "
                "an action, so the overlap is harmless; consider merging them."
            )
        return (
            f"Confirm the order of rules {self.a.order} and {self.b.order} is "
            f"intended; rule {min(self.a.order, self.b.order)} wins for the "
            "overlapping traffic."
        )


@dataclass
class Shadowed:
    """A rule that can never be the first match."""

    rule: Rule
    shadowed_by: list[Rule]

    def as_dict(self) -> dict[str, str]:
        orders = ", ".join(str(r.order) for r in self.shadowed_by)
        return {
            "Category": "Shadowed rule",
            "Rules": f"{self.rule.order} (by {orders})",
            "Explanation": self.explanation(),
            "Suggested review action": self.suggested_action(),
        }

    def explanation(self) -> str:
        orders = ", ".join(str(r.order) for r in self.shadowed_by)
        actions = {r.action for r in self.shadowed_by}
        effect = (
            "so removing it would not change any packet outcome"
            if actions == {self.rule.action}
            else "so its intended action never takes effect"
        )
        return (
            f"Rule {self.rule.order} ({self.rule.action} {self.rule.scope_text()}) "
            f"is fully shadowed by rule {orders}: every packet it describes is "
            f"matched earlier, {effect}."
        )

    def suggested_action(self) -> str:
        orders = ", ".join(str(r.order) for r in self.shadowed_by)
        extra = (
            ""
            if {r.action for r in self.shadowed_by} == {self.rule.action}
            else " If the tighter scope was meant to be reachable, move it above "
            f"rule {self.shadowed_by[0].order}."
        )
        return f"Remove rule {self.rule.order}, it is fully shadowed by rule {orders}.{extra}"


@dataclass
class Redundant:
    """A rule whose removal would not change any packet outcome."""

    rule: Rule
    redundant_with: list[Rule]
    kind: str  # "duplicate" or "covered"

    def as_dict(self) -> dict[str, str]:
        orders = ", ".join(str(r.order) for r in self.redundant_with)
        return {
            "Category": "Redundant rule",
            "Rules": f"{self.rule.order} (with {orders})",
            "Explanation": self.explanation(),
            "Suggested review action": self.suggested_action(),
        }

    def explanation(self) -> str:
        orders = ", ".join(str(r.order) for r in self.redundant_with)
        if self.kind == "duplicate":
            return (
                f"Rule {self.rule.order} is an exact duplicate of rule {orders} "
                "(same source, destination, port, protocol and action), so it can "
                "never change an outcome and only adds maintenance risk."
            )
        return (
            f"Rule {self.rule.order} ({self.rule.action}) is fully covered by rule "
            f"{orders} with the same action, so no packet's outcome depends on it."
        )

    def suggested_action(self) -> str:
        orders = ", ".join(str(r.order) for r in self.redundant_with)
        if self.kind == "duplicate":
            return f"Remove the duplicate, rule {self.rule.order} (identical to rule {orders})."
        return (
            f"Remove rule {self.rule.order}; rule {orders} already produces the "
            "same result for every packet."
        )


@dataclass
class Conflict:
    """Two overlapping rules with different actions; order decides the winner."""

    winner: Rule
    loser: Rule

    def as_dict(self) -> dict[str, str]:
        return {
            "Category": "Conflict",
            "Rules": f"{self.winner.order} vs {self.loser.order}",
            "Explanation": self.explanation(),
            "Suggested review action": self.suggested_action(),
        }

    def explanation(self) -> str:
        return (
            f"Rules {self.winner.order} ({self.winner.action}) and "
            f"{self.loser.order} ({self.loser.action}) overlap but disagree. "
            f"Rule {self.winner.order} wins because first-match evaluation "
            f"stops at order {self.winner.order}, before order "
            f"{self.loser.order} is ever considered; rule {self.loser.order} "
            "applies only to the part of its scope not already matched."
        )

    def suggested_action(self) -> str:
        return (
            f"Confirm the order of rules {self.winner.order} and "
            f"{self.loser.order} is intended "
            f"({self.winner.action} currently wins for the shared traffic)."
        )


@dataclass
class AnalysisResult:
    """Everything the auditor found, in four separate buckets."""

    policy: Policy
    overlaps: list[Overlap] = field(default_factory=list)
    shadowed: list[Shadowed] = field(default_factory=list)
    redundant: list[Redundant] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)

    # -- aggregate views ---------------------------------------------------
    def findings(self) -> list[dict[str, Any]]:
        """One flat list of findings for the UI table.

        Order is: shadowed, redundant, conflicts, then remaining overlaps,
        which puts the most actionable items first.
        """
        rows: list[dict[str, Any]] = []
        rows.extend(item.as_dict() for item in self.shadowed)
        rows.extend(item.as_dict() for item in self.redundant)
        rows.extend(item.as_dict() for item in self.conflicts)
        shadow_pairs = {
            (item.rule.order, min(r.order for r in item.shadowed_by))
            for item in self.shadowed
        }
        for overlap in self.overlaps:
            pair = (overlap.b.order, overlap.a.order)
            if pair in shadow_pairs:
                continue  # already reported as shadowing, avoid a duplicate row
            row = overlap.as_dict()
            row = {"Category": "Overlap", **row}
            rows.append(row)
        return rows

    def findings_frame(self) -> pd.DataFrame:
        """The findings as a DataFrame with stable columns (empty-safe)."""
        columns = ["Category", "Rules", "Explanation", "Suggested review action"]
        rows = self.findings()
        if not rows:
            return pd.DataFrame(columns=columns)
        return pd.DataFrame(rows, columns=columns)

    def summary(self) -> dict[str, int]:
        """Counts used for the one-line headline in the app."""
        return {
            "rules": len(self.policy),
            "overlaps": len(self.overlaps),
            "shadowed": len(self.shadowed),
            "redundant": len(self.redundant),
            "conflicts": len(self.conflicts),
        }


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _network_covers(
    outer: ipaddress.IPv4Network, inner: ipaddress.IPv4Network
) -> bool:
    """True when ``inner`` is entirely inside ``outer``.

    Compares address bounds rather than calling ``subnet_of`` so mismatched
    versions or prefixes can never raise here.
    """
    return (
        int(outer.network_address) <= int(inner.network_address)
        and int(inner.broadcast_address) <= int(outer.broadcast_address)
    )


def _network_overlaps(
    left: ipaddress.IPv4Network, right: ipaddress.IPv4Network
) -> bool:
    """True when the two address ranges share at least one address."""
    return (
        int(left.network_address) <= int(right.broadcast_address)
        and int(right.network_address) <= int(left.broadcast_address)
    )


def _as_packet(packet: Union[Packet, Mapping[str, Any]]) -> Packet:
    """Coerce a dict-like payload into a validated :class:`Packet`."""
    if isinstance(packet, Packet):
        return packet
    if isinstance(packet, Mapping):
        missing = {"source", "destination", "port", "protocol"} - set(packet)
        if missing:
            raise ValueError(
                "packet is missing field(s): " + ", ".join(sorted(missing))
            )
        return parse_packet(
            packet["source"], packet["destination"], packet["port"],
            packet["protocol"],
        )
    raise TypeError(
        "match_packet expects a Packet or a mapping; got "
        f"{type(packet).__name__}"
    )


def parse_packet(
    source: Any, destination: Any, port: Any, protocol: Any
) -> Packet:
    """Validate user input and build a :class:`Packet`.

    Raises
    ------
    ValueError
        With a message that is safe to show in the UI (no traceback needed).

    Validation rules mirror the CSV contract: both endpoints must be single
    IPv4 host addresses, the port must be an integer in 0-65535, and the
    protocol must be one of tcp, udp, icmp, any.
    """
    def _host(value: Any, field_name: str) -> str:
        text = "" if value is None else str(value).strip()
        if not text:
            raise ValueError(f"{field_name} is required (an IPv4 address such as 10.1.2.3)")
        if "/" in text:
            raise ValueError(
                f"{field_name} '{text}' is a CIDR; a simulated packet needs a "
                "single IPv4 address"
            )
        if ":" in text:
            raise ValueError(
                f"{field_name} '{text}' looks like IPv6; only IPv4 is supported"
            )
        try:
            return str(ipaddress.IPv4Address(text))
        except ValueError:
            raise ValueError(
                f"{field_name} '{text}' is not a valid IPv4 address"
            ) from None

    src = _host(source, "source IP")
    dst = _host(destination, "destination IP")

    port_text = "" if port is None else str(port).strip()
    if not port_text:
        raise ValueError("port is required (an integer 0-65535)")
    try:
        port_range = parse_port_spec(port_text)
    except PolicyFieldError as exc:
        raise ValueError(f"port: {exc}") from None
    if port_range.is_any or port_range.lo != port_range.hi:
        raise ValueError(
            f"port '{port_text}' must be a single port number 0-65535 for a "
            "simulated packet (ranges and 'any' belong in policy rules)"
        )

    try:
        proto = parse_protocol(protocol)
    except PolicyFieldError as exc:
        raise ValueError(f"protocol: {exc}") from None
    if proto == "any":
        raise ValueError(
            "protocol must be tcp, udp or icmp for a simulated packet "
            "('any' describes a rule, not a packet)"
        )
    return Packet(source=src, destination=dst, port=port_range.lo, protocol=proto)


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------
def compile_policy(policy: Union[Policy, pd.DataFrame, Any]) -> Policy:
    """Build a :class:`Policy` from a validated DataFrame (or pass one through).

    Accepted inputs
    ---------------
    * a :class:`Policy` (returned unchanged),
    * a validated policy DataFrame (six string columns),
    * a CSV path / bytes / file-like object, which is loaded and validated
      first.

    Raises
    ------
    ValueError
        If the policy fails validation. The message is the bullet list of
        validation errors, which is what the UI shows to the user.
    """
    if isinstance(policy, Policy):
        return policy
    if not isinstance(policy, pd.DataFrame):
        from .validation import load_and_validate

        result = load_and_validate(policy)
        if not result.ok:
            raise ValueError("policy is not valid:\n" + result.error_text())
        policy = result.policy  # type: ignore[assignment]

    frame = policy.copy()
    frame.columns = [str(col).strip().lower() for col in frame.columns]
    missing = [column for column in POLICY_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError("policy is missing column(s): " + ", ".join(missing))

    rules: list[Rule] = []
    for position, row in enumerate(frame.itertuples(index=False), start=1):
        record = dict(zip(frame.columns, row))
        try:
            src_net = parse_cidr(record["source"])
            dst_net = parse_cidr(record["destination"])
            port_range = parse_port_spec(record["port"])
            rule = Rule(
                order=int(record["order"]),
                source=str(src_net),
                destination=str(dst_net),
                port=str(port_range),
                protocol=parse_protocol(record["protocol"]),
                action=parse_action(record["action"]),
                src_net=src_net,
                dst_net=dst_net,
                port_range=port_range,
            )
        except (PolicyFieldError, TypeError, ValueError) as exc:
            raise ValueError(
                f"policy row {position + 1} could not be compiled: {exc}. "
                "Run validate_policy() and fix the reported errors first."
            ) from None
        rules.append(rule)

    orders = [rule.order for rule in rules]
    if len(set(orders)) != len(orders):
        raise ValueError("policy has duplicate order values; validate it first")
    rules.sort(key=lambda rule: rule.order)
    return Policy(rules=rules, dataframe=frame.loc[:, list(POLICY_COLUMNS)])


# ---------------------------------------------------------------------------
# 1. Packet matching (first match wins)
# ---------------------------------------------------------------------------
def match_packet(
    policy: Union[Policy, pd.DataFrame, Any],
    packet: Union[Packet, Mapping[str, Any]],
) -> MatchResult:
    """Simulate one packet and return the first matching rule and its action.

    Evaluation
    ----------
    Rules are visited in ascending ``order``. The first rule where the packet's
    source is inside the rule's source CIDR, its destination is inside the
    destination CIDR, its port falls in the rule's port scope (or the scope is
    ``any``), and its protocol equals the rule's protocol (or the rule is
    ``any``) is returned immediately.

    **Default action:** if no rule matches, the packet is ``DENY``ed
    (:data:`DEFAULT_ACTION`). ``MatchResult.is_default`` is then True and
    ``MatchResult.rule`` is ``None``; the explanation says so explicitly. The
    default is default-deny because the system audits hardened policies and a
    silent allow would be the wrong failure mode for an audit tool.

    Parameters
    ----------
    policy:
        A compiled policy, a validated DataFrame, or a CSV path/bytes/upload.
    packet:
        A :class:`Packet`, or a mapping with keys ``source``, ``destination``,
        ``port`` and ``protocol`` (validated by :func:`parse_packet`).

    Returns
    -------
    MatchResult
        ``.rule``, ``.action``, ``.is_default``, ``.rules_evaluated`` and a
        plain-English ``.explanation``. ``.shadowed_overlaps`` lists later rules
        that also cover the packet but were never reached, which is exactly the
        evidence for a shadowing finding.
    """
    compiled = compile_policy(policy)
    pkt = _as_packet(packet)

    evaluated = 0
    for rule in compiled.rules:
        evaluated += 1
        if rule.matches(pkt):
            later = [
                other
                for other in compiled.rules
                if other.order > rule.order and other.matches(pkt)
            ]
            explanation = _explain_match(compiled, pkt, rule, evaluated, later)
            return MatchResult(
                packet=pkt,
                rule=rule,
                action=rule.action,
                is_default=False,
                rules_evaluated=evaluated,
                explanation=explanation,
                shadowed_overlaps=later,
            )

    explanation = (
        f"Packet {pkt.label()} matches none of the {len(compiled)} rules, so the "
        f"DEFAULT ACTION {DEFAULT_ACTION.upper()} is applied "
        f"(documented default-deny posture; no implicit allow exists)."
    )
    return MatchResult(
        packet=pkt,
        rule=None,
        action=DEFAULT_ACTION,
        is_default=True,
        rules_evaluated=evaluated,
        explanation=explanation,
        shadowed_overlaps=[],
    )


def _explain_match(
    policy: Policy,
    packet: Packet,
    rule: Rule,
    evaluated: int,
    later_matches: Sequence[Rule],
) -> str:
    """Build the sentence(s) explaining how a packet resolved."""
    verdict = "allowed" if rule.action == "allow" else "denied"
    parts = [
        f"Packet {packet.label()} matches rule {rule.order} "
        f"({rule.action} {rule.scope_text()}) and is {verdict}."
    ]
    if evaluated == 1:
        parts.append(
            "It is the first rule in the policy, so it was decided immediately."
        )
    else:
        parts.append(
            f"The {evaluated - 1} higher-priority rule(s) were evaluated first and "
            f"none matched, so this is the first match and the remaining "
            f"{len(policy) - evaluated} rule(s) were not considered."
        )
    if later_matches:
        orders = ", ".join(str(other.order) for other in later_matches)
        parts.append(
            f"Rule {orders} would also have covered this packet but is shadowed "
            f"for it by rule {rule.order}."
        )
    return " ".join(parts)


def explain_packet_decision(
    policy: Union[Policy, pd.DataFrame, Any],
    packet: Union[Packet, Mapping[str, Any]],
) -> str:
    """Return just the plain-English explanation for a simulated packet.

    Example output::

        Packet 10.1.2.3:443/tcp -> 10.9.9.5 matches rule 1 (allow 10.0.0.0/8 to
        any, any port, any protocol) and is allowed. ...
    """
    return match_packet(policy, packet).explanation


# ---------------------------------------------------------------------------
# 2. Overlap detection
# ---------------------------------------------------------------------------
def find_overlaps(policy: Union[Policy, pd.DataFrame, Any]) -> list[Overlap]:
    """Find every pair of rules whose scopes intersect on all four dimensions.

    Method
    ------
    For each unordered pair ``(a, b)`` with ``a.order < b.order``:

    * **source / destination** — CIDR overlap via address-bound comparison
      (``ipaddress`` networks expose ``network_address``/``broadcast_address``,
      and two IPv4 networks overlap when neither range ends before the other
      starts). ``IPv4Network.overlaps`` is equivalent; the bounds comparison is
      used so the helper also documents the interval semantics used for ports.
    * **port** — inclusive interval intersection: ``a.lo <= b.hi and b.lo <= a.hi``.
    * **protocol** — equal, or either side is ``any``.

    A pair overlaps when all four are true. Complexity is O(n^2) in the number of
    rules, which is fine for the sizes this tool targets (hundreds of rules);
    it is not intended for 100k-rule files.
    """
    compiled = compile_policy(policy)
    overlaps: list[Overlap] = []
    rules = compiled.rules
    for index, first in enumerate(rules):
        for second in rules[index + 1:]:
            if first.overlaps(second):
                overlaps.append(
                    Overlap(
                        a=first,
                        b=second,
                        same_action=first.action == second.action,
                    )
                )
    return overlaps


# ---------------------------------------------------------------------------
# 3. Shadowing, redundancy and conflicts
# ---------------------------------------------------------------------------
def find_shadowed(policy: Union[Policy, pd.DataFrame, Any]) -> list[Shadowed]:
    """Find rules that can never be the first match.

    A rule ``j`` is shadowed when at least one earlier rule ``i`` covers it on
    every dimension: ``i.src ⊇ j.src``, ``i.dst ⊇ j.dst``,
    ``i.port ⊇ j.port`` and ``i.proto ⊇ j.proto``. First-match evaluation can
    then never reach ``j``, whatever the packet.

    Excluded on purpose: a rule that is an *exact duplicate* of an earlier rule
    is reported once, by :func:`find_redundant`, to avoid double-counting the
    same defect in two tables. Rules that are only partly clipped (the later
    rule still matches packets the earlier one does not) are **not** shadowed;
    they appear as conflicts instead if their actions differ.

    Returns
    -------
    list[Shadowed]
        Sorted by rule order, each naming every earlier rule that shadows it.
    """
    compiled = compile_policy(policy)
    results: list[Shadowed] = []
    for position, rule in enumerate(compiled.rules):
        earlier = compiled.rules[:position]
        if any(_same_scope(rule, other) and rule.action == other.action
               for other in earlier):
            continue  # exact duplicate -> redundant table
        shadowers = [other for other in earlier if other.covers(rule)]
        if shadowers:
            results.append(Shadowed(rule=rule, shadowed_by=shadowers))
    return results


def find_redundant(policy: Union[Policy, pd.DataFrame, Any]) -> list[Redundant]:
    """Find rules whose removal would not change any packet's outcome.

    Two cases are detected, both under the simplified single-rule assumption:

    ``duplicate``
        The rule has the same source, destination, port, protocol **and**
        action as an earlier rule.
    ``covered``
        The rule is fully covered by an earlier rule that has the **same
        action**, so it can never alter the verdict.

    Documented simplification: a rule that is only redundant because of the
    *combination* of two or more earlier rules (for example two /25 rules
    together covering a later /24) is not reported. Detecting that needs a
    set-cover analysis the tool does not attempt.
    """
    compiled = compile_policy(policy)
    results: list[Redundant] = []
    for position, rule in enumerate(compiled.rules):
        earlier = compiled.rules[:position]
        duplicates = [
            other for other in earlier
            if _same_scope(rule, other) and other.action == rule.action
        ]
        if duplicates:
            results.append(
                Redundant(rule=rule, redundant_with=duplicates, kind="duplicate")
            )
            continue
        same_action_coverers = [
            other for other in earlier
            if other.covers(rule) and other.action == rule.action
        ]
        if same_action_coverers:
            results.append(
                Redundant(
                    rule=rule, redundant_with=same_action_coverers, kind="covered"
                )
            )
    return results


def find_conflicts(policy: Union[Policy, pd.DataFrame, Any]) -> list[Conflict]:
    """Find overlapping rule pairs whose actions disagree.

    For every overlapping pair ``(i, j)`` with ``i.order < j.order`` and
    ``i.action != j.action``, the earlier rule is reported as the winner: a
    first-match policy stops at ``i``, so ``j`` only ever governs the part of
    its scope that ``i`` does not already match (possibly nothing at all).
    """
    compiled = compile_policy(policy)
    conflicts: list[Conflict] = []
    for overlap in find_overlaps(compiled):
        if overlap.same_action:
            continue
        conflicts.append(Conflict(winner=overlap.a, loser=overlap.b))
    return conflicts


def analyse_policy(policy: Union[Policy, pd.DataFrame, Any]) -> AnalysisResult:
    """Run the full analysis and return every finding bucket at once.

    This is the single entry point the UI calls. It compiles the policy once and
    reuses it for overlap, shadowing, redundancy and conflict detection.
    """
    compiled = compile_policy(policy)
    return AnalysisResult(
        policy=compiled,
        overlaps=find_overlaps(compiled),
        shadowed=find_shadowed(compiled),
        redundant=find_redundant(compiled),
        conflicts=find_conflicts(compiled),
    )


def _same_scope(left: Rule, right: Rule) -> bool:
    """True when two rules describe identical traffic (ignoring order).

    Compares the parsed scope, so ``any`` and ``0-65535`` (or a masked CIDR and
    its canonical form) count as the same traffic even though the raw strings
    differ.
    """
    return (
        left.src_net == right.src_net
        and left.dst_net == right.dst_net
        and left.port_range.lo == right.port_range.lo
        and left.port_range.hi == right.port_range.hi
        and left.protocol == right.protocol
    )


# ---------------------------------------------------------------------------
# 4. Policy explanation
# ---------------------------------------------------------------------------
def explain_rule(policy: Union[Policy, pd.DataFrame, Any], order: int) -> str:
    """Explain one rule in plain English, including its shadowing status.

    Example::

        Rule 3 (deny 10.1.2.0/24 to 10.9.9.0/24, port 3306, tcp protocol) is
        rule 3 of 14 in evaluation order. It is fully shadowed by rule 1: every
        packet it describes is matched earlier, so its intended action is
        unreachable. It overlaps rule 1 (allow) with the opposite action; the
        earlier rule wins for the shared traffic.
    """
    compiled = compile_policy(policy)
    rule = compiled.get(int(order))
    position = next(
        index for index, candidate in enumerate(compiled.rules, start=1)
        if candidate.order == rule.order
    )
    sentences = [
        f"Rule {rule.order} ({rule.action} {rule.scope_text()}) is rule "
        f"{position} of {len(compiled)} in evaluation order."
    ]

    earlier = [other for other in compiled.rules if other.order < rule.order]
    shadowers = [other for other in earlier if other.covers(rule)]
    duplicates = [
        other for other in earlier
        if _same_scope(rule, other) and other.action == rule.action
    ]

    if duplicates:
        orders = ", ".join(str(other.order) for other in duplicates)
        sentences.append(
            f"It is an exact duplicate of rule {orders}, so it is redundant."
        )
    elif shadowers:
        orders = ", ".join(str(other.order) for other in shadowers)
        same_action = {other.action for other in shadowers} == {rule.action}
        sentences.append(
            f"It is fully shadowed by rule {orders}: every packet it describes "
            "is matched earlier, so it can never take effect"
            + (", and removing it would change nothing." if same_action
               else ", so its intended action is unreachable.")
        )
    else:
        sentences.append(
            "No earlier rule fully covers it, so it can still be the deciding "
            "rule for traffic in its scope."
        )

    if not rule.port_range.is_any and rule.protocol == "icmp":
        sentences.append(
            "Note: it combines an ICMP protocol with a specific port, which the "
            "simplified semantics evaluate uniformly even though ICMP has no "
            "ports."
        )

    opposing = [
        other for other in compiled.rules
        if other.order != rule.order
        and other.overlaps(rule)
        and other.action != rule.action
    ]
    if opposing:
        orders = ", ".join(
            f"{other.order} ({other.action})" for other in sorted(
                opposing, key=lambda item: item.order
            )
        )
        sentences.append(
            f"It overlaps rules {orders} with the opposite action; the earlier "
            "rule wins for the shared traffic."
        )
    return " ".join(sentences)


def explain_policy(policy: Union[Policy, pd.DataFrame, Any]) -> str:
    """Return a short plain-English paragraph summarising the whole policy."""
    compiled = compile_policy(policy)
    analysis = analyse_policy(compiled)
    allowed = sum(1 for rule in compiled if rule.allow)
    counts = analysis.summary()
    return (
        f"The policy has {len(compiled)} rules evaluated top to bottom "
        f"({allowed} allow, {len(compiled) - allowed} deny), with a default "
        f"{DEFAULT_ACTION.upper()} when nothing matches. The audit found "
        f"{counts['overlaps']} overlapping pair(s), {counts['shadowed']} shadowed "
        f"rule(s), {counts['redundant']} redundant rule(s) and "
        f"{counts['conflicts']} conflicting pair(s)."
    )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def validate_and_compile(source: Any) -> tuple[Any, Optional[Policy]]:
    """Validate a CSV source and compile it in one step (UI convenience).

    Returns ``(validation_result, policy_or_None)``. The UI shows
    ``validation_result.errors`` when ``policy`` is ``None``.
    """
    result = validate_policy(source) if isinstance(source, pd.DataFrame) else None
    if result is None:
        from .validation import load_and_validate

        result = load_and_validate(source)
    if not result.ok:
        return result, None
    return result, compile_policy(result.policy)
