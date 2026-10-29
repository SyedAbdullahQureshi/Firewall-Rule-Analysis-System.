# Limitations

The Firewall Rule Analysis System audits a policy **file**. It does not enforce
traffic, does not connect to a device and does not observe real packets. Its
conclusions are only valid inside the simplified semantics below, all of which
are also documented in the engine's module docstring.

## 1. What the model ignores

* **Stateful connection tracking.** There is no `established` / `related`
  state. Every packet is evaluated as if it were the first packet of a flow, so
  return traffic needs its own rule. A policy that relies on a stateful engine
  to permit replies will look stricter here than it behaves in production, and
  a rule set that is only correct because of connection tracking will be
  reported as though it were not.
* **NAT.** No source or destination translation is modelled. Addresses are
  compared exactly as written, and pre-NAT / post-NAT address spaces are not
  distinguished. A finding about a `/32` host is about the address in the file,
  not about the address a packet will carry after translation.
* **Time-based rules.** No schedules, time windows, rate limits, quotas,
  session limits or counters. A rule that only applies between 09:00 and 17:00
  is treated as always active.
* **IPv6.** IPv4 only. IPv6 CIDRs are rejected by validation with an explicit
  message rather than being silently skipped, so an IPv6 policy fails loudly
  instead of producing an empty report.
* **Interface-specific behaviour.** The policy is single-interface. Zones,
  interfaces, directions (inbound / outbound / forward), VRFs, routing
  instances and per-interface defaults are not modelled: a rule is a filter on
  a (source, destination, port, protocol) tuple, not on a path through a
  device.
* **Application awareness.** No layer-7 inspection, user identity, application
  signatures, URL categories, TLS inspection or geolocation objects. A
  "destination" is an IPv4 range and nothing else.
* **Negation, groups and objects.** Rules are flat and independent. There are
  no `except` clauses, no negated addresses, no address/service groups, no
  inheritance, no implicit services and no vendor object expansion.

## 2. How the policy is interpreted

* **An ordered list with a single default action.** Rules are sorted by their
  `order` column and evaluated top to bottom; the first match wins and nothing
  after it is considered. When no rule matches, the documented default action
  applies: **deny** (`engine.DEFAULT_ACTION`). There is exactly one default for
  the whole policy — no per-zone or per-direction defaults, and no implicit
  allow anywhere.
* **A port dimension on every protocol.** Real ICMP has no ports. The engine
  evaluates the port field uniformly for all protocols so that overlap maths
  stays symmetric, so a rule with `protocol=icmp` and a specific port is
  interpreted literally. All ICMP rules in the sample policy use `port=any`.
* **Redundancy is single-rule.** A rule is flagged redundant only when an
  earlier rule *by itself* covers it (same action). A rule made redundant only
  by the union of several earlier rules (two `/25`s covering a later `/24`) is
  not reported. Shadowing and overlap detection are exact within the 4-tuple
  model.
* **Analysis is over the file, not over traffic.** Counts describe the rule set,
  not the network. "15 overlapping pairs" says nothing about how much traffic
  those pairs carry.

## 3. What it therefore cannot do

* **Model real vendor-specific firewall behaviour.** Policy formats, default
  actions, implicit rules, NAT interactions, stateful inspection, logging and
  hit counts differ between Cisco ASA/FTD, Fortinet FortiOS, Palo Alto PAN-OS,
  Check Point, iptables/nftables, AWS security groups and cloud NSGs. This tool
  reads the six columns it documents and nothing else; it does not import a
  vendor configuration, does not emulate a vendor engine and does not claim
  that its verdict matches what a specific device would do with the same rule
  set.
* **Validate that a policy is *correct*.** It finds structural problems —
  shadowing, duplication, ordering conflicts — but "rule 5 should allow
  203.0.113.45 to reach 198.51.100.10 on 8443" is a business intent question.
  Findings are review prompts, not verdicts.
* **Prove the absence of problems.** The analysis proves what it reports; it
  does not prove that an unreported rule is safe. Overlap detection is pairwise,
  and no attempt is made to reason about rule sets as a whole beyond the single
  default action.
* **Scale to very large policies.** Overlap detection is O(n²) in the number of
  rules. That is comfortable for the hundreds-of-rules policies this tool
  targets; it is not intended for 100k-rule files.
* **Enforce anything.** It audits the policy file. It does not install, push,
  deploy or enforce rules, and it never inspects or blocks a packet.
