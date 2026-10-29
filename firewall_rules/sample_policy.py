"""The built-in sample policy used for demos, docs and tests.

The same 14 rules live in ``sample_policy.csv`` at the repository root; the
constant below is the in-memory copy so the app and the notebook work even when
the working directory is somewhere else (for example a hosted notebook).

The policy is deliberately *dirty in the interesting ways* an auditor cares
about, while still passing validation (validation rejects malformed files, not
sloppy ones):

======  ==============================================================
Rule    Intent of the rule
======  ==============================================================
1       Broad allow: 10.0.0.0/8 -> any, any port, any protocol.
2       Wildcard deny of TCP/22 from anywhere, placed after rule 1.
3       Narrow rule fully shadowed by rule 1 (never evaluated).
4       Port-range rule, also fully shadowed by rule 1.
5       /32 host pair allow, narrower than rule 6.
6       Overlapping deny placed *after* rule 5 (allow-before-deny).
7       Overlapping deny placed *before* rule 8 (deny-before-allow).
8       Broad destination allow that rule 7 overrides for TCP/443.
9       Wildcard ICMP deny covering every address.
10      Exact duplicate of rule 9 -> redundant.
11      Narrow allow shadowed by rule 1 and redundant with it.
12      Wide rule with a low-port range that rule 2 cuts into.
13      Wildcard-port UDP allow (host-to-host direction reversed).
14      Cross-direction wildcard allow for a private range.
======  ==============================================================
"""

from __future__ import annotations

import os
from typing import Optional

import pandas as pd

SAMPLE_POLICY_CSV: str = """order,source,destination,port,protocol,action
1,10.0.0.0/8,0.0.0.0/0,any,any,allow
2,0.0.0.0/0,0.0.0.0/0,22,tcp,deny
3,10.1.2.0/24,10.9.9.0/24,3306,tcp,deny
4,10.2.0.0/16,172.16.0.0/12,1000-2000,udp,allow
5,203.0.113.45/32,198.51.100.10/32,8443,tcp,allow
6,203.0.113.0/24,198.51.100.0/24,8443,tcp,deny
7,203.0.113.0/24,198.51.100.0/24,443,tcp,deny
8,203.0.113.0/24,0.0.0.0/0,443,tcp,allow
9,0.0.0.0/0,0.0.0.0/0,any,icmp,deny
10,0.0.0.0/0,0.0.0.0/0,any,icmp,deny
11,10.5.0.0/16,10.6.0.0/16,80,tcp,allow
12,0.0.0.0/0,192.0.2.0/24,0-1023,tcp,allow
13,198.51.100.0/24,203.0.113.0/24,any,udp,allow
14,172.16.0.0/12,10.0.0.0/8,any,any,allow
"""

#: Example packets for the simulator, chosen to exercise every outcome.
SAMPLE_PACKETS: list[dict[str, object]] = [
    {
        "label": "Broad allow (rule 1)",
        "source": "10.1.2.3",
        "destination": "10.9.9.5",
        "port": "3306",
        "protocol": "tcp",
        "note": "Rule 1 allows it, so rule 3 never gets a chance to deny it.",
    },
    {
        "label": "Wildcard deny (rule 2)",
        "source": "8.8.8.8",
        "destination": "1.1.1.1",
        "port": "22",
        "protocol": "tcp",
        "note": "TCP/22 is denied for every address by rule 2.",
    },
    {
        "label": "Allow before deny (rules 5 and 6)",
        "source": "203.0.113.45",
        "destination": "198.51.100.10",
        "port": "8443",
        "protocol": "tcp",
        "note": "Rule 5 is the /32 allow that wins over the /24 deny in rule 6.",
    },
    {
        "label": "Deny before allow (rules 7 and 8)",
        "source": "203.0.113.10",
        "destination": "198.51.100.10",
        "port": "443",
        "protocol": "tcp",
        "note": "Rule 7 denies before rule 8 can allow the same traffic.",
    },
    {
        "label": "No match -> default action",
        "source": "8.8.8.8",
        "destination": "1.1.1.1",
        "port": "5353",
        "port_note": "UDP/5353 matches no rule",
        "protocol": "udp",
        "note": "Nothing matches, so the documented default action applies.",
    },
]


def sample_policy_dataframe() -> pd.DataFrame:
    """Return the sample policy as a DataFrame, exactly as parsed from CSV."""
    import io

    return pd.read_csv(io.StringIO(SAMPLE_POLICY_CSV), dtype=str)


def write_sample_policy(path: str = "sample_policy.csv") -> str:
    """Write the sample policy to ``path`` and return the path."""
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(SAMPLE_POLICY_CSV)
    return path


def sample_policy_path() -> str:
    """Locate (or create) the sample policy CSV and return its path.

    Looks next to this package's parent directory first (the repository root),
    then falls back to the current directory, and finally writes the CSV to a
    temporary file so the "load sample" button always works.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(here), "sample_policy.csv"),
        os.path.abspath("sample_policy.csv"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return write_sample_policy(candidates[0])


def read_sample_policy(path: Optional[str] = None) -> str:
    """Return the sample policy CSV text (from disk when available)."""
    resolved = path or sample_policy_path()
    try:
        with open(resolved, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return SAMPLE_POLICY_CSV
