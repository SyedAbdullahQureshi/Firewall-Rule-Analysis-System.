"""Loading and validation for firewall policy files (Phase 1).

Data contract
-------------
A policy file is a CSV whose header is exactly, in this order::

    order,source,destination,port,protocol,action

* ``order``       integer rule position; rules are evaluated top to bottom.
* ``source``      IPv4 CIDR, e.g. ``10.0.0.0/8`` or ``0.0.0.0/0``.
* ``destination`` IPv4 CIDR.
* ``port``        a single port (``443``), an inclusive range (``1000-2000``),
                  or ``any``.
* ``protocol``    ``tcp``, ``udp``, ``icmp`` or ``any``.
* ``action``      ``allow`` or ``deny``.

Design notes
------------
* :func:`load_policy` (I/O) and :func:`validate_policy` (semantics) are separate
  so each can be unit-tested on its own, and so a caller that already holds a
  DataFrame (a notebook, a test, a future REST layer) can skip the file layer.
* Neither function raises for bad *user data*: they return a result object with
  a list of errors. Exceptions are reserved for programmer errors.
* Errors are strings that start with the CSV line number, where line 1 is the
  header, so the message points at the same line the user sees in a text
  editor. A DataFrame index of 0 is therefore reported as "row 2".
* The parsers :func:`parse_cidr` and :func:`parse_port_spec` are shared with
  :mod:`firewall_rules.engine`, so validation and analysis can never disagree
  about what a CIDR or a port range means.
"""

from __future__ import annotations

import io
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import pandas as pd

#: The exact column set and order a policy file must provide.
POLICY_COLUMNS: tuple[str, ...] = (
    "order",
    "source",
    "destination",
    "port",
    "protocol",
    "action",
)

#: Canonical display order used in error messages.
PROTOCOL_ORDER: tuple[str, ...] = ("tcp", "udp", "icmp", "any")
ACTION_ORDER: tuple[str, ...] = ("allow", "deny")

ALLOWED_PROTOCOLS: frozenset[str] = frozenset(PROTOCOL_ORDER)
ALLOWED_ACTIONS: frozenset[str] = frozenset(ACTION_ORDER)

#: Legal TCP/UDP port range (documented assumption: no port 0 well-known
#: exception is modelled; 0 is accepted because some vendors use it for ICMP).
MIN_PORT = 0
MAX_PORT = 65535

#: Encodings tried in order when a byte stream is uploaded.
ENCODINGS: tuple[str, ...] = ("utf-8-sig", "utf-8", "cp1252", "latin-1")

_ANY_TOKENS = frozenset({"any", "*", ""})


class PolicyFieldError(ValueError):
    """Raised by the low-level parsers for a single illegal field value."""


@dataclass(frozen=True)
class PortRange:
    """A parsed port scope.

    ``is_any`` is kept separately from ``(lo, hi) == (0, 65535)`` so that the
    UI can echo the user's own wording back to them ("any" vs "0-65535").
    """

    lo: int
    hi: int
    is_any: bool

    def contains(self, port: int) -> bool:
        return self.lo <= port <= self.hi

    def covers(self, other: "PortRange") -> bool:
        """True when every port in ``other`` is also in ``self``."""
        return self.lo <= other.lo and other.hi <= self.hi

    def overlaps(self, other: "PortRange") -> bool:
        return self.lo <= other.hi and other.lo <= self.hi

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if self.is_any:
            return "any"
        if self.lo == self.hi:
            return str(self.lo)
        return f"{self.lo}-{self.hi}"


# ---------------------------------------------------------------------------
# Field parsers (shared with the engine)
# ---------------------------------------------------------------------------
def parse_cidr(value: Any) -> ipaddress.IPv4Network:
    """Parse ``value`` as an IPv4 CIDR and return an ``IPv4Network``.

    Rules
    -----
    * IPv4 only. IPv6 input is rejected with an explicit message instead of a
      ``TypeError`` so the row number can still be reported.
    * Host bits are masked off (``10.1.2.3/8`` becomes ``10.0.0.0/8``) using
      ``strict=False``; ``IPv4Network`` then guarantees a canonical prefix, and
      a warning is emitted by the validator when masking changed the value.
    * A bare address (``10.1.2.3``) is accepted as ``/32``; this keeps the tool
      usable for host rules typed by hand.

    Raises
    ------
    PolicyFieldError
        If the value is not a valid IPv4 network.
    """
    if value is None:
        raise PolicyFieldError("value is empty; expected an IPv4 CIDR such as 10.0.0.0/8")
    text = str(value).strip()
    if not text:
        raise PolicyFieldError("value is empty; expected an IPv4 CIDR such as 10.0.0.0/8")
    if ":" in text:
        raise PolicyFieldError(
            f"'{text}' looks like IPv6; only IPv4 CIDRs are supported "
            "(documented limitation)"
        )
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise PolicyFieldError(f"'{text}' is not a valid IPv4 CIDR ({exc})") from exc
    if not isinstance(network, ipaddress.IPv4Network):  # defensive
        raise PolicyFieldError(f"'{text}' is not an IPv4 CIDR")
    return network


def parse_port_spec(value: Any) -> PortRange:
    """Parse a port field into a :class:`PortRange`.

    Accepted forms
    --------------
    ``any`` (also ``*`` or an empty value), a single integer ``443``, or an
    inclusive range ``1000-2000``. En-dashes are normalised to hyphens so a
    spreadsheet autocorrect does not produce a confusing error.

    Raises
    ------
    PolicyFieldError
        For non-numeric text, ports outside 0-65535, more than one hyphen, or a
        range whose start is greater than its end.
    """
    if value is None:
        return PortRange(MIN_PORT, MAX_PORT, True)
    text = str(value).strip().lower().replace("\u2013", "-").replace("\u2014", "-")
    text = text.replace(" ", "")
    if text in _ANY_TOKENS:
        return PortRange(MIN_PORT, MAX_PORT, True)

    if "-" in text:
        parts = text.split("-")
        if len(parts) != 2:
            raise PolicyFieldError(
                f"'{value}' is not a valid port range; use 'start-end', e.g. 1000-2000"
            )
        start_text, end_text = parts[0].strip(), parts[1].strip()
        if not start_text or not end_text:
            raise PolicyFieldError(
                f"'{value}' is not a valid port range; both bounds are required"
            )
        start = _parse_port_number(start_text, value)
        end = _parse_port_number(end_text, value)
        if start > end:
            raise PolicyFieldError(
                f"port range '{value}' is inverted (start {start} > end {end})"
            )
        return PortRange(start, end, False)

    number = _parse_port_number(text, value)
    return PortRange(number, number, False)


def _parse_port_number(text: str, original: Any) -> int:
    try:
        number = int(text, 10)
    except (TypeError, ValueError):
        raise PolicyFieldError(
            f"'{original}' is not a valid port; use an integer 0-65535, a range "
            "such as 1000-2000, or 'any'"
        ) from None
    if number < MIN_PORT or number > MAX_PORT:
        raise PolicyFieldError(
            f"port {number} is outside the valid range {MIN_PORT}-{MAX_PORT}"
        )
    return number


def parse_protocol(value: Any) -> str:
    """Return a normalised lowercase protocol, or raise ``PolicyFieldError``."""
    text = "" if value is None else str(value).strip().lower()
    if text not in ALLOWED_PROTOCOLS:
        raise PolicyFieldError(
            f"'{value}' is not an allowed protocol; expected one of "
            f"{', '.join(PROTOCOL_ORDER)}"
        )
    return text


def parse_action(value: Any) -> str:
    """Return a normalised lowercase action, or raise ``PolicyFieldError``."""
    text = "" if value is None else str(value).strip().lower()
    if text not in ALLOWED_ACTIONS:
        raise PolicyFieldError(
            f"'{value}' is not an allowed action; expected one of "
            f"{', '.join(ACTION_ORDER)}"
        )
    return text


def parse_order(value: Any) -> int:
    """Return an integer rule order, or raise ``PolicyFieldError``.

    ``"3"`` and ``3`` are both accepted; ``"3.0"``, ``"3.5"`` and ``"abc"`` are
    rejected so that rule positions stay unambiguous.
    """
    text = "" if value is None else str(value).strip()
    if not text:
        raise PolicyFieldError("order is empty; expected an integer such as 1")
    try:
        number = int(text, 10)
    except (TypeError, ValueError):
        raise PolicyFieldError(
            f"order '{value}' is not an integer; expected a whole number such as 1"
        ) from None
    return number


# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------
@dataclass
class LoadResult:
    """Outcome of :func:`load_policy`.

    ``dataframe`` is ``None`` when the file could not be read at all (empty
    file, bad encoding, not a CSV). ``errors`` explains why.
    """

    dataframe: Optional[pd.DataFrame] = None
    errors: list[str] = field(default_factory=list)
    encoding: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.dataframe is not None and not self.errors


@dataclass
class ValidationResult:
    """Outcome of :func:`validate_policy` / :func:`load_and_validate`.

    ``policy`` is the normalised DataFrame (lowercase protocol/action, trimmed
    strings, integer order) and is only populated when ``ok`` is True.
    """

    ok: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    policy: Optional[pd.DataFrame] = None

    def error_text(self) -> str:
        """Human-readable bullet list of errors (empty string when valid)."""
        return "\n".join(f"- {error}" for error in self.errors)


# ---------------------------------------------------------------------------
# Loading (I/O only)
# ---------------------------------------------------------------------------
def load_policy(source: Any) -> LoadResult:
    """Read a policy CSV from a path, raw bytes, or a file-like object.

    Parameters
    ----------
    source:
        * ``str``/``os.PathLike`` path, or
        * ``bytes`` (what a Gradio ``gr.File(type="binary")`` returns), or
        * a text/binary file-like object exposing ``read()`` (Gradio
          ``type="filepath"`` hands over a temp path, which is also fine), or
        * a ``str`` of CSV text containing a newline.

    Robustness contract — every one of these is reported, never raised:
    empty file, whitespace-only file, binary/Excel upload, undecodable bytes,
    unparsable CSV, and a missing or misspelled header.

    Returns
    -------
    LoadResult
        ``.dataframe`` holds the raw string DataFrame (all values as text, no
        NaN coercion) or is ``None`` when the file could not be read.
    """
    errors: list[str] = []
    raw: bytes
    name = "<uploaded content>"

    try:
        raw, name = _read_source(source)
    except FileNotFoundError:
        return LoadResult(errors=[f"file not found: {source}"])
    except OSError as exc:
        return LoadResult(errors=[f"could not read {source}: {exc}"])

    if not raw or not raw.strip():
        return LoadResult(errors=[f"{name} is empty (no bytes, no header, no rules)"])

    if raw[:4] == b"PK\x03\x04":
        return LoadResult(
            errors=[
                f"{name} looks like an Excel .xlsx workbook, not a CSV. Use "
                "'Save as -> CSV UTF-8' first."
            ]
        )
    if raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return LoadResult(
            errors=[
                f"{name} looks like a legacy Excel .xls workbook, not a CSV. "
                "Use 'Save as -> CSV UTF-8' first."
            ]
        )
    if b"\x00" in raw[:4096]:
        return LoadResult(
            errors=[
                f"{name} is not a text CSV (it contains NUL bytes). Export the "
                "policy as CSV before uploading."
            ]
        )

    text, encoding = _decode(raw)
    if text is None:
        return LoadResult(
            errors=[
                f"{name} could not be decoded as text (tried "
                f"{', '.join(ENCODINGS)}). Save it as UTF-8 CSV and retry."
            ]
        )

    # Sniff the header before handing the text to pandas, so a wrong delimiter
    # or a plain-text file produces our message rather than pandas' traceback.
    first_line = next((line for line in text.splitlines() if line.strip()), "")
    if "," not in first_line:
        return LoadResult(
            errors=[
                f"{name} does not look like a comma-separated file: the first "
                f"line is {first_line[:80]!r} and contains no commas."
            ],
            encoding=encoding,
        )

    try:
        dataframe = pd.read_csv(
            io.StringIO(text),
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            skipinitialspace=True,
            on_bad_lines="error",
        )
    except pd.errors.EmptyDataError:
        return LoadResult(
            errors=[f"{name} has no header row, so no columns could be read"],
            encoding=encoding,
        )
    except pd.errors.ParserError as exc:
        return LoadResult(
            errors=[
                f"{name} could not be parsed as CSV: {exc}. Check for stray "
                "quotes, inconsistent column counts, or a non-CSV delimiter."
            ],
            encoding=encoding,
        )

    dataframe.columns = [str(col).strip().lower() for col in dataframe.columns]
    if dataframe.shape[1] == 1:
        return LoadResult(
            errors=[
                f"{name} parsed as a single column ({dataframe.columns[0]!r}); "
                "it is probably not comma-separated."
            ],
            encoding=encoding,
        )
    if dataframe.empty:
        return LoadResult(
            errors=[f"{name} has a header but no rule rows"],
            encoding=encoding,
        )
    return LoadResult(dataframe=dataframe, errors=errors, encoding=encoding)


def _read_source(source: Any) -> tuple[bytes, str]:
    """Normalise any supported source into ``(bytes, display_name)``."""
    if isinstance(source, (bytes, bytearray)):
        return bytes(source), "<uploaded content>"
    if isinstance(source, os.PathLike):
        path = os.fspath(source)
        with open(path, "rb") as handle:
            return handle.read(), os.path.basename(path)
    if hasattr(source, "read"):
        name = getattr(source, "name", None)
        data = source.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        return data, os.path.basename(str(name)) if name else "<uploaded content>"
    if isinstance(source, str):
        if "\n" in source or "\r" in source:
            return source.encode("utf-8"), "<inline CSV text>"
        if os.path.exists(source):
            with open(source, "rb") as handle:
                return handle.read(), os.path.basename(source)
        # Treat an unknown string as inline CSV so typos still get a useful
        # header/missing-column error instead of an OSError.
        return source.encode("utf-8"), "<inline CSV text>"
    raise TypeError(
        "load_policy expects a path, bytes, CSV text, or a file-like object; "
        f"got {type(source).__name__}"
    )


def _decode(raw: bytes) -> tuple[Optional[str], Optional[str]]:
    """Decode bytes using the first encoding that works."""
    for encoding in ENCODINGS:
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return None, None


# ---------------------------------------------------------------------------
# Validation (semantics only)
# ---------------------------------------------------------------------------
def validate_policy(dataframe: Optional[pd.DataFrame]) -> ValidationResult:
    """Validate a policy DataFrame and return normalised data or an error list.

    Checks performed (each produces one error string prefixed with the CSV line
    number, so several problems in one file are all reported at once):

    1. **Header** — all six required columns must be present. Unexpected extra
       columns are reported as warnings and ignored.
    2. **Rows** — an empty policy is an error.
    3. **order** — must be an integer, and must be unique across the file.
       Non-ascending order is a warning because evaluation always sorts by
       ``order``.
    4. **source/destination** — must be valid IPv4 CIDR (see
       :func:`parse_cidr`). Invalid prefixes (``/33``), invalid octets
       (``256.1.1.1/24``) and arbitrary text (``abc``) are rejected.
    5. **port** — ``any``, a single port, or ``start-end`` with both bounds in
       0-65535 and ``start <= end`` (see :func:`parse_port_spec`).
    6. **protocol** — one of tcp, udp, icmp, any (case-insensitive).
    7. **action** — one of allow, deny (case-insensitive).

    The function never raises for bad data; a fully valid file returns
    ``ValidationResult(ok=True, errors=[], policy=<normalised df>)``.

    Documented assumption: values are compared case-insensitively and trimmed,
    which mirrors how vendors' CLIs treat keywords.
    """
    result = ValidationResult()
    if dataframe is None:
        result.errors.append("no policy loaded")
        return result
    if not isinstance(dataframe, pd.DataFrame):
        result.errors.append(
            f"validate_policy expects a pandas DataFrame, got {type(dataframe).__name__}"
        )
        return result
    if dataframe.shape[0] == 0:
        result.errors.append("policy contains no rules")
        return result

    frame = dataframe.copy()
    frame.columns = [str(col).strip().lower() for col in frame.columns]

    missing = [column for column in POLICY_COLUMNS if column not in frame.columns]
    extra = [column for column in frame.columns if column not in POLICY_COLUMNS]
    if missing:
        result.errors.append(
            f"missing required column(s): {', '.join(missing)}; expected the "
            f"header '{','.join(POLICY_COLUMNS)}'"
        )
    if extra:
        result.warnings.append(
            f"ignoring unexpected column(s): {', '.join(extra)}"
        )
    if missing:
        # Row-level checks would only produce noise on top of a bad header.
        return result

    frame = frame.loc[:, list(POLICY_COLUMNS)]
    frame = frame.apply(
        lambda column: column.map(lambda v: v.strip() if isinstance(v, str) else v)
    )

    orders: dict[int, list[int]] = {}
    normalised_rows: list[dict[str, Any]] = []
    row_is_valid: list[bool] = []

    for position, (_, row) in enumerate(frame.iterrows()):
        line = position + 2  # +1 for zero-based index, +1 for the header line
        row_errors: list[str] = []
        clean: dict[str, Any] = {}

        # --- order -------------------------------------------------------
        try:
            order = parse_order(row["order"])
            clean["order"] = order
            orders.setdefault(order, []).append(line)
        except PolicyFieldError as exc:
            row_errors.append(f"row {line}: {exc}")

        # --- source / destination ---------------------------------------
        networks: dict[str, ipaddress.IPv4Network] = {}
        for column in ("source", "destination"):
            try:
                network = parse_cidr(row[column])
                clean[column] = str(network)
                networks[column] = network
                original = str(row[column]).strip()
                if original and str(network) != original:
                    result.warnings.append(
                        f"row {line}: {column} '{original}' was normalised to "
                        f"'{network}' (host bits are masked off)"
                    )
            except PolicyFieldError as exc:
                row_errors.append(f"row {line}: {column}: {exc}")

        # --- port --------------------------------------------------------
        try:
            clean["port"] = str(parse_port_spec(row["port"]))
        except PolicyFieldError as exc:
            row_errors.append(f"row {line}: port: {exc}")

        # --- protocol / action ------------------------------------------
        try:
            clean["protocol"] = parse_protocol(row["protocol"])
        except PolicyFieldError as exc:
            row_errors.append(f"row {line}: protocol: {exc}")
        try:
            clean["action"] = parse_action(row["action"])
        except PolicyFieldError as exc:
            row_errors.append(f"row {line}: action: {exc}")

        if row_errors:
            result.errors.extend(row_errors)
            row_is_valid.append(False)
        else:
            normalised_rows.append(clean)
            row_is_valid.append(True)

    # --- duplicate orders ------------------------------------------------
    for order, lines in sorted(orders.items()):
        if len(lines) > 1:
            result.errors.append(
                f"rows {', '.join(str(line) for line in lines)}: duplicate order "
                f"value {order}; every rule needs a unique order"
            )

    # --- ordering sanity (warning only) ----------------------------------
    parsed_orders = [row["order"] for row in normalised_rows]
    if parsed_orders and parsed_orders != sorted(parsed_orders):
        result.warnings.append(
            "rows are not in ascending order; rules will be evaluated by the "
            "'order' column, not by their line position in the file"
        )

    if result.errors:
        result.ok = False
        result.policy = None
        return result

    result.ok = True
    result.policy = pd.DataFrame(
        normalised_rows, columns=list(POLICY_COLUMNS)
    ).astype({"order": "int64"})
    result.policy = result.policy.sort_values("order").reset_index(drop=True)
    return result


def load_and_validate(source: Any) -> ValidationResult:
    """Convenience wrapper: :func:`load_policy` then :func:`validate_policy`.

    Load-level and validation-level errors are merged into one list so a caller
    (the Gradio app) can show a single error panel.
    """
    loaded = load_policy(source)
    if loaded.dataframe is None:
        return ValidationResult(ok=False, errors=list(loaded.errors))
    result = validate_policy(loaded.dataframe)
    if loaded.errors:
        result.errors = list(loaded.errors) + result.errors
        result.ok = False
    if loaded.encoding and loaded.encoding not in ("utf-8", "utf-8-sig"):
        result.warnings.append(
            f"file decoded as {loaded.encoding}; re-save as UTF-8 to be safe"
        )
    return result


def write_policy_csv(dataframe: pd.DataFrame, path: Any) -> None:
    """Write a policy DataFrame back to CSV (useful for exporting fixtures)."""
    dataframe.loc[:, list(POLICY_COLUMNS)].to_csv(path, index=False)
