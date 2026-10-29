"""Run the acceptance suite and turn it into a test-case table.

The table is *generated from the run*, never hand-written: the "actual result"
column comes from what the tests observed (``tests.test_acceptance.RECORDS``),
and pass/fail comes from :mod:`unittest`. If a test starts failing, the table in
the notebook changes by itself.

Public functions
----------------
:func:`run_acceptance_suite`
    Run every test and return ``{case_id: {...}}`` with status, expected and
    actual strings.
:func:`test_case_rows`
    The same data as rows of five strings, ready for a DataFrame or markdown.
:func:`markdown_table`
    A ready-to-paste GitHub-flavoured markdown table.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from typing import Any, Optional

_COLUMNS = ("Test ID", "Description", "Input", "Expected result",
            "Actual result", "Pass/Fail")


def _load_test_module():
    """Import ``tests/test_acceptance.py`` by path (it is not a package)."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "tests", "test_acceptance.py")
    if not os.path.exists(path):
        raise FileNotFoundError(f"acceptance tests not found at {path}")
    spec = importlib.util.spec_from_file_location("fr_test_acceptance", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["fr_test_acceptance"] = module
    spec.loader.exec_module(module)
    return module


class _RecordingResult(unittest.TextTestResult):
    """Collect per-test outcomes without hiding the normal console output."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.outcomes: dict[str, tuple[bool, str]] = {}

    def _name(self, test: unittest.TestCase) -> str:
        return getattr(test, "_testMethodName", str(test))

    def addSuccess(self, test: unittest.TestCase) -> None:
        super().addSuccess(test)
        self.outcomes[self._name(test)] = (True, "")

    def addFailure(self, test: unittest.TestCase, err: Any) -> None:
        super().addFailure(test, err)
        self.outcomes[self._name(test)] = (False, self._short(err))

    def addError(self, test: unittest.TestCase, err: Any) -> None:
        super().addError(test, err)
        self.outcomes[self._name(test)] = (False, self._short(err))

    @staticmethod
    def _short(err: Any) -> str:
        text = err[1].strip().splitlines()
        return text[-1][:300] if text else "error"


def run_acceptance_suite(verbosity: int = 0) -> dict[str, dict[str, str]]:
    """Execute the acceptance tests and return one record per case id.

    Returns
    -------
    dict
        ``{case_id: {"id", "description", "input", "expected", "actual",
        "status"}}`` where ``status`` is ``"PASS"`` or ``"FAIL"``.
    """
    module = _load_test_module()
    module.RECORDS.clear()

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        module.AcceptanceTests
    )
    runner = unittest.TextTestRunner(
        stream=open(os.devnull, "w") if verbosity == 0 else sys.stderr,
        verbosity=verbosity,
        resultclass=_RecordingResult,
    )
    result = runner.run(suite)

    records: dict[str, dict[str, str]] = {}
    for case in module.CASES:
        passed, failure = result.outcomes.get(case["method"], (False, "test not run"))
        actual = module.RECORDS.get(case["id"], "not recorded")
        records[case["id"]] = {
            "id": case["id"],
            "description": case["description"],
            "input": case["input"],
            "expected": case["expected"],
            "actual": actual if passed else f"{actual} [assertion failed: {failure}]",
            "status": "PASS" if passed else "FAIL",
        }
    return records


def test_case_rows(verbosity: int = 0) -> list[list[str]]:
    """Return the test-case table as rows of six strings (header first)."""
    records = run_acceptance_suite(verbosity=verbosity)
    rows: list[list[str]] = [list(_COLUMNS)]
    for case_id in sorted(records):
        record = records[case_id]
        rows.append([
            record["id"],
            record["description"],
            record["input"],
            record["expected"],
            record["actual"],
            record["status"],
        ])
    return rows


def _escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def markdown_table(verbosity: int = 0) -> str:
    """Return the whole test-case table as a markdown string."""
    rows = test_case_rows(verbosity=verbosity)
    header, body = rows[0], rows[1:]
    lines = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join(" --- " for _ in header) + "|",
    ]
    lines.extend("| " + " | ".join(_escape(cell) for cell in row) + " |"
                 for row in body)
    passed = sum(1 for row in body if row[-1] == "PASS")
    lines.append("")
    lines.append(f"**{passed}/{len(body)} acceptance tests passed.**")
    return "\n".join(lines)


def summary(verbosity: int = 0) -> dict[str, Any]:
    """Small dict for the UI badge: counts plus a headline string."""
    records = run_acceptance_suite(verbosity=verbosity)
    passed = sum(1 for record in records.values() if record["status"] == "PASS")
    total = len(records)
    return {
        "passed": passed,
        "total": total,
        "headline": f"{passed}/{total} acceptance tests passed",
        "failed_ids": [key for key, value in records.items()
                       if value["status"] != "PASS"],
    }


if __name__ == "__main__":  # pragma: no cover
    print(markdown_table(verbosity=0))
