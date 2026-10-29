# Submission checklist

## Deliverables

| ✔ | Item | Where |
|---|------|-------|
| ☑ | Rerunnable notebook (Restart & Run All, no manual steps) | `Firewall_Rule_Analysis_System.ipynb` |
| ☑ | Sample data (14-rule policy, deliberately messy) | `sample_policy.csv`, `firewall_rules/sample_policy.py` |
| ☑ | Example files used for the screenshots | `docs/examples/valid_custom_policy.csv`, `docs/examples/invalid_policy.csv` |
| ☑ | Phase 1 — CSV contract, sample policy, validation | notebook §1, `firewall_rules/validation.py` |
| ☑ | Phase 2 — analysis engine + docstrings + test run | notebook §2, `firewall_rules/engine.py` |
| ☑ | Phase 3 — Gradio app + launch instructions | notebook §3, `firewall_rules/ui.py` |
| ☑ | Phase 4 — acceptance tests (unittest) | `tests/test_acceptance.py` (18 tests) |
| ☑ | Test-case table (generated from the run) | notebook §4, `docs/TEST_CASES.md` |
| ☑ | Limitations section | notebook §5, `docs/LIMITATIONS.md` |
| ☑ | Architecture explanation (prose) | notebook §6, `docs/ARCHITECTURE.md` |
| ☑ | Screenshots + list of screens | `docs/screenshots/` (8 images), `docs/SCREENSHOTS.md` |
| ☑ | UI redesign notes + before/after checklist | `docs/UI_REDESIGN.md` |
| ☑ | Run instructions | `README.md` |
| ☑ | Reproducible notebook build | `tools/build_notebook.py` (regenerates and re-executes) |

## Final check

1. `python -m unittest discover -s tests -v` → **18 tests, OK**.
2. Restart & Run All in the notebook → every cell runs, the last cell prints
   `FINAL CHECK PASSED` and no cell raises.
3. `python -m firewall_rules.ui --port 7860` → the console UI loads in its empty
   state (grey badge, simulator disabled); **Load built-in sample policy** then
   fills every section without an upload.
4. Upload `docs/examples/invalid_policy.csv` → 8 errors, no crash.
5. Upload `docs/examples/valid_custom_policy.csv` → 5 rules accepted, 1
   redundant, 1 overlap.
6. Simulate `8.8.8.8 -> 1.1.1.1:5353/udp` → *NO MATCH — DEFAULT DENY*, stated as default.

## Environment

Python 3.11, pandas 3.1, gradio 6.31, `ipaddress` (standard library).
`pip install -r requirements.txt`. No network access is required at runtime
apart from whatever Gradio initialises locally; `share=True` is opt-in.
