"""
Regression gate (Phase 0). Runs the deterministic detection pipeline for every
dataset with an oracle and fails if a gated metric drops below the committed
baseline (eval/baselines/) beyond tolerance, or if the two hard invariants slip:
soundness must stay 1.0 for the grounded engine and hallucination must stay 0.

Deterministic-only on purpose (`include_ai=False`): the committed baseline is the
no-provider path, so this test is fast, reproducible, and never flakes on a
provider's rate limit. Later phases update the baseline when they genuinely move
a metric. Run `pytest backend/eval` (or `pytest -s backend/eval` to see the
numbers).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ on path

import pytest  # noqa: E402

from eval.detection import (  # noqa: E402
    check_regressions,
    datasets_with_oracle,
    evaluate_all,
    load_baseline,
    render_table,
)


@pytest.fixture(scope="module")
def results() -> dict:
    return evaluate_all(include_ai=False)


def test_baselines_exist():
    missing = [k for k in datasets_with_oracle() if load_baseline(k) is None]
    assert not missing, (f"no committed baseline for {missing}; run "
                         f"`python -m eval.detection --no-ai --update-baseline`")


def test_no_metric_regressions(results):
    baselines = {k: load_baseline(k) for k in results}
    print(render_table(results, baselines))  # visible under `pytest -s`
    failures = check_regressions(results)
    assert not failures, "detection metrics regressed:\n  - " + "\n  - ".join(failures)


def test_soundness_is_perfect(results):
    for key, report in results.items():
        assert report["soundness"] == 1.0, (
            f"{key}: soundness {report['soundness']} != 1.0 — the deterministic "
            f"engine asserted a hop with no real graph edge")


def test_zero_hallucination(results):
    for key, report in results.items():
        assert report["hallucination_rate"] == 0.0, (
            f"{key}: hallucination_rate {report['hallucination_rate']} != 0 — a "
            f"detected path named a host or QID not in scope")
