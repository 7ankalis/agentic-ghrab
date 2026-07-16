"""
Verification oracle — the held-out documented attack paths (PATH-A..F).

This is deliberately NOT part of the ingested scan/CMDB data the platform
reasons over. When the datasets were built, the answer key (the fully
cross-referenced attack-path chains, the per-finding `Attack_Path_Ref` column,
and the "this finding is downstream in Path A" hints) was stripped out of the
architecture docs and the vulnerability CSVs and moved here, under data/oracle/.

Nothing in the detection pipeline loads this module: not core/attack_graph.py
(the reachability engine), not any LLM agent. That is the whole point — the
engine and the agents must rediscover these paths from the raw asset inventory,
ownership, and network/identity relationships alone. This module is loaded ONLY
by:
  * tests/test_rediscovery.py — scores how many documented paths the engine
    independently reconnects (the acceptance gate), and
  * the API's "discovered vs ground-truth" verification overlay, so an operator
    can eyeball whether the AI actually found the known paths.
"""
from __future__ import annotations

import csv

from core.config import DATA_DIR

ORACLE_DIR = DATA_DIR / "oracle"


def _oracle_csv(dataset_key: str):
    return ORACLE_DIR / f"{dataset_key}_attack_paths.csv"


def attack_path_refs(dataset_key: str | None = None) -> dict[int, str]:
    """QID -> documented Attack_Path_Ref (e.g. 'PATH-E-Step3' | 'Standalone').

    Empty dict if the active dataset has no oracle file, so verification simply
    degrades to 'nothing to check against' rather than erroring."""
    if dataset_key is None:
        from core.config import active_dataset_key
        dataset_key = active_dataset_key()
    path = _oracle_csv(dataset_key)
    if not path.exists():
        return {}
    refs: dict[int, str] = {}
    with path.open(encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                refs[int(row["QID"])] = str(row.get("Attack_Path_Ref", "")).strip()
            except (KeyError, ValueError):
                continue
    return refs
