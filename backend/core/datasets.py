"""
Dataset registry: discovers which enterprises can be scanned by scanning the
data directory, and holds which one is currently active.

An enterprise is scannable when the data dir contains BOTH a
`<name>_vulnerabilities.csv` (the CVEs / misconfigs export) AND a
`<name>_architecture.md` (the CMDB / architecture description). Requiring both
is deliberate: without the architecture doc the CMDB parses empty and the whole
attack-path engine + LLM layer run with no grounding context.

The active dataset used to be a hardcoded constant in core/config.py; it is now
runtime-switchable (see api/routes.py's /datasets endpoints). Everything that
used to import the fixed VULN_CSV_PATH / ARCHITECTURE_MD_PATH / DATASET_KEY /
ACTIVE_ORG now reads the active dataset here at call time instead.
"""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path

from core.config import DATA_DIR

VULN_SUFFIX = "_vulnerabilities.csv"
ARCH_SUFFIX = "_architecture.md"

# Tailored personas for the built-in lab datasets. Anything else dropped into
# the data dir is auto-profiled from its architecture.md (see _derive_profile),
# falling back to a neutral profile.
_BUILTIN_PROFILES: dict[str, dict[str, str]] = {
    "ghrab": {
        "name": "Ghrab Financial Group",
        "sector": "a financial services firm",
        "frameworks": "PCI DSS, SWIFT CSP, EU DORA",
    },
    "velon": {
        "name": "Velon Health Systems",
        "sector": "a healthcare provider",
        "frameworks": "HIPAA Security Rule, FDA Premarket/Postmarket Cybersecurity Guidance",
    },
}

_GENERIC_PROFILE = {"sector": "an enterprise", "frameworks": "ISO 27001, NIST CSF"}


@dataclass(frozen=True)
class Dataset:
    key: str                  # enterprise name, e.g. "velon" — the persistence/scoping key
    name: str                 # display name for the org persona + UI header
    sector: str               # e.g. "a healthcare provider"
    frameworks: str           # e.g. "HIPAA Security Rule, ..."
    vuln_csv: Path
    architecture_md: Path
    findings: int             # row count of the CSV (header excluded)

    @property
    def has_architecture(self) -> bool:
        return self.architecture_md is not None


def _count_rows(csv: Path) -> int:
    try:
        with csv.open(encoding="utf-8", errors="ignore") as f:
            return max(0, sum(1 for _ in f) - 1)
    except OSError:
        return 0


def _derive_profile(key: str, arch_md: Path) -> dict[str, str]:
    """Persona for a dataset: built-in override wins, otherwise auto-parse the
    top of the architecture.md (H1 heading + optional `Sector:` / `Frameworks:`
    lines), otherwise a neutral generic profile."""
    profile = {"name": key.replace("_", " ").title(), **_GENERIC_PROFILE}
    if key in _BUILTIN_PROFILES:
        profile.update(_BUILTIN_PROFILES[key])
        return profile
    try:
        head = arch_md.read_text(encoding="utf-8", errors="ignore")[:4000]
    except OSError:
        return profile
    if m := re.search(r"^#\s+(.+)$", head, re.M):
        profile["name"] = m.group(1).strip()
    if m := re.search(r"(?im)^\s*>?\s*sector\s*[:\-]\s*(.+)$", head):
        profile["sector"] = m.group(1).strip()
    if m := re.search(r"(?im)^\s*>?\s*(?:frameworks|compliance)\s*[:\-]\s*(.+)$", head):
        profile["frameworks"] = m.group(1).strip()
    return profile


def discover() -> list[Dataset]:
    """Every scannable enterprise in the data dir, sorted by key. Re-scans the
    filesystem on every call so newly dropped-in files are picked up live."""
    out: list[Dataset] = []
    for csv in sorted(DATA_DIR.glob(f"*{VULN_SUFFIX}")):
        key = csv.name[: -len(VULN_SUFFIX)]
        if not key:
            continue
        arch = DATA_DIR / f"{key}{ARCH_SUFFIX}"
        if not arch.exists():
            continue  # not scannable without an architecture doc
        prof = _derive_profile(key, arch)
        out.append(Dataset(
            key=key, name=prof["name"], sector=prof["sector"],
            frameworks=prof["frameworks"], vuln_csv=csv, architecture_md=arch,
            findings=_count_rows(csv),
        ))
    return out


_lock = threading.Lock()
_active_key: str | None = None
# Preferred default on a cold boot when it's present, so behaviour matches the
# old hardcoded config; otherwise the first discovered dataset wins.
_PREFERRED_DEFAULT = "velon"


def _resolve_active(datasets: dict[str, Dataset]) -> str | None:
    global _active_key
    if _active_key in datasets:
        return _active_key
    if _PREFERRED_DEFAULT in datasets:
        _active_key = _PREFERRED_DEFAULT
    else:
        _active_key = next(iter(datasets), None)
    return _active_key


def get_active() -> Dataset:
    with _lock:
        datasets = {d.key: d for d in discover()}
        key = _resolve_active(datasets)
        if key is None:
            raise RuntimeError(f"No scannable datasets found in {DATA_DIR}")
        return datasets[key]


def set_active(key: str) -> Dataset:
    global _active_key
    datasets = {d.key: d for d in discover()}
    if key not in datasets:
        raise KeyError(key)
    with _lock:
        _active_key = key
    return datasets[key]
