"""Content fingerprint of the analysis inputs.

Used to answer "have we already analyzed exactly this?" without a human
having to remember. Deliberately scoped to the *data* (CSV + CMDB/architecture
+ risk methodology) — not to runtime knobs like which LLM provider is
assigned to which agent, since a provider swap is a deliberate operator
choice that should produce a fresh run, not a silent duplicate match.
"""
from __future__ import annotations

import hashlib

from core.config import (
    RISK_METHODOLOGY_MD_PATH, active_architecture_md, active_vuln_csv,
)


def compute_input_fingerprint() -> str:
    # Resolved at call time — which CSV + architecture doc are the inputs depends
    # on the currently active enterprise, not a fixed path.
    input_files = (active_vuln_csv(), active_architecture_md(), RISK_METHODOLOGY_MD_PATH)
    h = hashlib.sha256()
    for path in input_files:
        if path is None:
            h.update(b"<none>")
            continue
        h.update(path.name.encode())
        if path.exists():
            h.update(path.read_bytes())
        else:
            h.update(b"<missing>")
    return h.hexdigest()
