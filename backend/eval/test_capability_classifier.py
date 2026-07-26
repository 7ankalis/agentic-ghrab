"""
Phase 1 unit tests for the hybrid capability classifier.

Covers the three things the brief calls out: (1) regex-only mode is byte-identical
to today, (2) known findings map to the expected capabilities, and (3) a
deliberately oddly-worded finding that the regex misses is now caught by the LLM
path — with provenance recorded and host pivots still derived deterministically
from the finding text (so no out-of-scope host can be introduced).

The LLM is stubbed (no provider/network) so these stay fast and deterministic.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/ on path

import pandas as pd  # noqa: E402
import pytest  # noqa: E402

from core import capability, capability_llm, datasets, providers  # noqa: E402
from core.capability import (  # noqa: E402
    CREDENTIAL_THEFT, GRANT_DOMAIN_ADMIN, PRIV_ESC, RCE_SYSTEM,
    classify_all, classify_all_hybrid,
)
from core.capability_llm import LLMCapability  # noqa: E402
from core.cmdb import reset_cmdb  # noqa: E402
from core.ingestion import get_vulnerabilities, reset_vulnerabilities  # noqa: E402
from eval.detection import datasets_with_oracle  # noqa: E402


def _load_df(key: str) -> pd.DataFrame:
    datasets.set_active(key)
    reset_vulnerabilities()
    reset_cmdb()
    return get_vulnerabilities()


@pytest.mark.parametrize("key", datasets_with_oracle())
def test_regex_only_mode_is_identical_to_today(key):
    df = _load_df(key)
    assert classify_all_hybrid(df, use_llm=False) == classify_all(df), (
        f"{key}: hybrid classifier with the LLM disabled diverged from the pure "
        f"regex classifier — graceful degradation must be exact")


def test_known_findings_map_to_expected_capabilities():
    df = _load_df("ghrab")
    caps = classify_all(df)
    # EternalBlue (CVE-2017-0144) → SYSTEM-level RCE.
    assert RCE_SYSTEM in caps[38689].effects
    # Zerologon → privilege escalation yielding Domain Admin.
    assert PRIV_ESC in caps[90512].effects
    assert GRANT_DOMAIN_ADMIN in caps[90512].grants
    # Regex classifications carry no LLM provenance.
    assert caps[38689].source == "regex"


def _odd_credential_df() -> pd.DataFrame:
    """Two findings: an oddly-worded credential-reuse issue on HOST-A that names
    HOST-B (no `cred` keyword the regex matches), plus a benign HOST-B finding so
    HOST-B is a known asset the pivot can resolve to."""
    base = {
        "Severity": "High", "CVSS_Base": 8.1, "CVE_ID": "",
        "IP_Address": "10.0.0.9", "Port": "445", "Service_Protocol": "smb",
        "Consequence": "Attacker moves between the two hosts.",
        "Remediation": "Rotate.", "Patch_Available": "No",
        "Responsible_Team": "IT", "Status": "Open", "Compliance_Ref": "",
        "GRS": 7.0,
    }
    rows = [
        {**base, "QID": 999001, "Title": "Break-glass secret drift on HOST-A",
         "Category": "Configuration", "CVSS_Vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "Description": "Operators reuse the same break-glass secret between HOST-A "
                        "and HOST-B through an out-of-band channel.",
         "Hostname": "HOST-A", "VLAN_ID": "10", "Zone": "Server", "Exposure_Tier": "Internal"},
        {**base, "QID": 999002, "Title": "Verbose banner on HOST-B",
         "Category": "Information", "CVSS_Vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "Description": "HOST-B discloses its version banner.",
         "Hostname": "HOST-B", "VLAN_ID": "10", "Zone": "Server", "Exposure_Tier": "Internal"},
    ]
    return pd.DataFrame(rows)


def test_llm_catches_a_regex_gap_with_provenance(monkeypatch, tmp_path):
    df = _odd_credential_df()

    # Regex alone does not see credential reuse in this wording.
    assert CREDENTIAL_THEFT not in classify_all(df)[999001].effects

    # Force the hybrid path on, isolate the cache, and stub the provider call.
    monkeypatch.setattr(providers, "any_provider_configured", lambda ss: True)
    monkeypatch.setattr(capability_llm, "CAPABILITY_CACHE_DIR", tmp_path)

    def fake_batch_extract(fields_list, session_state):
        out = {}
        for f in fields_list:
            if f["qid"] == 999001:
                out[999001] = {"effects": [CREDENTIAL_THEFT], "grants": [],
                               "precondition": "", "is_entry": False,
                               "mitre_tactic": "Credential Access",
                               "evidence": "reuse the same break-glass secret"}
            else:
                out[f["qid"]] = {"effects": [], "grants": [], "precondition": ""}
        return out, "stub-model"

    monkeypatch.setattr(capability_llm, "_raw_llm_extract_batch", fake_batch_extract)

    caps = classify_all_hybrid(df, use_llm=True)  # explicit: the flag defaults off
    cap = caps[999001]
    assert CREDENTIAL_THEFT in cap.effects, "LLM-supplied effect was not merged in"
    assert cap.source in ("llm", "both") and cap.capability_confidence in ("high", "medium")
    assert cap.evidence
    # Pivot is derived from the finding text against real assets — HOST-B resolves,
    # nothing out-of-scope is introduced.
    assert "HOST-B" in cap.host_pivots
    assert all(h in {"HOST-A", "HOST-B"} for h in cap.host_pivots)


def test_llm_pivot_to_unknown_host_is_dropped(monkeypatch, tmp_path):
    """A credential effect whose text names a host that is not a real asset must
    not produce a pivot — the graph never learns an out-of-scope host."""
    df = _odd_credential_df()
    df.loc[0, "Description"] = ("Operators reuse the same break-glass secret between "
                               "HOST-A and GHOST-Z9 (an asset not in inventory).")
    monkeypatch.setattr(providers, "any_provider_configured", lambda ss: True)
    monkeypatch.setattr(capability_llm, "CAPABILITY_CACHE_DIR", tmp_path)
    monkeypatch.setattr(capability_llm, "_raw_llm_extract_batch",
                        lambda fl, ss: ({f["qid"]: ({"effects": [CREDENTIAL_THEFT]}
                                                    if f["qid"] == 999001 else {"effects": []})
                                         for f in fl}, "stub-model"))

    cap = classify_all_hybrid(df, use_llm=True)[999001]
    assert CREDENTIAL_THEFT in cap.effects
    assert "GHOST-Z9" not in cap.host_pivots
    assert all(h in {"HOST-A", "HOST-B"} for h in cap.host_pivots)


def test_malformed_llm_output_is_dropped_not_trusted(monkeypatch, tmp_path):
    """Unknown effect tokens are filtered; the finding keeps its regex result."""
    bad = LLMCapability(effects=["teleport", "credential_theft", "nonsense"],
                        grants=["god_mode"], precondition="wishful").sanitized()
    assert bad.effects == [CREDENTIAL_THEFT]
    assert bad.grants == []
    assert bad.precondition == ""
