"""
LLM capability extraction — the intelligent half of the Phase 1 hybrid classifier.

`core/capability.py` maps a finding to attacker capabilities with regex/keyword
rules: fast, free, deterministic, but blind to any wording its keywords don't
cover (e.g. "shared local Administrator credential" reads as credential reuse to
a human but matches no `cred` keyword). This module adds an LLM pass that reads
each finding's full Title/Description/Consequence/CVSS/CVE and returns the same
structured effects/grants/preconditions — catching what the regex misses.

Deliberately narrow contract: the model classifies WHAT the finding grants an
attacker (effects, grants, entry-ability). It never names hosts or zones — those
pivots are re-derived deterministically from the finding text in capability.py's
merge, so the LLM can never introduce a host/QID that isn't in scope (hallucination
stays 0 by construction). Output is validated against a strict Pydantic model and
vocab-filtered; anything malformed is dropped, not trusted.

Batched + cached: each finding's extraction is cached under CAPABILITY_CACHE_DIR
keyed by a hash of the finding content + intended model id (so re-runs are
token-free and deterministic at temperature 0), and cache-misses are sent in
batched calls of CAPABILITY_LLM_BATCH_SIZE findings rather than one call each — a
full run costs a handful of calls, which keeps it under free-tier RPM caps. No
provider configured ⇒ this module is never reached (capability.classify_all_hybrid
short-circuits to regex-only).
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pandas as pd
from pydantic import BaseModel, Field, ValidationError

from core.capability import (
    CLOUD_PRIV_ESC, CREDENTIAL_THEFT, GRANT_CLOUD_ADMIN, GRANT_DOMAIN_ADMIN,
    IMPACT, INITIAL_ACCESS, LATERAL, PRE_ADJACENT, PRE_CLOUD, PRE_CREDS,
    PRE_FOOTHOLD, PRE_UNAUTH, PRIV_ESC, RCE_SYSTEM, RCE_USER, SEGMENTATION_BREAK,
)
from core.config import (
    CAPABILITY_CACHE_DIR, CAPABILITY_LLM_BATCH_SIZE, CAPABILITY_LLM_MAX_TOKENS,
    CAPABILITY_LLM_TEMPERATURE, DEFAULT_AGENT_MODEL, DEFAULT_AGENT_PROVIDER,
    FALLBACK_ORDER, PROVIDERS,
)
from core.providers import ProviderUnavailable, call_llm

logger = logging.getLogger(__name__)

_ROLE = "capability"
_VALID_EFFECTS = {
    INITIAL_ACCESS, RCE_SYSTEM, RCE_USER, CREDENTIAL_THEFT, PRIV_ESC, LATERAL,
    SEGMENTATION_BREAK, CLOUD_PRIV_ESC, IMPACT,
}
_VALID_GRANTS = {GRANT_DOMAIN_ADMIN, GRANT_CLOUD_ADMIN}
_VALID_PRE = {PRE_UNAUTH, PRE_ADJACENT, PRE_FOOTHOLD, PRE_CREDS, PRE_CLOUD}


class LLMCapability(BaseModel):
    """Strict schema for the model's per-finding output. Unknown tokens are
    filtered out by `sanitized()` rather than raising, so one odd token never
    discards an otherwise-good extraction."""
    effects: list[str] = Field(default_factory=list)
    grants: list[str] = Field(default_factory=list)
    precondition: str = ""
    is_entry: bool = False
    mitre_tactic: str = ""
    evidence: str = ""

    def sanitized(self) -> "LLMCapability":
        return LLMCapability(
            effects=[e for e in dict.fromkeys(self.effects) if e in _VALID_EFFECTS],
            grants=[g for g in dict.fromkeys(self.grants) if g in _VALID_GRANTS],
            precondition=self.precondition if self.precondition in _VALID_PRE else "",
            is_entry=bool(self.is_entry),
            mitre_tactic=str(self.mitre_tactic or "")[:40],
            evidence=str(self.evidence or "")[:240],
        )


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM = (
    "You are a vulnerability capability extractor. Given ONE finding, output what "
    "an attacker GAINS from exploiting it, using ONLY this vocabulary.\n"
    "effects (choose all that apply): "
    f"{INITIAL_ACCESS} (foothold from outside a boundary), "
    f"{RCE_SYSTEM} (code exec as SYSTEM/root — full host), "
    f"{RCE_USER} (code exec at lower privilege), "
    f"{CREDENTIAL_THEFT} (yields credentials usable elsewhere, incl. shared/reused/"
    "hardcoded/default creds, hash/ticket theft), "
    f"{PRIV_ESC} (elevates on host / to domain / to cloud admin), "
    f"{SEGMENTATION_BREAK} (opens a network boundary between zones/hosts, incl. "
    "excessive firewall rules, VLAN hop, DB links, flat trust), "
    f"{CLOUD_PRIV_ESC} (cloud identity/IAM escalation), "
    f"{LATERAL} (explicit host-to-host movement), "
    f"{IMPACT} (terminal business impact: data exfiltration, settlement/payment "
    "tampering, full DB/share compromise).\n"
    f"grants (only if truly implied): {GRANT_DOMAIN_ADMIN} (AD-wide compromise), "
    f"{GRANT_CLOUD_ADMIN} (cloud tenant admin).\n"
    f"precondition (single best): {PRE_UNAUTH} (no prior access), "
    f"{PRE_ADJACENT} (same segment), {PRE_FOOTHOLD} (code exec on host already), "
    f"{PRE_CREDS} (valid creds), {PRE_CLOUD} (cloud token).\n"
    "is_entry = true only if internet/untrusted-reachable and exploitable without "
    "prior access. Reason ONLY from the finding text; do NOT invent CVEs, hosts, or "
    "effects the text does not support. Respond with ONE JSON object, no prose."
)

_SCHEMA_HINT = (
    'For EACH finding return an object {"effects":[...],"grants":[...],'
    '"precondition":"...","is_entry":true|false,"mitre_tactic":"<ATT&CK tactic>",'
    '"evidence":"<= 20 words quoting the phrase that justifies the strongest effect"}'
)


def _finding_fields(row: pd.Series) -> dict:
    """The stable subset of a finding the extraction depends on (also the cache
    key material — must not include volatile/derived columns like GRS)."""
    return {
        "qid": int(row["QID"]),
        "title": str(row.get("Title", "")),
        "category": str(row.get("Category", "")),
        "cvss_vector": str(row.get("CVSS_Vector", "")),
        "cve": str(row.get("CVE_ID", "")),
        "description": str(row.get("Description", "")),
        "consequence": str(row.get("Consequence", "")),
        "exposure": str(row.get("Exposure_Tier", "")),
        "zone": str(row.get("Zone", "")),
    }


def _finding_block(f: dict) -> str:
    return (
        f"[QID {f['qid']}] Title: {f['title']} | Category: {f['category']} | "
        f"CVSS: {f['cvss_vector']} | CVE: {f['cve']} | Zone: {f['zone']} | "
        f"Exposure: {f['exposure']}\n"
        f"  Description: {f['description']}\n  Consequence: {f['consequence']}"
    )


def _batch_user_prompt(fields_list: list[dict]) -> str:
    blocks = "\n\n".join(_finding_block(f) for f in fields_list)
    return (
        f"Classify EACH of the {len(fields_list)} findings below. {_SCHEMA_HINT}\n"
        'Respond as ONE JSON object mapping each finding\'s QID (as a string key) to '
        'its capability object, e.g. {"38689": {"effects":["rce_system"], ...}, ...}. '
        "Include every QID exactly once and add no other keys.\n\n"
        f"FINDINGS:\n{blocks}"
    )


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _intended_model(session_state) -> str:
    """The provider:model the capability role would resolve to from config — used
    as cache-key material so a model change invalidates cached classifications."""
    prov = (session_state.get(f"agent_provider_{_ROLE}") if session_state else None) \
        or DEFAULT_AGENT_PROVIDER.get(_ROLE) or FALLBACK_ORDER[0]
    role_default = DEFAULT_AGENT_MODEL.get(_ROLE) if prov == DEFAULT_AGENT_PROVIDER.get(_ROLE) else None
    model = (session_state.get(f"agent_model_{_ROLE}") if session_state else None) \
        or role_default or PROVIDERS[prov].default_model
    return f"{prov}:{model}"


def _cache_key(fields: dict, model_id: str) -> str:
    blob = json.dumps({**fields, "model": model_id}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cache_read(cache_dir: Path, key: str) -> LLMCapability | None:
    path = cache_dir / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return LLMCapability(**data.get("capability", {})).sanitized()
    except (json.JSONDecodeError, ValidationError, OSError):
        return None


def _cache_write(cache_dir: Path, key: str, cap: LLMCapability,
                 model_id: str, actual_model: str) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    payload = {"model_intended": model_id, "model_actual": actual_model,
               "capability": cap.model_dump()}
    try:
        (cache_dir / f"{key}.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:  # cache is best-effort; a write failure never breaks a run
        logger.warning("capability cache write failed for %s: %s", key, exc)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _loads(text: str) -> dict:
    """Parse a JSON object out of a completion, tolerating ``` fences / prose."""
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.startswith("json"):
            t = t[4:]
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        s, e = t.find("{"), t.rfind("}")
        if s != -1 and e != -1:
            return json.loads(t[s:e + 1])
        raise


def _batch_max_tokens(n: int) -> int:
    """Output budget for a batch of n findings — each object is small, so this
    scales linearly with a floor and a hard cap to keep cost bounded."""
    return min(4096, max(CAPABILITY_LLM_MAX_TOKENS, 160 * n + 400))


def _parse_batch(data) -> dict[int, dict]:
    """Normalise the model's batch reply to {qid:int -> capability dict},
    tolerating a {qid: obj} map, a {results:[...]} wrapper, or a bare list."""
    items = None
    if isinstance(data, dict):
        for k in ("results", "findings", "capabilities", "classifications"):
            if isinstance(data.get(k), list):
                items = data[k]
                break
        if items is None:                    # plain {qid: obj} mapping
            out: dict[int, dict] = {}
            for k, v in data.items():
                if isinstance(v, dict):
                    try:
                        out[int(k)] = v
                    except (TypeError, ValueError):
                        continue
            return out
    elif isinstance(data, list):
        items = data
    out = {}
    for it in items or []:
        if isinstance(it, dict) and "qid" in it:
            try:
                qid = int(it["qid"])
            except (TypeError, ValueError):
                continue
            out[qid] = {k: v for k, v in it.items() if k != "qid"}
    return out


def _raw_llm_extract_batch(fields_list: list[dict],
                           session_state) -> tuple[dict[int, dict], str]:
    """One provider call classifying a whole batch. Returns ({qid: parsed_json},
    actual_model). Isolated so tests can monkeypatch it without a provider."""
    res = call_llm(
        _ROLE, _SYSTEM, _batch_user_prompt(fields_list), session_state=session_state,
        json_mode=True, max_tokens=_batch_max_tokens(len(fields_list)),
        temperature=CAPABILITY_LLM_TEMPERATURE,
        detail=f"classify {len(fields_list)} findings",
    )
    return _parse_batch(_loads(res.text)), res.model


def _chunks(seq: list, n: int):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def classify_llm(df: pd.DataFrame, session_state=None,
                 cache_dir: Path | None = None) -> dict[int, LLMCapability]:
    """LLM capability extraction for every finding, cached per finding but issued
    in batched calls (CAPABILITY_LLM_BATCH_SIZE findings each) so a full run costs
    a handful of calls, not one-per-finding. Returns a (possibly partial)
    {qid: LLMCapability}; a finding the model omits or that errors is simply
    absent, so the caller keeps its regex classification for it. If no provider
    can serve, remaining batches are skipped and cached results are returned."""
    cache_dir = cache_dir or CAPABILITY_CACHE_DIR
    model_id = _intended_model(session_state)
    out: dict[int, LLMCapability] = {}
    misses: list[tuple[int, dict, str]] = []
    for _, row in df.iterrows():
        fields = _finding_fields(row)
        key = _cache_key(fields, model_id)
        cached = _cache_read(cache_dir, key)
        if cached is not None:
            out[fields["qid"]] = cached
        else:
            misses.append((fields["qid"], fields, key))

    for chunk in _chunks(misses, max(1, CAPABILITY_LLM_BATCH_SIZE)):
        fields_list = [f for _, f, _ in chunk]
        try:
            raw_map, actual = _raw_llm_extract_batch(fields_list, session_state)
        except ProviderUnavailable:
            logger.warning("capability LLM: no provider available; keeping regex "
                           "for the remaining %d finding(s)",
                           sum(len(c) for c in [chunk]))
            break
        except Exception as exc:  # noqa: BLE001 — one bad batch never fails the run
            logger.warning("capability LLM batch failed (%d findings): %s",
                           len(fields_list), exc)
            continue
        for qid, _fields, key in chunk:
            raw = raw_map.get(qid)
            if not isinstance(raw, dict):
                continue  # model omitted this finding → keep its regex result
            try:
                cap = LLMCapability(**raw).sanitized()
            except ValidationError as exc:
                logger.warning("capability LLM malformed for QID %s: %s", qid, exc)
                continue
            out[qid] = cap
            _cache_write(cache_dir, key, cap, model_id, actual)
    return out
