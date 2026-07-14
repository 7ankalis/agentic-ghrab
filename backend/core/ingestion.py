"""Loads the Qualys-style vulnerability export CSV into a pandas DataFrame
and enriches every row with its computed GRS (deterministic, no LLM)."""
from __future__ import annotations

import pandas as pd

from core.config import VULN_CSV_PATH
from core.risk_engine import compute_grs, exposure_tier_label


def load_vulnerabilities(path=VULN_CSV_PATH) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["CVSS_Base"] = pd.to_numeric(df["CVSS_Base"], errors="coerce").fillna(0.0)

    grs_rows = []
    for _, row in df.iterrows():
        result = compute_grs(int(row["QID"]), float(row["CVSS_Base"]), str(row["CVE_ID"]))
        grs_rows.append({
            "GRS": result.grs,
            "GRS_Band": result.band,
            "GRS_SLA": result.sla,
            "Impact_Score": result.impact_score,
            "Exposure_Tier": exposure_tier_label(result.exposure_tier),
            "Exposure_Multiplier": result.exposure_multiplier,
            "EPSS": result.epss,
            "KEV": result.kev,
            "ACW": result.acw,
            "TCM": result.tcm,
            "CCF": result.ccf,
            "DORA_CIF": result.is_dora_cif,
            "DORA_SLA_Capped": result.dora_sla_capped,
        })
    grs_df = pd.DataFrame(grs_rows)
    df = pd.concat([df.reset_index(drop=True), grs_df.reset_index(drop=True)], axis=1)
    df = df.sort_values("GRS", ascending=False).reset_index(drop=True)
    return df


_vuln_singleton: pd.DataFrame | None = None


def get_vulnerabilities() -> pd.DataFrame:
    global _vuln_singleton
    if _vuln_singleton is None:
        _vuln_singleton = load_vulnerabilities()
    return _vuln_singleton
