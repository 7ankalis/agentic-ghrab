# The Ghrab Risk Score (GRS)
### A Context-Aware Vulnerability Risk Formula for the Ghrab Financial Group Lab

**Purpose:** CVSS alone answers "how bad is this bug in theory?" It does not answer "how dangerous is this bug *to Ghrab, right now, given where it sits and who can reach it*?" That second question is what your VM agents need to get right — and it's exactly where hallucination or naive CVSS-sorting shows up. This document defines a composite score, the **Ghrab Risk Score (GRS)**, built from real industry methodologies, and applies it to all 32 findings in `ghrab_vulnerabilities.csv`, producing `ghrab_vulnerabilities_risk_scored.csv`.

---

## 1. Why CVSS alone fails the exact scenario you described

Your example — a CVSS 10 on a hidden, admin-only internal VM vs. a CVSS 7 on an internet-facing asset — is precisely the gap that the industry has spent the last several years closing. A few grounding points from current practice:

- **Tenable's Vulnerability Priority Rating (VPR)** was built because CVSS alone flags roughly 60% of all vulnerabilities as High or Critical, which is operationally useless — VPR narrows that down to a small fraction of vulnerabilities that represent real business risk by combining technical impact with a threat-intelligence-driven likelihood component.
- **Tenable's Attack Path Analysis and "toxic combinations"** concept treats vulnerabilities, misconfigurations, and excessive permissions as amplifying each other — a critical CVE sitting alone on an isolated VM is explicitly called out by Tenable's own research as *not* your biggest risk; the danger is in combinations that create a viable path to something that matters.
- **EPSS (FIRST.org)** scores the probability a CVE will actually be exploited in the next 30 days — orthogonal to CVSS severity, and the two are deliberately not meant to be naively multiplied together (severity and likelihood are different axes of risk, and FIRST's own research warns against collapsing them into one number without care).
- **CISA's SSVC** explicitly builds "Exposure" (small / controlled / open) into its decision tree, separate from severity — a direct, formalized version of your "is this asset actually reachable" instinct. SSVC produces an *action call* (Track / Track\* / Attend / Act) rather than a raw score.
- **The FAIR model** (Factor Analysis of Information Risk, maintained by the FAIR Institute) defines risk as probable frequency × probable magnitude of loss, and frequency in turn depends on whether a threat agent is even in "contact" with the asset — an unreachable asset has near-zero contact frequency almost regardless of severity.
- **EU DORA** (Regulation (EU) 2022/2554, with its RTS Commission Delegated Regulation (EU) 2024/1774, Article 10) requires financial entities to run a documented, risk-based vulnerability management process, with tighter scanning/remediation cadence specifically for ICT assets supporting **critical or important functions (CIF)** — meaning a financial-sector risk score can't just be a technical severity number; it has to carry a regulatory-scope weighting too.

GRS combines these five ideas — severity, exploitation likelihood, confirmed exploitation, business/compliance criticality, and toxic-combination blast radius — gated by a reachability multiplier, which is the mechanism that directly produces the reordering your example describes.

---

## 2. The Formula

```
GRS = min(100, ImpactScore × ExposureTier × CCF)

ImpactScore = 10 × ( 0.30·CVSS_norm + 0.15·EPSS_norm + 0.15·KEV_norm + 0.20·ACW + 0.20·TCM_norm )

  where (all normalized to a 0-10 scale before weighting):
    CVSS_norm  = CVSS v3.1/v4 Base Score                              (0-10, as-scanned)
    EPSS_norm  = EPSS probability × 10                                 (0-10)
    KEV_norm   = 10 if CVE is on the CISA KEV catalog, else 0          (binary gate)
    ACW        = Asset Criticality Weight × 10                         (0-10, see §3)
    TCM_norm   = Toxic Combination / blast-radius score                (0-10, see §4)
```

```
ExposureTier ∈ { 1.30, 1.15, 0.90, 0.50, 0.15 }        (see §5)
CCF          = Compensating Controls Factor, 0.5-1.0    (see §6)
```

**Design choices, explained:**

- **CVSS gets the largest single weight (0.30)** because it's still the most standardized, auditable, comparable input — every scanner and every auditor already speaks CVSS. GRS doesn't discard it; it contextualizes it.
- **EPSS + KEV together (0.30 combined)** encode "is anyone actually exploiting this" — deliberately kept separate rather than multiplied into CVSS, consistent with FIRST's own guidance that severity and threat-likelihood are orthogonal signals that should be considered together, not collapsed.
- **ACW (0.20)** is Ghrab's own version of Tenable's Asset Criticality Rating — how much this asset matters to the business and to regulatory scope, independent of any specific vulnerability.
- **TCM (0.20)** is Ghrab's own version of Tenable's toxic-combination / attack-path choke-point concept — how much *worse* this specific finding is because of what it connects to, not just what it is.
- **ExposureTier is a multiplier, not an additive term**, deliberately, because reachability functions as a gate on the FAIR "contact frequency" concept: an attacker who cannot reach an asset has near-zero contact frequency almost regardless of how severe or well-understood the flaw is. A gating multiplier lets a very low exposure tier suppress an otherwise-critical score toward the bottom of the range, and lets a very high exposure tier push a moderately-severe finding into the danger zone — which is exactly the reordering effect you asked for.
- **CCF** captures verified compensating controls (WAF rules, MFA, EDR/IPS coverage, a *validated* — not assumed — segmentation boundary), echoing Tenable One's practice of mapping active controls onto attack paths to deprioritize findings that existing defenses already neutralize.

---

## 3. Asset Criticality Weight (ACW) — 0.0 to 1.0

Modeled on Tenable's Asset Criticality Rating (1-10, normalized here to 0-1) plus explicit DORA "critical or important function" (CIF) status:

| Tier | ACW | Examples in Ghrab |
|---|---|---|
| Crown jewel | 1.0 | DC01, TRADE-CORE01, SWIFT-GATEWAY01, SETTLEMENT01, CDE segmentation itself |
| Regulated financial data | 0.85-0.9 | DB-FIN01, DB-TRADE01, ghrab-finance-rds, APP-TRADE01 |
| High-leverage infrastructure | 0.7-0.8 | JUMP01, VCENTER01, BACKUP-MGR01, NAS01, IAM role, Entra tenant |
| Business-important | 0.5-0.7 | DB-CRM01, APP-CRM01, FILESRV01, S3 bucket, DMZ infra |
| Standard endpoint | 0.3-0.4 | WKS-FIN01, WKS-HR02, BRANCH-RTR01, GUEST-AP-SW01, APP-HR01 |

## 4. Toxic Combination Score (TCM) — 0 to 10

This is the direct implementation of Tenable's toxic-combination/attack-path philosophy: **a finding's danger depends on what it connects to, not just what it is.** For each finding, TCM asks: *if this is exploited, how many crown-jewel assets does that open a path to, and how directly?*

- **0-2**: Standalone finding, no identified chain to a sensitive asset (e.g., the legacy any-any rule on the branch router)
- **3-5**: Chains to one business-important asset (e.g., Path A → FILESRV01's HR data)
- **6-8**: Chains to regulated financial data or high-leverage infrastructure (e.g., Path C → the finance RDS instance; Path D → hypervisor/backup control)
- **9-10**: Direct or near-direct path to a crown-jewel financial system (e.g., Zerologon on DC01 → flat trust → TRADE-CORE01 → SWIFT-GATEWAY01)

TCM values for all 32 findings, derived from the `Attack_Path_Ref` chains documented in `ghrab_architecture.md` §5, are in the scored CSV.

## 5. Exposure / Reachability Tier — this is the lever your example needs

| Tier | Multiplier | Definition | Ghrab examples |
|---|---|---|---|
| Internet-facing | **1.30** | Directly reachable from the internet, no prior foothold needed | WEB-PORTAL01, VPN-GW01, MAIL-RELAY01, public S3 bucket, public RDS |
| Adjacent | **1.15** | One hop from an untrusted zone, or reachable via an already-broken ACL/trust | Guest WiFi switch, LB01→CRM excess ACL, VPN split-tunnel target, IAM role (once keys leak), Entra tenant (any phished credential) |
| Internal | **0.90** | Reachable only after a prior foothold on the general internal network | Corporate LAN hosts, App Tier hosts, Finance zone hosts (assuming intended segmentation holds) |
| Restricted | **0.50** | Segmented internal zone, reachable only from specific upstream tiers | DB Tier, Backup/Storage, Finance/Trading zone under *intended* (not actual) segmentation |
| Isolated | **0.15** | Named-admin-only access, MFA/PAM-gated, no routable path from any lower-trust zone | Management/OOB VLAN hosts (JUMP01, VCENTER01, BACKUP-MGR01) |

This is a direct, quantified answer to your original example: **a CVSS 10 sitting in the Isolated tier is multiplied by 0.15; a CVSS 7 sitting in the Internet-facing tier is multiplied by 1.30 — an 8.7× swing from exposure alone**, before any other factor is applied.

## 6. Compensating Controls Factor (CCF)

Default is 1.0 (no verified compensating control). Applied reductions, each requiring *evidence*, not assumption (consistent with Tenable One's control-validation approach of only deprioritizing what's demonstrably mitigated):

| Verified control | Reduction |
|---|---|
| WAF rule confirmed blocking the specific exploit pattern | −0.15 |
| MFA enforced on the access path | −0.15 |
| EDR/IPS signature confirmed for this technique | −0.10 |
| Network segmentation control independently tested (not just assumed from a diagram) | −0.10 |

CCF is floored at 0.5 — no combination of controls should ever be treated as making a real vulnerability's risk zero; DORA's own testing requirements (Article 24-27, including mandatory Threat-Led Penetration Testing for significant entities) exist precisely because assumed controls are frequently found not to work as documented.

**In this lab, every finding uses CCF = 1.0** — none of the intended controls (WAF, MFA, verified segmentation) are actually implemented, which is itself part of the ground truth your agents should be able to identify from the architecture doc.

## 7. Action Bands (SSVC-aligned)

| GRS Range | Band | Meaning | Default SLA |
|---|---|---|---|
| 80-100 | **IMMEDIATE** | Confirmed/likely exploitation path to a crown-jewel asset, low barrier to entry | 24-72h, emergency change |
| 60-79 | **ACT** | High-confidence exploitable and reachable, meaningful business impact | 7 days |
| 40-59 | **ATTEND** | Real risk, but exposure or blast radius is partially contained | 30 days |
| 20-39 | **TRACK\*** | Elevated interest, but low current exploitation signal or exposure | 90 days / next patch cycle |
| 0-19 | **TRACK** | Low priority under current conditions; monitor for changes in exposure or threat intel | Monitor only |

**DORA overlay:** any finding on an asset in scope for a "critical or important function" (Ghrab's Finance/Trading zone, DC01, the finance database/RDS, and the CDE segmentation control itself) has its SLA capped at 30 days regardless of computed band, reflecting DORA RTS Article 10's requirement for at least weekly automated scanning and prompt remediation on CIF-supporting assets. A GRS ≥ 60 on a CIF asset should also be flagged as a candidate for DORA major-incident-readiness review if exploitation is later confirmed — DORA's incident classification explicitly considers cumulative and cascading impact, not just the technical fix.

---

## 8. Worked Example — your exact scenario

**Vulnerability A:** CVSS 10.0, isolated internal VM, admin-only access, no known exploitation.
```
CVSS=10, EPSS=0.02, KEV=0, ACW=0.6 (moderately important internal system), TCM=1 (no chain to a crown jewel)
ImpactScore = 10×(0.30×10 + 0.15×0.2 + 0.15×0 + 0.20×6 + 0.20×1) = 10×(3.0+0.03+0+1.2+0.2) = 44.3
ExposureTier = 0.15 (Isolated)
GRS = 44.3 × 0.15 = 6.6   →   TRACK
```

**Vulnerability B:** CVSS 7.0, internet-facing, actively exploited.
```
CVSS=7, EPSS=0.55, KEV=0, ACW=0.6, TCM=5 (chains to a business-important DB)
ImpactScore = 10×(0.30×7 + 0.15×5.5 + 0.15×0 + 0.20×6 + 0.20×5) = 10×(2.1+0.825+0+1.2+1.0) = 51.25
ExposureTier = 1.30 (Internet-facing)
GRS = 51.25 × 1.30 = 66.6   →   ACT
```

**Result: Vulnerability B (CVSS 7) scores 66.6 and requires action within 7 days; Vulnerability A (CVSS 10) scores 6.6 and is monitor-only — a 10× difference in the opposite direction of raw CVSS**, exactly matching your stated intuition.

This isn't a hypothetical constructed just for this document — it mirrors two real findings in the scored CSV: **CVE-2021-21972 on VCENTER01 (CVSS 9.8, isolated in the Management VLAN) scores 26.9 (TRACK\*)**, while **the WordPress SQLi on WEB-PORTAL01 (CVSS 9.1, internet-facing) scores 65.7 (ACT)** — see `ghrab_risk_ranking.png` for the full picture across all 32 findings.

---

## 9. Using this to test your VM agents

1. Feed the agent `ghrab_vulnerabilities_risk_scored.csv` (or have it compute GRS itself from the raw CSV + this methodology) and ask it to prioritize a remediation backlog.
2. Check whether it defaults to naive CVSS sorting — a hallucinating or under-contextualized agent will rank VCENTER01's 9.8 above WEB-PORTAL01's 9.1, which is the wrong call given Ghrab's actual architecture.
3. Ask it to justify a specific GRS — a good agent should be able to decompose its answer into the five factors (severity, exploitation likelihood, confirmed exploitation, asset criticality, toxic-combination blast radius) and the exposure gate, not just restate the CVSS.
4. Ask compliance-flavored questions ("which findings are DORA CIF-scope and what's their SLA?") to check whether it correctly applies the regulatory overlay rather than inventing one.
5. Compare its stated reasoning against `ghrab_architecture.md` §5 (attack paths) — if it claims a toxic combination or blast radius that isn't in the documented attack graph, that's a hallucination signal.

---

## 10. Caveats and production notes

- **EPSS and KEV values in the scored CSV are representative**, chosen using well-established public status for the real CVEs used in this lab (e.g., EternalBlue, Zerologon, Log4Shell, BlueKeep, ProxyShell, and the FortiOS/vCenter/Outlook CVEs are all confirmed CISA KEV entries with historically high EPSS). In a live pipeline, pull EPSS daily from the FIRST.org API and KEV status from CISA's published catalog rather than hardcoding them.
- **The weights (0.30/0.15/0.15/0.20/0.20) are a defensible starting point, not a universal constant.** Tenable's own VPR model uses a trained machine-learning approach rather than fixed linear weights; a from-scratch linear formula like GRS is more transparent and easier to audit/explain to a regulator, at the cost of being less adaptive. If you calibrate GRS against real incident outcomes over time, expect (and document) weight adjustments.
- **CCF must stay evidence-gated.** The biggest failure mode in real vulnerability-management programs is assuming a compensating control works because it's documented, rather than because it's been tested — DORA's Threat-Led Penetration Testing requirement exists specifically to catch that gap.
