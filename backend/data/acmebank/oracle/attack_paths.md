# AcmeBank — Held-Out Attack-Path Oracle (SCORING KEY ONLY)

> **DO NOT FEED THIS FILE TO ANY AGENT, GRAPH, OR CLASSIFIER.**
> This is the held-out ground truth used *only* to score detection
> (precision/recall/F1) against what the engine rediscovers on its own. Nothing
> in the detection pipeline loads this directory — not `core/cmdb.py`, not
> `core/attack_graph.py`, not any LLM agent. The engine must reconstruct these
> routes from the structured CMDB (`cmdb/*.csv`) + the scan (`vulnerabilities.csv`)
> alone. Guard: `eval/test_no_oracle_leakage.py`.

**The number of attack paths is a property of the topology, not a target.** The
paths below are the routes that genuinely exist in the AcmeBank CMDB given its
misconfigurations, credential reuse, and dependencies. An accurate engine surfaces
exactly these — no invented routes, no missed routes, and never a hop across a
`Should-Not-Exist` zone pair. As the CMDB changes, this list changes with it.

Crown-jewel objectives (business ground truth, independent of any engine
heuristic): **DC01** (identity/domain), **PAY-CORE01 / SETTLEMENT01 / SWIFT-GW01**
(Payments/CDE), the customer & payment data stores **DB-EBANK01 / DB-PAY01**, and
the cloud finance data **acmebank-finance-rds**.

---

## PATH A — Easy: Public cloud misconfiguration → finance data

- **A1 (direct):** `INTERNET → acmebank-finance-rds` — RDS `publicly-accessible`
  flag enabled (**QID 300067**, `RULE-AB-014`).
- **A2 (chained):** `INTERNET → acmebank-public-assets` (S3 public read,
  **QID 300011**, `RULE-AB-013`) → leaked backup yields IAM role creds
  (`REL-AB-115`) → **acmebank-app-role** has `AdministratorAccess`
  (**QID 300045**, `REL-AB-116`) → `acmebank-finance-rds`.
- **Impact:** exposure of finance/customer data held in AWS. **Objective:** cloud data.

## PATH B — Medium: Internet web RCE → eBanking customer database

`INTERNET → WEB-PORTAL01` (Apache path-traversal RCE, **QID 38701**,
`RULE-AB-001`) → **DMZ→App tier** `ANY/ANY` firewall over-permission
(**QID 200114**, `RULE-AB-003`, the *Excessive* rule replacing the intended
`RULE-AB-002` tcp/8443) → `APP-EBANK01` → **Depends on** `DB-EBANK01` where the
app account holds `db_owner` (**QID 200338**, `REL-AB-102`).
- **Impact:** full read/write of eBanking customer data. **Objective:** DB-EBANK01.

## PATH C — Medium/Hard: Web → payments app → payments DB → settlement (stale DB link)

`INTERNET → WEB-PORTAL01` (**QID 38701**) → **DMZ→App** `ANY/ANY`
(**QID 200114**, `RULE-AB-003`) → `APP-PAY01` → hardcoded DB credentials in app
config (**QID 150233**, `REL-AB-103`) → `DB-PAY01` → **stale Oracle DB link into
the CDE** (**QID 200622**, `REL-AB-105`) → `SETTLEMENT01`.
- **Key point:** the App→CDE crossing is **not** a network rule
  (`RULE-AB-012` is `Should-Not-Exist`) — it is a non-network **DB-link** pivot.
  An engine that only reasons over firewall rules misses this. **Objective:** SETTLEMENT01 (CDE).

## PATH D — Medium: Guest WiFi → corporate LAN → Domain Admin → CDE

`INTERNET → GUEST-AP-SW01` (guest 802.1Q trunk VLAN-hop, **QID 105001**,
`RULE-AB-008`, VLAN 70→10) → corporate LAN → `FILESRV01` (SMBv1 EternalBlue,
**QID 38689**) and/or shared local-admin pass-the-hash (**QID 90013**,
`CRED-AB-01`) → `DC01` (**Zerologon**, **QID 91001**) ⇒ **Domain Admin** →
**flat trust corporate→CDE** (**QID 200512**, `RULE-AB-005`, `CRED-AB-03`) →
`PAY-CORE01` / `SWIFT-GW01`.
- **Impact:** domain-wide compromise reaching the cardholder data environment.
  **Objectives:** DC01, PAY-CORE01, SWIFT-GW01.

## PATH E — Medium/Hard: DMZ → VPN split-tunnel → management plane → hypervisor / DA blast

`INTERNET → MAIL-RELAY01` (Exchange ProxyLogon RCE, **QID 38702**) *or*
`WEB-PORTAL01` → **VPN split-tunnel into the management VLAN** (**QID 200401**,
`RULE-AB-007`, DMZ→Mgmt) → then either:
- `JUMP01` cached Domain-Admin session (**QID 90211**, `CRED-AB-03`) ⇒ Domain
  Admin → CDE (via `RULE-AB-005`); or
- `VCENTER01` unauthenticated RCE (**QID 200800**) ⇒ **hypervisor blast radius**
  over every guest VM it hosts (`REL-AB-V01…V10`), including the CDE crowns
  `PAY-CORE01`, `SETTLEMENT01`, `SWIFT-GW01`.
- **Note:** the direct `Corporate→Management` pair is `Should-Not-Exist`
  (`RULE-AB-006`); management is reachable here *only* via the Excessive VPN
  split-tunnel. **Objectives:** PAY-CORE01, SETTLEMENT01, SWIFT-GW01.

## PATH F — Hard: Kerberoast → Domain Admin → CDE

Web foothold → `APP-PAY01` → Kerberoastable `svc_pay` weak password
(**QID 90344**, `CRED-AB-02`) → offline crack → domain escalation ⇒ Domain Admin
→ flat trust into CDE (**QID 200512**, `RULE-AB-005`) → `PAY-CORE01`.
- **Objective:** PAY-CORE01 (CDE). Variant of D reaching DA via credential access
  rather than a DC exploit.

## PATH G — Hard: Shared SWIFT-admin credential → SWIFT gateway

From any Domain-Admin / CDE foothold (Paths D, E, F) → **shared SWIFT-admin
credential that is identical to Domain Admin** (**QID 200533**, `CRED-AB-04`,
valid on `PAY-CORE01` + `SWIFT-GW01`) → `SWIFT-GW01`.
- **Impact:** unauthorized interbank payment-message injection. Violates SWIFT CSP
  dedicated-identity. **Objective:** SWIFT-GW01.

### Supporting blast-radius (not a standalone entry path)
- `BACKUP-MGR01` (reached via the management plane in Path E) **Backs up**
  `DB-PAY01` and `DR-PAY-CORE01` (`REL-AB-111`, `REL-AB-113`): compromise of the
  backup manager exposes payment data at rest and the DR mirror.

---

## Forbidden hops — MUST NOT appear in any output (deterministic or LLM)

These zone pairs are `Should-Not-Exist` in `net_reachability.csv`. No output hop
may cross them; any that does is fabricated:

| Rule | Forbidden crossing |
|---|---|
| `RULE-AB-006` | Corporate LAN (10) → Management/OOB (50) — *directly* |
| `RULE-AB-011` | Corporate LAN (10) → DB tier (30) — *directly* |
| `RULE-AB-012` | App tier (21) → Payments/CDE (40) — *directly* (Path C crosses via DB-link, not the network) |
| `RULE-AB-015` | Guest WiFi (70) → Payments/CDE (40) — *directly* |

## Decoys — MUST yield NO attack path

- `APP-HR01 → DB-HR01` (`REL-AB-104`) is a legitimate HR dependency whose only
  finding is a benign reflected-XSS (**QID 500002**); it reaches no crown jewel.
- Benign posture findings with no movement value: TLS 1.0 on `LB01`
  (**QID 500001**), SNMP `public` on `CORE-SW01` (**QID 500003**), missing HTTP
  headers on `WEB-PORTAL01` (**QID 500004**).

## Seeded data-quality defects (the validator MUST report these)

- **Orphan CI:** `SRV-AB-1092` (ORPHAN-DECOM01) — referenced by no relationship.
- **Dangling reference:** `REL-AB-199` targets `SRV-AB-9999`, which is not a CI.
- **Finding without CI:** **QID 999001** cites `SRV-AB-8888` / `GHOST-HOST01`,
  which resolve to no CI.
