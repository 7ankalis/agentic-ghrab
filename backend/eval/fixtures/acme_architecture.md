# Acme Robotics — Enterprise Architecture (SYNTHETIC TEST FIXTURE)

> Tiny hand-built environment used ONLY by the Phase 2 graph-generality test. Its
> VLAN numbering is deliberately unlike the shipped datasets (100/200/400, not
> 10/20/40) to prove the graph derives its tiers from trust/criticality/platform
> and the §4 relations, never from literal VLAN numbers.

## 1. CI Inventory

### 1.1 Network Segments

| CI ID | Name | CIDR | Trust Level | Owning Support Group |
|---|---|---|---|---|
| SEG-INET | Internet (untrusted) | 0.0.0.0/0 | None | — |
| SEG-EDGE | VLAN 200 — Edge DMZ | 10.9.200.0/24 | Low (internet-facing) | NetOps |
| SEG-CORP | VLAN 100 — Corporate | 10.9.100.0/24 | Medium | AppOps |
| SEG-VAULT | VLAN 400 — Vault Zone | 10.9.400.0/24 | Critical | SecOps |

### 1.2 Servers

| Name | IP | Platform | Zone | Criticality | Support Group |
|---|---|---|---|---|---|
| `WEBEDGE01` | 10.9.200.10 | Linux (nginx) | SEG-EDGE | Business-Important | NetOps |
| `APPX01` | 10.9.100.10 | Linux (Java) | SEG-CORP | Standard | AppOps |
| `VAULT01` | 10.9.400.10 | Linux (Secrets Vault) | SEG-VAULT | Crown Jewel | SecOps |

### 1.7 Support Groups

| Name | Group ID | Responsible For |
|---|---|---|
| NetOps | GRP-NET | Perimeter and DMZ |
| AppOps | GRP-APP | Application tier |
| SecOps | GRP-SEC | Crown-jewel systems |

## 4. Host, Application & Database Dependencies

| Relationship ID | Source CI | Relationship Type | Target CI | Flag | Justification |
|---|---|---|---|---|---|
| REL-AC-101 | SRV-AC-1 (APPX01) | Depends On | SRV-AC-2 (VAULT01) | Excessive (QID 500004) | App service account holds standing read access to the vault |
