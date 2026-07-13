# Sample Architecture (test fixture)

This is a synthetic fixture used only to exercise Agent 1's markdown parser
in unit tests — it is not the real `ghrab_architecture.md`.

## Zones

| VLAN | Zone | Team | Compliance |
|------|------|------|------------|
| 10 | Corporate LAN | IT Infrastructure | |
| 40 | Finance/Trading | Finance IT | PCI DSS; SWIFT CSP |
| 70 | Guest WiFi | Network | |

## Trust Edges

- Guest WiFi -> Corporate LAN: Trunk port misconfiguration allows VLAN hopping
- Corporate LAN -> Finance/Trading: Flat firewall rule permits any-any traffic
