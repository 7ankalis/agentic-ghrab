from vmc.agents.ingest import (
    build_assets_and_teams,
    parse_architecture_markdown,
    parse_findings_csv,
    run_agent1,
)


def test_parse_findings_csv_normalizes_generic_columns(sample_findings_csv):
    findings, issues, scanner = parse_findings_csv(sample_findings_csv)

    assert scanner == "generic"
    # 7 data rows, 1 unparseable (F-007 has no title) -> 6 valid findings
    assert len(findings) == 6
    zerologon = next(f for f in findings if f.finding_id == "F-001")
    assert zerologon.cve_id == "CVE-2020-1472"
    assert zerologon.cvss_score == 10.0
    assert zerologon.patch_available is True
    assert zerologon.attack_path_refs == ["PATH-E-Step1"]
    assert zerologon.compliance_refs == ["PCI DSS 6.2"]


def test_parse_findings_csv_flags_unparseable_row(sample_findings_csv):
    findings, issues, _ = parse_findings_csv(sample_findings_csv)
    unparseable = [i for i in issues if i.issue_type == "unparseable_row"]
    assert len(unparseable) == 1
    assert "F-007" not in [f.finding_id for f in findings]


def test_parse_architecture_markdown_extracts_zones_and_trust_edges(sample_architecture_md):
    graph = parse_architecture_markdown(sample_architecture_md)

    assert "corporate_lan" in graph.zones
    finance = graph.zones["finance_trading"]
    assert finance.vlan_ids == ["40"]
    assert finance.owning_team == "Finance IT"
    assert "PCI DSS" in finance.compliance_scope

    assert len(graph.trust_edges) == 2
    edge = next(e for e in graph.trust_edges if e.source_zone == "Guest WiFi")
    assert edge.target_zone == "Corporate LAN"
    assert "VLAN hopping" in edge.description


def test_build_assets_and_teams_flags_ambiguous_ownership(sample_findings_csv, sample_architecture_md):
    findings, _, _ = parse_findings_csv(sample_findings_csv)
    topology = parse_architecture_markdown(sample_architecture_md)
    assets, teams, issues = build_assets_and_teams(findings, topology)

    # DC01 appears with two different responsible teams (F-001, F-006)
    ambiguous = [i for i in issues if i.issue_type == "ambiguous_ownership"]
    assert any("DC01" in i.detail for i in ambiguous)

    # F-004's zone "Unknown" never triggers orphaned_ip (it's the explicit no-zone marker)
    orphaned = [i for i in issues if i.issue_type == "orphaned_ip"]
    assert all("Unknown" not in i.detail for i in orphaned)

    assert "IT Infrastructure" in [t.name for t in teams.values()]
    assert assets["DC01"].zone == "Corporate LAN"


def test_run_agent1_end_to_end(sample_findings_csv, sample_architecture_md):
    findings, assets, teams, topology, issues = run_agent1(sample_findings_csv, sample_architecture_md)

    assert len(findings) == 6
    assert len(assets) > 0
    assert len(teams) > 0
    assert len(topology.zones) == 3
    assert any(i.issue_type == "unparseable_row" for i in issues)
    assert any(i.issue_type == "ambiguous_ownership" for i in issues)
