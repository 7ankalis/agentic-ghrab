from pathlib import Path

from vmc.agents.ingest import run_agent1
from vmc.agents.topology import run_agent2
from vmc.agents.attack_paths import run_agent4

SAMPLE_DATA = Path(__file__).parent.parent / "docs" / "sample_data"
FINDINGS_CSV = SAMPLE_DATA / "ghrab_vulnerabilities.csv"
ARCHITECTURE_MD = SAMPLE_DATA / "ghrab_architecture.md"


def _load():
    findings, assets, teams, topology, _ = run_agent1(FINDINGS_CSV, ARCHITECTURE_MD)
    topology, assets, _ = run_agent2(findings, assets, topology)
    attack_paths, choke_points, tcm_by_finding = run_agent4(findings, ARCHITECTURE_MD, assets)
    return findings, assets, attack_paths, choke_points, tcm_by_finding


def test_all_six_paths_parsed_with_correct_targets():
    _, _, attack_paths, _, _ = _load()
    assert set(attack_paths) == {"PATH-A", "PATH-B", "PATH-C", "PATH-D", "PATH-E", "PATH-F"}
    assert attack_paths["PATH-E"].target_asset == "SWIFT-GATEWAY01"  # the crown-jewel scenario
    assert len(attack_paths["PATH-E"].steps) == 5


def test_crown_jewel_path_gets_highest_tcm_band():
    findings, _, _, _, tcm_by_finding = _load()
    # PATH-E-Step2 = Zerologon on DC01, which cascades to SWIFT-GATEWAY01 (crown jewel)
    zerologon = next(f for f in findings if f.cve_id == "CVE-2020-1472")
    assert tcm_by_finding[zerologon.finding_id] >= 9.0


def test_standalone_finding_gets_low_tcm():
    findings, _, _, _, tcm_by_finding = _load()
    # NAS01 anonymous SMB is explicitly documented as standalone (architecture.md §5);
    # its CSV Attack_Path_Ref is the literal string "Standalone", not a PATH-X-StepN ref.
    nas_finding = next(f for f in findings if f.asset_hostname == "NAS01")
    assert tcm_by_finding[nas_finding.finding_id] <= 2.0


def test_each_paths_entry_step_is_a_choke_point():
    _, _, attack_paths, choke_points, _ = _load()
    choke_finding_ids = {cp.finding_id for cp in choke_points}
    assert len(choke_finding_ids) == len(attack_paths)  # one choke point (Step1) per path
    for cp in choke_points:
        assert cp.paths_collapsed
