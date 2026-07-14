from vmc.agents.attack_paths import compute_choke_points, discover_attack_paths, run_agent4
from vmc.agents.attack_paths import AttackPathDiscovery, DiscoveredPath, DiscoveredStep
from vmc.models import Asset, Finding, NetworkGraph
from vmc.providers.fake_provider import FakeProvider
from vmc.providers.router import ModelRouter

POLICY = {
    "agents": {"attack_path_discovery": {"provider": "fake", "model": "fake-model", "temperature": 0.4}},
    "fallback_chain": [],
}


def _router(responses) -> ModelRouter:
    registry = {"fake": lambda model, temp: FakeProvider("fake", responses)}
    return ModelRouter(POLICY, registry)


def _finding(finding_id: str, hostname: str, zone: str = "Corporate LAN") -> Finding:
    return Finding(
        finding_id=finding_id,
        category="Missing Patch",
        title=f"finding {finding_id}",
        severity_raw="High",
        cvss_score=8.0,
        asset_ip="10.0.0.1",
        asset_hostname=hostname,
        zone=zone,
        responsible_team="IT Infrastructure Team",
    )


def _asset(hostname: str, acw: float, zone: str = "Corporate LAN") -> Asset:
    return Asset(hostname=hostname, ip="10.0.0.1", zone=zone, owning_team="IT Infrastructure Team", criticality_tier=1, acw=acw)


async def test_discovers_multistep_chain_and_computes_crown_jewel_tcm():
    findings = [_finding("F1", "GUEST-SW01"), _finding("F2", "DC01")]
    assets = {"GUEST-SW01": _asset("GUEST-SW01", 0.35), "DC01": _asset("DC01", 1.0)}
    topology = NetworkGraph()

    discovery = AttackPathDiscovery(
        paths=[
            DiscoveredPath(
                target_asset="DC01",
                summary="Guest network pivot to domain controller",
                steps=[
                    DiscoveredStep(finding_id="F1", rationale="VLAN hop into corporate network"),
                    DiscoveredStep(finding_id="F2", rationale="Unpatched DC compromised for domain admin"),
                ],
            )
        ]
    )
    router = _router([discovery])

    attack_paths, choke_points, tcm_by_finding, degraded = await run_agent4(findings, assets, topology, [], router)

    assert degraded is False
    assert len(attack_paths) == 1
    path = next(iter(attack_paths.values()))
    assert path.target_asset == "DC01"
    assert [s.finding_id for s in path.steps] == ["F1", "F2"]
    assert tcm_by_finding["F2"] >= 9.0  # chains to a crown-jewel asset (ACW 1.0)
    assert tcm_by_finding["F1"] >= 9.0  # every step in the chain shares the chain's TCM
    assert len(choke_points) == 1
    assert choke_points[0].finding_id == "F1"  # entry step


async def test_hallucinated_finding_id_is_dropped_not_trusted():
    findings = [_finding("F1", "HOST1")]
    assets = {"HOST1": _asset("HOST1", 0.5)}
    topology = NetworkGraph()

    discovery = AttackPathDiscovery(
        paths=[
            DiscoveredPath(
                target_asset="HOST1",
                summary="fabricated chain",
                steps=[
                    DiscoveredStep(finding_id="F1", rationale="real step"),
                    DiscoveredStep(finding_id="F999-DOES-NOT-EXIST", rationale="hallucinated step"),
                ],
            )
        ]
    )
    router = _router([discovery])

    attack_paths, degraded = await discover_attack_paths(findings, assets, topology, [], router)

    # the hallucinated step is dropped, leaving only 1 real step -> below the
    # 2-step minimum, so the whole path is discarded rather than kept half-fabricated
    assert attack_paths == {}
    assert degraded is False  # the model responded fine; validation just rejected the bad step


async def test_hallucinated_target_asset_is_nulled_not_trusted():
    findings = [_finding("F1", "HOST1"), _finding("F2", "HOST1")]
    assets = {"HOST1": _asset("HOST1", 0.5)}
    topology = NetworkGraph()

    discovery = AttackPathDiscovery(
        paths=[
            DiscoveredPath(
                target_asset="CROWN-JEWEL-THAT-DOES-NOT-EXIST",
                summary="chain with fabricated target",
                steps=[
                    DiscoveredStep(finding_id="F1", rationale="step one"),
                    DiscoveredStep(finding_id="F2", rationale="step two"),
                ],
            )
        ]
    )
    router = _router([discovery])

    attack_paths, degraded = await discover_attack_paths(findings, assets, topology, [], router)

    assert degraded is False
    assert len(attack_paths) == 1
    path = next(iter(attack_paths.values()))
    assert path.target_asset is None  # fabricated hostname never propagated
    assert len(path.steps) == 2  # the steps themselves were still valid


async def test_single_step_is_not_a_chain():
    findings = [_finding("F1", "HOST1")]
    assets = {"HOST1": _asset("HOST1", 0.5)}
    topology = NetworkGraph()

    discovery = AttackPathDiscovery(
        paths=[DiscoveredPath(target_asset="HOST1", summary="not a chain", steps=[DiscoveredStep(finding_id="F1", rationale="alone")])]
    )
    router = _router([discovery])

    attack_paths, degraded = await discover_attack_paths(findings, assets, topology, [], router)
    assert attack_paths == {}
    assert degraded is False


async def test_no_router_is_a_known_state_not_degraded():
    findings = [_finding("F1", "HOST1")]
    assets = {"HOST1": _asset("HOST1", 0.5)}
    topology = NetworkGraph()

    attack_paths, choke_points, tcm_by_finding, degraded = await run_agent4(findings, assets, topology, [], None)

    assert attack_paths == {}
    assert choke_points == []
    assert tcm_by_finding["F1"] == 1.0  # "no chain" default
    assert degraded is False  # no AI configured at all is expected, not a run-time failure


async def test_all_providers_exhausted_is_reported_as_degraded():
    from vmc.providers.errors import ProviderError, ProviderErrorType

    findings = [_finding("F1", "HOST1"), _finding("F2", "HOST1")]
    assets = {"HOST1": _asset("HOST1", 0.5)}
    topology = NetworkGraph()

    exhausted = ProviderError(ProviderErrorType.AUTH, "no valid key", provider="fake")
    router = _router([exhausted])

    attack_paths, choke_points, tcm_by_finding, degraded = await run_agent4(findings, assets, topology, [], router)

    assert attack_paths == {}
    assert degraded is True  # must be distinguishable from "the model found nothing"


def test_choke_points_require_at_least_two_steps():
    from vmc.models import AttackPath, AttackPathStep

    single_step_path = AttackPath(
        path_ref="PATH-01", steps=[AttackPathStep(step_ref="PATH-01-Step1", finding_id="F1", description="d")]
    )
    assert compute_choke_points({"PATH-01": single_step_path}) == []
