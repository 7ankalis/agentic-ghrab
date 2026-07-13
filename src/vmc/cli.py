"""Phase 1 deliverable: a CLI that ingests findings.csv + architecture.md and
prints a normalized findings table with asset/team context attached.

    python -m vmc.cli ingest <findings.csv> <architecture.md>
"""

from __future__ import annotations

import argparse
import sys

from vmc.agents import run_agent1


def _ingest_command(args: argparse.Namespace) -> int:
    findings, assets, teams, topology, issues = run_agent1(args.findings_csv, args.architecture_md)

    print(f"Ingested {len(findings)} findings, {len(assets)} assets, {len(teams)} teams, "
          f"{len(topology.zones)} zones from architecture.md\n")

    col_widths = (12, 22, 22, 18, 8, 22)
    header = ("finding_id", "title", "asset_hostname", "team", "cvss", "zone")
    print(" | ".join(h.ljust(w) for h, w in zip(header, col_widths)))
    print("-+-".join("-" * w for w in col_widths))
    for finding in findings:
        row = (
            finding.finding_id,
            finding.title,
            finding.asset_hostname,
            finding.responsible_team,
            f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "-",
            finding.zone,
        )
        print(" | ".join(str(v)[: w].ljust(w) for v, w in zip(row, col_widths)))

    if issues:
        print(f"\n{len(issues)} data quality issue(s):")
        for issue in issues:
            print(f"  [{issue.issue_type}] {issue.detail}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vmc")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Run Agent 1 against a findings CSV + architecture.md")
    ingest_parser.add_argument("findings_csv")
    ingest_parser.add_argument("architecture_md")
    ingest_parser.set_defaults(func=_ingest_command)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
