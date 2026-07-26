"""
Detection-quality evaluation harness.

Phase 0 of docs/attack-path-intelligence-brief.md: turn "more intelligent" into a
number. This package scores the attack-path detection pipeline (the deterministic
engine plus, when a provider is configured, the AI detection layer) against the
held-out oracle and emits precision / recall / F1 / soundness / hallucination
metrics per shipped dataset, with a committed baseline the regression test guards.

The oracle (core/oracle.py, core/graph.build_chains) is loaded ONLY here and in
the verification overlay — never by a classifier, graph builder, or agent. See
test_no_oracle_leakage.py for the assertion that keeps it that way.
"""
