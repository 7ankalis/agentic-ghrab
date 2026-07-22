# Prompt — Agentic AI System for a VOC (general, no enterprise specifics)

Copy everything below the line into Claude (artifact / design mode) as a single prompt.
Use it to regenerate or restyle the presentation without leaking any enterprise data or
path-detection statistics.

---

You are designing a **single-file, self-contained HTML presentation** that explains — clearly,
visually, and to a general/management audience — the **agentic AI system** behind a
**Vulnerability Operations Center (VOC)**. The whole point of the document is to make the reader
feel that **agentic AI systems are powerful, dependable, and genuinely helpful** in security
operations.

**Hard constraints — keep it general:**
- Do **not** name any specific company, environment, or lab, and do **not** use any real
  organization as an example.
- Do **not** cite path-detection statistics or any numbers tied to a specific data set
  (no "X out of Y paths found", no per-environment counts). Where you need a chart, make it
  **conceptual/illustrative** and label it as such.
- Achievements should be **architectural and qualitative** (what was built, how it's designed),
  never enterprise-specific results.

## What to convey (narrative arc)
1. **The problem.** Scanners emit thousands of isolated findings sorted by score; real breaches
   are several ordinary weaknesses chained across machines. Row-by-row tools can't see chains.
2. **What an "agent" is.** A capability ladder: script → single AI call → AI agent (role + tools +
   grounded context + goal, output verified) → multi-agent system (specialists handing verified
   work to each other). Show it as a diagram **and** a capability matrix.
3. **Degrees of autonomy.** A spectrum (assisted → supervised → autonomous): deterministic engine
   fully autonomous; AI agents autonomous **with guardrails**; the human analyst owns decisions.
   Frame: "autonomy where it's safe, human judgment where it matters."
4. **The pipeline (centerpiece diagram).** Ingest (scan findings + infrastructure doc + threat-intel
   signals) → Ground (a CMDB engine parses the doc into zones/assets/owners/trust) → Deterministic
   layer, no AI, always runs (a capability classifier maps findings to ATT&CK-style attacker effects;
   a reachability graph engine enumerates internet→crown-jewel chains ranked by blast radius) →
   AI agent layer (grounded in the verified results) → Verify (a gate checks every cited path/finding/
   host; a **held-out answer key**, kept entirely outside the pipeline, scores engine and agents) →
   Present (dashboard, interactive attack graph, grounded chat). Draw the deterministic layer visually
   distinct from the AI layer, and the verification step as a literal gate.
5. **The agent team (roster).** Seven specialists: an **Analyst** detection agent (flagship — reasons
   paths from grounding alone), **Discovery** (validates/ranks/narrates chains, finds toxic combos),
   **Correlation** (non-obvious risk, re-prioritize beyond score), **Compliance** (regulatory/control
   impact), **Remediation** (which single fix severs the most paths), **Triage** (consistent executive
   synthesis, runs last), and a **grounded conversational Analyst** chat. Show the hand-off order.
6. **Why it's trustworthy (anti-hallucination).** Map first (AI never invents topology); answer key
   severed (agents can't cheat); verify every claim post-generation; score honestly in the open.
7. **Engineering resilience.** Multi-provider LLM routing with automatic failover, per-provider pacing,
   retry-with-backoff — no single vendor outage stops the platform.
8. **Agentic vs. traditional.** A conceptual capability-profile chart (cross-machine reasoning,
   context, prioritization, explainability, adaptability, verifiability) — agentic wins each.
9. **What's built + value + roadmap.** Delivered: hybrid engine, seven-agent pipeline, full web
   platform, verification harness, resilient AI plumbing, containerized deploy. Value: from thousands
   of findings to a ranked list of real routes and the one fix that severs the most. Roadmap:
   production hardening (durable storage, job workers, SSO), centralized AI gateway, continuous
   re-scans, more connectors.

## Design
- One long scrollable page of full-width "slide" sections; sticky slim top nav; light+dark themes
  (token-based, honor the OS preference and a manual toggle).
- **Dark command-center aesthetic** as the signature: near-black cool ground, a single teal/mint
  accent used with restraint, an indigo secondary, and a reserved status ramp
  (critical/high/medium/low/ok) used **only** for severity, always with labels.
- Type: a serif display face (Georgia stack) for executive gravitas, a clean sans for body, a mono
  face for labels/IDs. Inline everything — no external fonts, scripts, or requests (strict CSP).
- Build every diagram as **inline SVG** in the palette. Wide diagrams scroll inside their own
  container; the page body never scrolls sideways. Subtle fade-up on scroll; respect
  `prefers-reduced-motion`. Explain each technical term in one clause at first use.

Deliver the complete HTML in one file.
