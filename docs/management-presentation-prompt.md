# Prompt for Claude — Ghrab VOC Agentic System: Management Presentation

Copy everything below the line into Claude (artifact / design mode) as a single prompt.

---

You are designing a **single-file, self-contained HTML presentation document** for the **top management team** of my organization. They have **never seen this project before**. The document must explain — clearly, visually, and without assuming technical background — the platform I built (**Ghrab VOC**) and, above all, its **agentic AI system**: what agents are, why they beat plain scripts and one-shot AI calls, how autonomous they are, how the pipeline cycle works, where the data comes from, and how we keep the AI honest.

The document should feel like a premium product briefing: executive, confident, beautiful — not a technical README. Everything must be inline (CSS, SVG, fonts fallbacks); no external requests.

## 1. The product being presented

**Ghrab VOC** (Ghrab = غراب, "raven" in Arabic) is a **Vulnerability Operations Center**: a full web platform (FastAPI backend + React single-page app) that ingests raw vulnerability scan results and the company's infrastructure documentation, and **autonomously discovers multi-step attack paths** an adversary could take from the internet to our crown-jewel systems — then prioritizes, correlates, maps compliance impact, and writes the executive summary. It replaces a static dashboard mindset with an **autonomous analysis engine plus a team of specialized AI agents**.

Key views of the live platform (mention them so management knows what exists): Command Center (KPIs, charts, executive synthesis), Findings explorer, interactive Attack Paths graph, Teams, Correlation, Compliance, a streaming grounded AI Analyst chat, and a Verification page that scores the AI against held-out ground truth.

## 2. Core narrative arc (structure the document around this story)

1. **The problem.** Vulnerability scanners produce thousands of isolated findings. Humans triage by CVSS score. But **modern attackers don't exploit single findings — they chain several "medium" findings across machines** (internet foothold → credential theft → lateral movement → domain admin → crown jewel). A pile of individually-mediocre findings can hide a catastrophic path. Traditional tools and simple scripts cannot see chains; they see rows in a table.
2. **What an AI agent actually is.** Explain the ladder clearly, with a visual:
   - **Simple code / scripts**: fixed rules, brittle, only finds what it was told to look for.
   - **A single AI call**: a smart answer, but no memory, no tools, no verification, prone to making things up.
   - **An AI agent**: a model given a **role, tools, grounded context, and a goal**, which reasons in steps, uses real data, and whose output is **checked against reality before anyone sees it**.
   - **A multi-agent system (what Ghrab has)**: several specialized agents that hand results to each other in a pipeline, each building on verified work of the previous one — like a security team, not a chatbot.
3. **Degrees of autonomy.** Show a spectrum graphic (assisted → supervised → autonomous): Ghrab's deterministic engine runs **fully autonomously**; the AI agents run **autonomously with guardrails** (every claim verified against ground truth); the human analyst stays in command of decisions and remediation. Frame it as "autonomy where it's safe, human judgment where it matters."
4. **The agent team.** Present the agents as a roster of named specialists (cards or an org-chart-style graphic):
   - **Analyst Detection Agent** — the flagship. Given ONLY the infrastructure grounding and per-finding capability classifications (no hints, no pre-solved answers), it independently reasons out attack paths, hop by hop; every hop is verified against real hosts and real finding IDs.
   - **Discovery Agent** — validates, ranks, and narrates the candidate attack chains found by the deterministic graph engine; hunts "toxic combinations" of findings.
   - **Correlation Agent** — cross-references the full asset inventory and findings to surface non-obvious risk and re-prioritize beyond raw CVSS.
   - **Compliance Agent** — maps findings and paths onto compliance/regulatory impact.
   - **Triage Agent** — reads the conclusions of all previous agents and writes a consistent executive synthesis for the Command Center.
   - **Remediation Agent** — turns paths into concrete, ordered fix plans (which single fix severs the most attack paths).
   - **Grounded AI Analyst (chat)** — a streaming conversational analyst that answers questions citing real discovered paths and real finding IDs, never generic advice.
5. **The pipeline cycle** (the centerpiece diagram — a circular or left-to-right flow):
   1. **Ingest** — raw vulnerability scan export (CSV of findings with QIDs, CVSS, hosts) + the company's architecture/CMDB document (asset inventory, network zones, VLANs, trust relationships, dependencies, credential-reuse relationships) + threat intelligence signals (EPSS exploit-probability, CISA KEV known-exploited catalog).
   2. **Ground** — a CMDB engine parses the architecture doc into structured knowledge: zones, assets, owners, criticality, reachability rules.
   3. **Deterministic analysis (no AI, always runs)** — a capability classifier maps every finding to attacker capabilities (initial access, code execution, credential theft, privilege escalation, segmentation break, impact) using MITRE ATT&CK-style effects; a **reachability graph engine** then builds a map of the network and enumerates every internet → crown-jewel chain, ranked by blast radius. This layer is pure math/graph theory — reproducible, explainable, zero hallucination.
   4. **AI agent layer** — the agent team above runs in sequence, each grounded in the deterministic results and the CMDB context.
   5. **Verify** — every AI-cited path ID, finding ID, and host is checked against the deterministic ground truth; anything unverifiable is filtered or flagged before reaching the UI. A **held-out oracle** (documented attack paths kept completely outside the pipeline, like an exam answer key locked in a drawer) scores both the engine and the agents: the engine currently rediscovers **6 out of 6** documented attack paths on both test environments, and the Analyst Agent independently found **6 grounded paths** hitting the real crown-jewel systems.
   6. **Present & converse** — dashboard, interactive attack graph, and the grounded chat.
6. **Why this design is trustworthy (anti-hallucination story — management cares about this).**
   - Deterministic engine first: the AI never invents the map, it reasons over a verified one.
   - The "answer key" is **severed** from everything the AI sees — agents cannot cheat; their results are scored against it afterward.
   - Post-generation verification: hallucinated references never reach the screen.
   - A public **Verification page** in the product shows the score honestly.
7. **Engineering resilience** (one compact section): multi-provider LLM strategy (Mistral, Groq, Gemini) with automatic failover, per-provider rate-limit pacing and retry with backoff — no single AI vendor outage stops the platform.
8. **Why agents beat modern attackers** — attackers already automate chaining; defense that reviews findings one-by-one is structurally outmatched. Ghrab thinks in chains, at machine speed, continuously, and explains itself in plain language.
9. **Business value & what's next.** Value: from thousands of findings to a ranked list of real attack paths; the one fix that severs the most paths; audit-ready compliance mapping; an analyst that answers questions instantly. Roadmap: production hardening (Postgres, Redis, background job workers, single-sign-on/OIDC, centralized LLM gateway), scheduled continuous re-scans, more data connectors.

## 3. Brand & visual identity (must match the platform exactly)

Use the **dark command-center theme** as the primary look (it is the platform's signature), with these exact values.

**Fonts:** headings/display = `"Libre Baskerville", Georgia, serif`; body = `"Lato", system-ui, sans-serif`; code/IDs/labels = `"JetBrains Mono", ui-monospace, monospace`. Use system fallbacks only — do not load external fonts.

**Dark theme palette (primary):**
- Background base `rgb(8 12 11)`; card surface `rgb(14 22 20)`; raised surfaces `rgb(19 30 26)` and `rgb(26 40 34)`; borders `rgb(29 40 37)` / strong `rgb(42 56 51)`.
- Text ink `rgb(233 239 236)`; muted `rgb(159 176 169)`; faint `rgb(108 125 118)`.
- **Brand greens:** forest `rgb(0 60 48)`, forest-lit `rgb(11 90 72)`, sage `rgb(85 161 133)` (the hero accent), sage-bright `rgb(127 208 173)`.
- **Status ramp** (severity colors, most→least urgent): immediate `rgb(240 85 63)`, act `rgb(247 133 58)`, attend `rgb(232 189 74)`, track-blue `rgb(111 151 184)`, track-green `rgb(79 174 139)`, purple accent `rgb(201 123 216)`.
- Signature effects: subtle sage glow `0 0 0 1px rgba(85,161,133,0.35), 0 0 32px rgba(85,161,133,0.18)` on key cards; gradient headline text from ink into sage-bright.

**Logo — include this exact inline SVG** (the origami raven mark; "Ghrab" means raven). Place it in the header/hero next to the wordmark "Ghrab" set in Libre Baskerville bold, with a small "VOC — Vulnerability Operations Center" subtitle in Lato:

```html
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="56" height="56">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0B5A48"/>
      <stop offset="1" stop-color="#003C30"/>
    </linearGradient>
  </defs>
  <rect width="64" height="64" rx="14" fill="url(#bg)"/>
  <polygon points="18,54 22,30 40,36 36,54" fill="#55A185"/>
  <polygon points="22,30 30,14 46,22 38,32" fill="#88A682"/>
  <polygon points="46,22 60,30 40,36" fill="#F7F2EE"/>
  <circle cx="41" cy="24" r="2.4" fill="#003C30"/>
</svg>
```

## 4. Layout & design instructions

- **Format:** one long scrollable page composed of full-width "slide" sections, each self-contained enough to present on a projector. Sticky slim top bar with the raven mark + section quick-nav.
- **Hero:** raven logo, "Ghrab VOC" wordmark, one-line thesis ("An autonomous, agent-driven Vulnerability Operations Center that thinks in attack paths, not findings"), and 3–4 headline stat tiles (e.g., "6/6 documented attack paths rediscovered autonomously", "7 specialized AI agents", "every AI claim verified against ground truth", "multi-provider AI failover").
- **Diagrams:** build them as inline SVG in the brand palette — (a) the ladder "script → AI call → agent → multi-agent system", (b) the autonomy spectrum, (c) the pipeline cycle (the hero diagram — make it gorgeous, with the deterministic layer visually distinct from the AI layer and the verification gate drawn as a literal gate/checkpoint), (d) a small example attack-chain graphic: INTERNET → web server → credential theft → internal pivot → crown jewel, with hops colored by the status ramp.
- **Agent roster:** cards with a monospace agent name, a one-line mission, "grounded in" and "verified by" micro-labels.
- **Tone:** executive and plain-spoken. Every technical term gets a one-clause explanation at first use (QID = scanner finding ID, CMDB = the inventory of our systems, crown jewel = most business-critical system). No hype words like "revolutionary"; let the verification numbers carry the credibility.
- **Accessibility & polish:** strong contrast, generous whitespace, `max-width` content column ~1100px, smooth-scroll nav, subtle fade-up animations on section entry, print-friendly (sections avoid page-break through cards). Fully responsive; wide diagrams scroll horizontally inside their container, never the page.
- **End slide:** "What I'm asking from you" — a short closing section for management (support for the production rollout roadmap), plus footer with the raven mark.

Deliver the complete HTML document in one file.
