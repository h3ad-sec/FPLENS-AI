# FPLENS-AI

**False Positive Analyzer — Part of [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/)**

FPLENS-AI analyzes detection rule alerts and raw alert context to distinguish true positives from false positives. Paste the detection rule and alert data and get a structured verdict — TP probability, FP scenarios, tuning recommendations, and suppression logic — backed by specific behavioral reasoning.

## Features

- Supports four AI providers: Anthropic (Claude), OpenAI (GPT), Google Gemini, Groq
- Verdict: Escalate / Tune / Close with probability and reasoning
- TP trigger scenarios: specific behaviors that make this alert a true positive
- FP trigger scenarios: specific benign conditions that explain the alert
- Benign baseline: expected noise in typical environments
- Detection tuning recommendations with concrete filter logic
- Suppression or exception guidance
- Analyst playbook: tiered investigation steps (L1 / L2 / L3 / IR)
- Fully responsive — works on mobile, tablet, and desktop

## Output Sections

| Section | Content |
|---------|---------|
| Verdict | Escalate / Tune / Close + TP probability |
| TP Scenarios | Specific behaviors confirming malicious activity |
| FP Scenarios | Specific benign conditions explaining the alert |
| Benign Baseline | What normal looks like for this detection |
| Tuning | Concrete filter/exception recommendations |
| Analyst Playbook | Step-by-step investigation guide by tier |

## How to Use

1. Add your API key via the settings icon
2. Paste the detection rule (Sigma, KQL, SPL, or description) and alert context
3. Click ANALYZE
4. Review the verdict, scenarios, and tuning guidance

## Live Tool

[h3ad-sec.github.io/FPLENS-AI](https://h3ad-sec.github.io/FPLENS-AI/)

## Part of H3AD-SEC

FPLENS-AI is a sub-tool under [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/), the AI-assisted analysis hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.

## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, MALBRIEF-AI |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG, PHISHOPS |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | — |
