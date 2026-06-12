# AGENTS.md

This file defines how agents should work in this repository.

## Product Focus

VibeShield is a security-audit pipeline, not a general AppSec platform.

The MVP must prove the detection core:

- accept a repo/archive;
- classify the project;
- run staged analysis;
- verify findings with code evidence;
- report only useful, actionable findings;
- preserve internal debug artifacts for calibration.

Do not spend MVP effort on dashboards, GitHub App flows, PR generation, auto-fixes, accounts, or continuous monitoring unless the project plan explicitly changes.

## Engineering Principles

Follow these principles aggressively:

- **KISS**: choose the simplest design that proves the current detection hypothesis.
- **DRY**: share contracts, schemas, and analyzer plumbing instead of duplicating finding formats.
- **YAGNI**: do not build SaaS infrastructure, plugin marketplaces, complex queues, or broad abstractions before they are needed.

Prefer boring, inspectable code over clever orchestration.

## Architecture Rules

Keep architecture choices grounded in the current plan, but avoid hard-coding detailed technical decisions in this file.

High-level expectations:

- keep the system modular and easy to change;
- keep data contracts explicit;
- keep generated outputs inspectable;
- keep security-sensitive behavior conservative;
- avoid premature infrastructure;
- update the relevant docs when a material decision changes.

## Output Rules

External reports should be short and actionable:

- `Fix now`: maximum 3 findings.
- `Fix next`: maximum 5 findings.
- `Hygiene`: maximum 5 findings.
- Include code evidence and confidence.
- Include coverage boundaries.

Internal artifacts may be verbose:

- raw scanner outputs;
- suppressed findings;
- hypotheses;
- verifier traces;
- metrics.

## Documentation Rules

- Keep current plans in `docs/`.
- Preserve brainstorm/history files unless the user asks to rewrite them.
- When a plan changes materially, update the relevant doc in the same change.
- Prefer clear product language over enterprise security jargon.

## Git Rules

- Do not rewrite history unless the user explicitly asks.
- Do not revert user changes without explicit permission.
- Keep commits focused and readable when commits are requested.
