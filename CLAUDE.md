## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
- Author a backlog-ready spec/issue → invoke /spec

## Gstack Integration

Gstack is a suite of premium skills for development, design, QA, and deployment workflows. 

**Browser & Web Automation:** Use the `/browse` skill from gstack for all web browsing tasks. Never use `mcp__claude-in-chrome__*` tools directly.

**Available Gstack Skills:**
- `/office-hours` — YC Office Hours mode for brainstorming
- `/plan-ceo-review` — CEO/founder-mode plan review
- `/plan-eng-review` — Engineering manager plan review
- `/plan-design-review` — Designer's eye plan review
- `/design-consultation` — Full design system research & proposals
- `/design-shotgun` — Multi-variant AI design generation
- `/design-html` — Production-quality HTML/CSS generation
- `/review` — Pre-landing PR code review
- `/ship` — Ship workflow (merge, test, bump, commit, push, PR)
- `/land-and-deploy` — Land and deploy workflow with canary
- `/canary` — Post-deploy canary monitoring
- `/benchmark` — Performance regression detection
- `/browse` — Drive a real browser through flows, read pages, take screenshots
- `/connect-chrome` — Launch GStack Browser with sidebar extension
- `/qa` — Systematically QA test and fix bugs
- `/qa-only` — QA testing (report-only)
- `/design-review` — Visual QA and design polish fixes
- `/scrape` — Pull data from web pages through the browser
- `/setup-browser-cookies` — Import cookies from real browser
- `/setup-deploy` — Configure deployment settings
- `/setup-gbrain` — Set up gbrain knowledge base
- `/retro` — Weekly engineering retrospective
- `/investigate` — Systematic debugging with root cause analysis
- `/document-release` — Post-ship documentation updates
- `/document-generate` — Generate missing documentation
- `/codex` — OpenAI Codex CLI wrapper
- `/cso` — Chief Security Officer mode
- `/autoplan` — Auto-review pipeline (CEO, design, eng, DX)
- `/plan-devex-review` — Developer experience plan review
- `/devex-review` — Live developer experience audit
- `/careful` — Safety guardrails for destructive commands
- `/freeze` — Restrict file edits to specific directory
- `/guard` — Full safety mode with warnings
- `/unfreeze` — Clear freeze boundary
- `/gstack-upgrade` — Upgrade gstack to latest version
- `/learn` — Manage project learnings
