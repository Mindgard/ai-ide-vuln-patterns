# AI IDE Security Checklist

A compact checklist for eliminating classes of vulnerabilities in AI coding assistants. Each item maps to a pattern in the [vulnerability catalog](README.md).

Use this to **test** existing tools and to **build** new ones securely. Every unchecked box is an open attack surface.

---

### Workspace Configuration Approval

*Blocks: [MCP Config Poisoning](README.md#11-mcp-configuration-poisoning), [LSP Config](README.md#12-lsp-configuration), [Tools/Skills Auto-Loading](README.md#13-toolsskills-definition-auto-loading), [Hooks Definition](README.md#15-hooks-definition), [App-Specific Config Auto-Execution](README.md#16-application-specific-configuration-auto-execution), [IDE Settings Abuse](README.md#112-ide-settings-abuse-idesaster), [Prompt Template Auto-Loading](README.md#22-prompt-template-auto-loading), [Rules Override](README.md#24-rules-override), [Model Provider Redirect](README.md#35-model-provider-redirect), [Pre-Configured URL Fetching](README.md#33-pre-configured-url-fetching) (direct variant)*

- [ ] Workspace-sourced MCP configs require explicit user approval before activation
- [ ] Hooks, tool definitions, and skill files from workspace require approval before execution
- [ ] App-specific config fields that accept commands or script references (`notify`, `load`, `discoveryCommand`) require approval
- [ ] LSP binary paths from workspace settings require approval before execution
- [ ] IDE settings that reference executable paths (e.g., `php.validate.executablePath`, `PATH_TO_GIT`) cannot be overridden from workspace without approval
- [ ] `.code-workspace` and `.idea/workspace.xml` settings that reference executable paths require approval
- [ ] Prompt template files from workspace cannot override system behavior or trigger tool execution without approval
- [ ] Rules/directives files from workspace cannot override safety mechanisms (e.g., `requires_approval=false`)
- [ ] Model provider endpoints cannot be overridden from workspace-level config
- [ ] Workspace config fields that store external URLs are validated against a domain allowlist

### Deny-By-Default Trust & Initialization Safety

*Blocks: [Initialization Race Condition](README.md#17-initialization-race-condition), all zero-click config-based attacks*

- [ ] Deny-by-default workspace trust: nothing from workspace executes until trust is explicitly granted
- [ ] No config surface auto-executes during IDE initialization before the trust dialog is displayed and answered
- [ ] Trust revocation undoes previously applied configuration — rejecting trust after load is not cosmetic

### Trust Integrity (TOCTOU)

*Blocks: [Trust Persistence / TOCTOU](README.md#4-trust-persistence--toctou), [MCP Config Poisoning](README.md#11-mcp-configuration-poisoning) (two-step variant)*

- [ ] Trust decisions are bound to content hash, not file path or config name
- [ ] Config modifications via `git pull` / `git switch` / `git rebase` trigger re-approval
- [ ] Re-approval is required for all config surfaces: MCP, hooks, rules, app-specific config, model provider, prompt templates

### File Write Restrictions

*Blocks: [File Write to Config Modification](README.md#23-prompt-injection-to-config-modification-via-file-write), [Rules Override](README.md#24-rules-override) (PI variant), [Pre-Configured URL Fetching](README.md#33-pre-configured-url-fetching) (PI variant)*

- [ ] Agent cannot modify its own configuration files (MCP config, rules, IDE settings, allowlists)
- [ ] File writes to security-sensitive paths (`.vscode/`, `.cursor/`, `.claude/`, `.windsurf/`, `.idea/`, config dirs) require elevated approval
- [ ] Agent cannot modify workspace trust configuration or approval records
- [ ] Agent cannot modify prompt template files, hook definitions, or tool definition files

### Command Execution & Filtering

*Blocks: [Terminal Command Filtering Bypasses](README.md#18-terminal-command-filtering-bypasses), [Argument Injection](README.md#14-argument-injection), [Environment Variable Prefixing](README.md#111-environment-variable-prefixing), [Safe Executables with In-Workspace Config](README.md#110-safe-executables-with-in-workspace-config), [DNS-Based Exfiltration](README.md#36-dns-based-exfiltration) (partially)*

- [ ] Command parser correctly handles: newline (`\n`), shell metacharacters, IFS manipulation, backticks, `$()` expansion
- [ ] Environment variable prefixes (`VAR=val cmd`, `LD_PRELOAD=x.so`, `DYLD_INSERT_LIBRARIES=x.dylib`) are stripped or rejected before allowlist validation
- [ ] Allowlisted commands are audited for dangerous flags (`find -exec`, `git` with external diff drivers, `--output`, `--post-file`)
- [ ] Shell expansion in arguments (`echo $(whoami)`, `` echo `whoami` ``) is detected and blocked
- [ ] All execution paths require user approval — no silent bypass via `background=true` or similar parameters
- [ ] Tool arguments are properly sanitized/escaped before being passed to shell execution
- [ ] Workspace `.gitattributes` / `.gitconfig` cannot redirect "safe" commands to arbitrary scripts via external diff/merge drivers
- [ ] DNS query commands (`ping`, `nslookup`, `dig`, `host`) are not auto-approved; hostnames are validated

### Binary & Path Resolution

*Blocks: [Binary Planting](README.md#19-binary-planting)*

- [ ] Tool binary search path does not include the workspace directory
- [ ] Workspace directory does not appear earlier in search order than system binary paths
- [ ] Binary integrity is verified (known path, signature) before execution
- [ ] Binary discovery and execution do not happen automatically before user approval

### Input Sanitization & Prompt Injection Resistance

*Blocks: [Adversarial Directory Names](README.md#21-adversarial-directory-names), [Hidden Instructions](README.md#25-hidden-instructions-invisible-unicode), and reduces effectiveness of all prompt-injection-dependent attack chains*

- [ ] Invisible Unicode characters (U+E0000–U+E007F, zero-width joiners/spaces, tag characters) are stripped from all input before LLM processing
- [ ] Directory and file names are sanitized before inclusion in agent context
- [ ] Tool call responses and external data sources (GitHub issues, Linear tickets, web content) are treated as untrusted input
- [ ] Agent system prompt includes explicit boundaries that resist instruction-following from workspace file content

### Outbound Channel Controls

*Blocks: [Markdown Image Rendering](README.md#31-markdown-image-rendering), [Mermaid Diagram Abuse](README.md#32-mermaid-diagram-abuse), [Pre-Configured URL Fetching](README.md#33-pre-configured-url-fetching), [Webview Rendering](README.md#34-webview-rendering), [Model Provider Redirect](README.md#35-model-provider-redirect), [DNS-Based Exfiltration](README.md#36-dns-based-exfiltration)*

- [ ] External URLs in rendered markdown images are blocked or require user approval
- [ ] Mermaid diagram external image references are subject to the same URL restrictions as markdown images
- [ ] Webview/browser-preview tool validates URLs — cannot encode arbitrary workspace data in request parameters
- [ ] Model provider endpoints are hardcoded or restricted to a known allowlist — not configurable from workspace
- [ ] DNS query commands are gated; hostnames in shell commands cannot encode arbitrary data
- [ ] Outbound HTTP requests from IDE rendering features are logged and filterable
- [ ] All exfiltration channels are tested independently — blocking one (e.g., markdown images) does not mean others (mermaid, DNS, webview) are blocked

### Network Service Security

*Blocks: [Unauthenticated Local Network Services](README.md#113-unauthenticated-local-network-services)*

- [ ] Local services exposed during operation require authentication (token, secret)
- [ ] CORS restricted to same-origin — no cross-origin access from arbitrary websites
- [ ] Exposed ports are documented, use randomized port selection, and bind to localhost only

---

## Critical Gates

Every attack chain flows through one or more chokepoints. The table below maps every vulnerability pattern to the gate(s) that block it.

### Gate Definitions

| Gate | Principle | What it blocks |
|------|-----------|---------------|
| **G1 — Config Approval** | Nothing from workspace auto-executes without explicit user approval | Zero-click config-based attacks: MCP poisoning, hooks, tools, LSP, IDE settings, app-specific config, prompt templates, rules, model provider redirect, pre-configured URL fetch |
| **G2 — Initialization Safety** | No execution before trust dialog is displayed and answered | Race condition attacks where payloads fire during IDE startup before user can reject |
| **G3 — Trust Integrity** | Trust bound to content hash; changes require re-approval | TOCTOU/trust persistence attacks where approved config is later modified via git |
| **G4 — File Write Restrictions** | Agent cannot modify its own config, rules, settings, or allowlists | PI → config modification → code execution (the "classic chain") |
| **G5 — Command Robustness** | Parsing handles all shell tricks; arguments are sanitized | Terminal filter bypasses, argument injection, env var prefixing, safe-command config abuse |
| **G6 — Binary Security** | Workspace not in binary search path; integrity verified | Binary planting (zero-click code exec via planted executables) |
| **G7 — Input Sanitization** | Strip invisible Unicode; sanitize file/dir names; treat external data as untrusted | Covert prompt injection delivery (invisible chars, adversarial dirs) |
| **G8 — Outbound Controls** | Block or gate all outbound requests from rendering and tool execution | All data exfiltration channels: markdown images, mermaid, DNS, webview, URL fetch, model provider redirect |
| **G9 — Network Security** | Local services require auth; CORS restricted | Unauthenticated local service exploitation |

### Pattern-to-Gate Mapping

| # | Pattern | G1 | G2 | G3 | G4 | G5 | G6 | G7 | G8 | G9 |
|---|---------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| 1.1 | [MCP Config Poisoning](README.md#11-mcp-configuration-poisoning) | **X** | | X | X | | | | | |
| 1.2 | [LSP Configuration](README.md#12-lsp-configuration) | **X** | | | | | | | | |
| 1.3 | [Tools/Skills Auto-Loading](README.md#13-toolsskills-definition-auto-loading) | **X** | | | | | | | | |
| 1.4 | [Argument Injection](README.md#14-argument-injection) | | | | | **X** | | | | |
| 1.5 | [Hooks Definition](README.md#15-hooks-definition) | **X** | | X | | | | | | |
| 1.6 | [App-Specific Config Auto-Execution](README.md#16-application-specific-configuration-auto-execution) | **X** | | | | | | | | |
| 1.7 | [Initialization Race Condition](README.md#17-initialization-race-condition) | | **X** | | | | | | | |
| 1.8 | [Terminal Filter Bypasses](README.md#18-terminal-command-filtering-bypasses) | | | | | **X** | | | | |
| 1.9 | [Binary Planting](README.md#19-binary-planting) | | | | | | **X** | | | |
| 1.10 | [Safe Exec + Workspace Config](README.md#110-safe-executables-with-in-workspace-config) | | | | | **X** | | | | |
| 1.11 | [Env Var Prefixing](README.md#111-environment-variable-prefixing) | | | | | **X** | | | | |
| 1.12 | [IDE Settings Abuse](README.md#112-ide-settings-abuse-idesaster) | **X** | | | | | | | | |
| 1.13 | [Local Network Services](README.md#113-unauthenticated-local-network-services) | | | | | | | | | **X** |
| 2.1 | [Adversarial Directories](README.md#21-adversarial-directory-names) | | | | | | | **X** | | |
| 2.2 | [Prompt Templates](README.md#22-prompt-template-auto-loading) | **X** | | | | | | | | |
| 2.3 | [File Write → Config Mod](README.md#23-prompt-injection-to-config-modification-via-file-write) | | | | **X** | | | | | |
| 2.4 | [Rules Override](README.md#24-rules-override) | **X** | | | X | | | | | |
| 2.5 | [Hidden Instructions](README.md#25-hidden-instructions-invisible-unicode) | | | | | | | **X** | | |
| 3.1 | [Markdown Image](README.md#31-markdown-image-rendering) | | | | | | | | **X** | |
| 3.2 | [Mermaid Abuse](README.md#32-mermaid-diagram-abuse) | | | | | | | | **X** | |
| 3.3 | [Pre-Configured URL Fetch](README.md#33-pre-configured-url-fetching) | X | | | X | | | | **X** | |
| 3.4 | [Webview Rendering](README.md#34-webview-rendering) | | | | | | | | **X** | |
| 3.5 | [Model Provider Redirect](README.md#35-model-provider-redirect) | **X** | | | | | | | **X** | |
| 3.6 | [DNS-Based Exfiltration](README.md#36-dns-based-exfiltration) | | | | | X | | | **X** | |
| 4 | [Trust Persistence / TOCTOU](README.md#4-trust-persistence--toctou) | | | **X** | | | | | | |

**X** = primary gate that blocks this pattern. X = secondary/supporting gate.

### Coverage Summary

| Gate | Patterns blocked (primary) | Priority |
|------|---------------------------|----------|
| G1 — Config Approval | 1.1, 1.2, 1.3, 1.5, 1.6, 1.12, 2.2, 2.4, 3.5 (9 patterns) | Highest — blocks the most patterns |
| G8 — Outbound Controls | 3.1, 3.2, 3.3, 3.4, 3.5, 3.6 (6 patterns) | High — blocks all exfiltration |
| G5 — Command Robustness | 1.4, 1.8, 1.10, 1.11 (4 patterns) | High — blocks terminal-based attacks |
| G7 — Input Sanitization | 2.1, 2.5 (2 patterns, but amplifies all PI chains) | High — reduces all PI-dependent attacks |
| G4 — File Write Restrictions | 2.3 (1 primary, but breaks the most common escalation chain) | High — breaks PI → code exec chain |
| G2 — Initialization Safety | 1.7 (1 pattern, but upgrades all config attacks to zero-click) | Medium — prevents race conditions |
| G3 — Trust Integrity | 4 (1 pattern, but applies across all config surfaces) | Medium — prevents post-approval attacks |
| G6 — Binary Security | 1.9 (1 pattern) | Medium |
| G9 — Network Security | 1.13 (1 pattern) | Medium |

### If You Can Only Do Five Things

1. **Nothing auto-executes from workspace without approval** — G1 blocks 9 patterns
2. **Block all outbound requests from rendering and tool features** — G8 blocks all 6 exfiltration patterns
3. **Harden command parsing** — G5 blocks 4 terminal-based attack patterns
4. **Agent cannot write to its own config files** — G4 breaks the classic PI → code execution escalation chain
5. **Strip invisible Unicode from LLM input** — G7 defeats covert prompt injection delivery across all chains
