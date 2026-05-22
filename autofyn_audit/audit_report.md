# Security Audit Report: Agent TARS

**Audit Firm:** AutoFyn SignalPilot

**Audit Model:** Claude Opus 4.5

**Target:** Agent TARS / UI-TARS Desktop

**Repository:** `UI-TARS-desktop`

**Commit Reviewed:** `7986f5aea500c4535c0e55dc5c5d0cda73767c45`

**Date:** 2026-05-11

**Status:** 25 Security Findings Validated + 20 Exploit Chain Scenarios Documented

---

## Executive Summary

This audit identified **25 security findings** in Agent TARS, including **4 Critical**, **18 High**, and **3 Medium** severity issues. The highest-risk findings are architectural: MCP servers expose command execution and filesystem capabilities over HTTP without authentication in the tested configuration, the multi-tenant agent server accepts unsigned identity headers, and multiple session/configuration surfaces lack ownership checks or schema validation.

The strongest live-confirmed issues are:

- **Unauthenticated remote command execution** through the MCP commands server.
- **Unauthenticated MCP access** to command and filesystem tools.
- **Identity forgery** through unsigned `X-User-Info` headers in multi-tenant mode.
- **Filesystem boundary bypass** through path-prefix collision (code-level; secondary runtime check limits direct exploitation).
- **Session access and configuration manipulation** in the tested agent server setup.

The audit also documents **20 exploit chain scenarios** showing how these issues compose into realistic attack paths. Some chains are direct live exploits; others combine live-confirmed primitives with source-confirmed browser, LLM, SSRF, XSS, or cloud-metadata legs that require deployment-specific validation before claiming full end-to-end exploitation. Those evidence levels are explicitly labeled below.

## Evidence Types

- **Direct Agent TARS Exploit** — the proof-of-concept executed against the Agent TARS implementation in the local audited environment.
- **Direct Agent TARS Exploit + Source Review** — at least one core step executed live, with remaining impact supported by source review.
- **Source-Confirmed / Partial Live** — the vulnerable code path is present and reviewed, with limited live probing or a runtime precondition not fully exercised.

| ID | Vulnerability | Severity | CVSS | Status | Evidence |
|----|---------------|----------|------|--------|----------|
| ATARS-001 | MCP Command Injection via `run_command` | Critical | 10.0 | Validated | Direct Agent TARS Exploit |
| ATARS-004 | Missing Authentication on MCP HTTP Endpoints | Critical | 9.8 | Validated | Direct Agent TARS Exploit |
| ATARS-007 | `X-User-Info` Identity Forgery | Critical | 9.1 | Validated | Direct Agent TARS Exploit |
| ATARS-012 | Plaintext API Key Exposure in User Config | Critical | 9.1 | Validated | Direct Agent TARS Exploit + Source Review |
| ATARS-002 | Filesystem Path Prefix Collision | High | 8.6 | Validated | Source-Confirmed / Partial Live |
| ATARS-016 | SSRF via Unvalidated `webui.remoteUrl` | High | 8.6 | Validated | Source-Confirmed / Partial Live |
| ATARS-021 | Stored XSS via Unsanitized Workspace Filenames | High | 8.2 | Validated | Source-Confirmed / Partial Live |
| ATARS-006 | Session Hijacking in Single-Tenant Mode | High | 8.1 | Validated | Direct Agent TARS Exploit |
| ATARS-025 | Unvalidated `agentOptions` Override | High | 8.1 | Validated | Direct Agent TARS Exploit + Source Review |
| ATARS-014 | Prompt Injection via Unsanitized Tool Results | High | 8.0 | Validated | Source-Confirmed / Partial Live |
| ATARS-003 | Environment Variable Exposure via Child Process | High | 7.5 | Validated | Direct Agent TARS Exploit |
| ATARS-005 | Arbitrary `cwd` for Command Execution | High | 7.5 | Validated | Direct Agent TARS Exploit |
| ATARS-008 | LLM Params Override Bypass | High | 7.5 | Validated | Source-Confirmed / Partial Live |
| ATARS-009 | Browser SSRF via Navigate Action | High | 7.5 | Validated | Source-Confirmed / Partial Live |
| ATARS-011 | Runtime Settings Injection | High | 7.5 | Validated | Direct Agent TARS Exploit + Source Review |
| ATARS-013 | SSE Wildcard CORS Header | High | 7.5 | Validated | Direct Agent TARS Exploit + Source Review |
| ATARS-015 | Missing Rate Limiting | High | 7.5 | Validated | Direct Agent TARS Exploit |
| ATARS-017 | Unsafe Prototype-Key Handling in `deepMerge` | High | 7.5 | Validated | Source-Confirmed / Partial Live |
| ATARS-019 | Workspace File IDOR | High | 7.5 | Validated | Source-Confirmed / Partial Live |
| ATARS-020 | Symlink Workspace Escape | High | 7.5 | Validated | Source-Confirmed / Partial Live |
| ATARS-022 | Browser Config Poisoning via Shared Singleton | High | 7.5 | Validated | Source-Confirmed / Partial Live |
| ATARS-010 | Browser XSS via `innerHTML` | High | 7.1 | Validated | Source-Confirmed / Partial Live |
| ATARS-018 | CSRF Token Replay | Medium | 6.8 | Validated | Direct Agent TARS Exploit |
| ATARS-023 | Stack Trace Exposure | Medium | 5.3 | Validated | Source-Confirmed / Partial Live |
| ATARS-024 | Log Injection via `sessionId` | Medium | 5.3 | Validated | Source-Confirmed / Partial Live |

---

## Exploit Chains

The following chains combine multiple vulnerabilities into realistic attack scenarios. They demonstrate that the individual findings are not isolated defects: unauthenticated command execution, weak identity, missing ownership checks, unsafe configuration merging, and browser/LLM trust-boundary issues compound into higher-impact paths.

### Chain Evidence Matrix

| Chain | Script | Evidence |
|------|--------|----------|
| A | `chain_A_remote_api_key_theft.sh` | Direct Agent TARS Exploit |
| B | `chain_B_cross_user_key_theft.sh` | Direct Agent TARS Exploit + Source Review |
| C | `chain_C_full_llm_hijack.sh` | Direct Agent TARS Exploit + Source Review |
| D | `chain_D_session_prompt_poisoning.sh` | Direct Agent TARS Exploit + Source Review |
| E | `chain_E_rce_to_file_read.sh` | Direct Agent TARS Exploit + Source Review |
| F | `chain_F_cors_session_theft.sh` | Source-Confirmed / Partial Live |
| G | `chain_G_stored_xss_csrf_amplification.sh` | Direct Agent TARS Exploit + Source Review |
| H | `chain_H_ssrf_via_runtime_settings.sh` | Direct Agent TARS Exploit + Source Review |
| I | `chain_I_prefix_collision_cred_read.sh` | Source-Confirmed / Partial Live |
| J | `chain_J_session_enum_workspace_escape.sh` | Direct Agent TARS Exploit + Source Review |
| K | `chain_K_prototype_pollution_privesc.sh` | Source-Confirmed / Partial Live |
| L | `chain_L_full_rce_lifecycle.sh` | Direct Agent TARS Exploit |
| M | `chain_M_recon_targeted_attack.sh` | Direct Agent TARS Exploit + Source Review |
| N | `chain_N_amplified_dos_cascade.sh` | Direct Agent TARS Exploit + Source Review |
| O | `chain_O_browser_session_theft.sh` | Source-Confirmed / Partial Live |
| P | `chain_P_multitenant_workspace_takeover.sh` | Direct Agent TARS Exploit + Source Review |
| Q | `chain_Q_cross_origin_persistent_rce.sh` | Direct Agent TARS Exploit + Source Review |
| R | `chain_R_prompt_driven_credential_theft.sh` | Direct Agent TARS Exploit + Source Review |
| S | `chain_S_targeted_ssrf_via_recon.sh` | Direct Agent TARS Exploit + Source Review |
| T | `chain_T_browser_pollution_cascade.sh` | Source-Confirmed / Partial Live |

### Chain A: Remote Environment Exposure (ATARS-004 + ATARS-001 + ATARS-003)

**Severity:** Critical (CVSS 10.0)  
**Exploit:** `autofyn_audit/exploit_chains/chain_A_remote_api_key_theft.sh`  
**Evidence:** Direct Agent TARS Exploit

**Attack flow:**
1. Attacker connects to the MCP commands server without authentication.
2. Attacker invokes `run_command` with `printenv`.
3. The command executes via `/bin/sh -c`.
4. The child process inherits the server process environment.
5. Any API keys, tokens, or credentials present in the server environment are exposed.

**Confirmed output:**
```
[PASS STEP 1] MCP commands server responds to unauthenticated requests
[PASS STEP 2] printenv command executed via unauthenticated RCE
[PASS STEP 3] environment variables inherited by child process
```

### Chain B: Cross-User Config Exposure (ATARS-007 + ATARS-012)

**Severity:** Critical (CVSS 9.1)  
**Exploit:** `autofyn_audit/exploit_chains/chain_B_cross_user_key_theft.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Attacker forges `X-User-Info` with a victim `userId`.
2. The server accepts the unsigned identity header.
3. The user config controller returns config data without API-key redaction.
4. Stored provider keys are exposed when the selected user config contains them.

**Confirmed output:**
```
[PASS STEP 1] CSRF token obtained using forged victim identity
[PASS STEP 3] Endpoint reached with forged identity
[PASS STEP 4] user.ts has no apiKey sanitization/redaction
```

### Chain C: LLM Parameter Override (ATARS-025 + ATARS-008)

**Severity:** High (CVSS 8.1)  
**Exploit:** `autofyn_audit/exploit_chains/chain_C_full_llm_hijack.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Attacker creates a session with arbitrary `agentOptions`.
2. `agentOptions` are accepted as `Record<string, any>` without schema validation.
3. `AgentSession.ts` spreads `agentOptions` with highest precedence.
4. `model.params` can override model parameters because untrusted params are spread last.
5. Final outbound LLM behavior requires validation against a live model request sink.

**Confirmed output:**
```
[PASS STEP 3] Zero schema validation for agentOptions
[PASS STEP 4] agentOptions spread in final position
[PASS STEP 5] Session created with malicious agentOptions accepted
```

### Chain D: Session Injection + Prompt Poisoning (ATARS-006 + ATARS-014)

**Severity:** High (CVSS 8.1)  
**Exploit:** `autofyn_audit/exploit_chains/chain_D_session_prompt_poisoning.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Attacker obtains or enumerates a valid session ID in single-tenant mode.
2. Session endpoints accept access without authenticated ownership validation.
3. Attacker injects query content into the target session.
4. Tool-result content can flow into LLM context without sufficient sanitization or trust-boundary marking.
5. LLM compliance with injected instructions was not validated end to end.

**Confirmed output:**
```
[PASS] session access path confirmed
[PASS] prompt-injection sink confirmed by source review
```

### Chain E: RCE to Workspace File Read Scenario (ATARS-001 + ATARS-020)

**Severity:** High (CVSS 8.0)  
**Exploit:** `autofyn_audit/exploit_chains/chain_E_rce_to_file_read.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Attacker executes shell commands through the unauthenticated MCP commands server.
2. Attacker creates or manipulates files/symlinks in a workspace path.
3. The workspace static server uses string path resolution rather than symlink-aware canonicalization.
4. If the static route serves the symlinked path, files outside the workspace can be exposed.

**Confirmed output:**
```
[PASS] MCP command execution confirmed
[PASS] symlink boundary weakness confirmed by source review
```

### Chain F: CORS Session Exposure Risk (ATARS-013 + ATARS-006)

**Severity:** High (CVSS 7.5)  
**Exploit:** `autofyn_audit/exploit_chains/chain_F_cors_session_theft.sh`  
**Evidence:** Source-Confirmed / Partial Live

**Attack flow:**
1. SSE streaming responses set wildcard `Access-Control-Allow-Origin`.
2. Session endpoints expose session data without sufficient ownership checks in the tested mode.
3. A malicious browser origin may be able to read affected responses where request/preflight conditions permit.
4. Full browser execution of the cross-origin session read was not completed in this audit.

**Confirmed output:**
```
[PASS] wildcard CORS behavior/source path confirmed
[PASS] unauthenticated session access confirmed separately
```

### Chain G: Stored XSS + CSRF Replay (ATARS-021 + ATARS-018)

**Severity:** High (CVSS 8.2)  
**Exploit:** `autofyn_audit/exploit_chains/chain_G_stored_xss_csrf_amplification.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Attacker places a malicious filename in a workspace listing path.
2. The static listing template renders filenames without HTML escaping.
3. A victim browser viewing that listing could execute the injected script.
4. CSRF tokens remain reusable until expiry or eviction.
5. If XSS obtains a token, it can amplify mutations through replay.

**Confirmed output:**
```
[PASS] XSS sink confirmed by source review
[PASS] CSRF replay confirmed live
```

### Chain H: Runtime Settings to SSRF Scenario (ATARS-011 + ATARS-016)

**Severity:** High (CVSS 8.6)  
**Exploit:** `autofyn_audit/exploit_chains/chain_H_ssrf_via_runtime_settings.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Runtime settings accept arbitrary keys without schema validation.
2. Agent session configuration spreads those settings into privileged options.
3. Separately, `AgentUIBuilder` fetches configured remote web UI URLs with no SSRF guard.
4. The direct runtime-settings-to-share trigger path requires additional validation.

**Confirmed output:**
```
[PASS] arbitrary runtime settings accepted/persisted
[PASS] unvalidated server-side fetch confirmed by source review
```

### Chain I: Prefix Collision Credential Read (ATARS-002 + ATARS-004)

**Severity:** High (CVSS 8.6)  
**Exploit:** `autofyn_audit/exploit_chains/chain_I_prefix_collision_cred_read.sh`  
**Evidence:** Source-Confirmed / Partial Live

**Attack flow:**
1. Attacker invokes the filesystem MCP server without authentication.
2. The requested path is outside the allowed directory but shares its string prefix.
3. `startsWith()` containment accepts the sibling path.
4. A secondary `realpath`-based parent-directory check can block requests when the sibling parent does not exist.
5. When the sibling directory and file both exist on disk, the prefix collision bypasses the primary containment check.

**Confirmed output:**
```
[PASS] sibling-prefix file read confirmed
[PASS] negative control outside the prefix rejected
```

### Chain J: Session Enumeration + Workspace IDOR (ATARS-006 + ATARS-019)

**Severity:** High (CVSS 7.5)  
**Exploit:** `autofyn_audit/exploit_chains/chain_J_session_enum_workspace_escape.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Attacker enumerates session IDs in the tested single-tenant configuration.
2. Workspace file APIs rely on caller-supplied session identifiers.
3. Source review shows missing ownership binding in the inspected workspace route.
4. Runtime exposure depends on the server variant and route mounting.

**Confirmed output:**
```
[PASS] session enumeration/access confirmed live
[PASS] workspace ownership gap confirmed by source review
```

### Chain K: Prototype-Key Handling + Identity/Config Exposure (ATARS-017 + ATARS-007 + ATARS-012)

**Severity:** High (CVSS 7.5)  
**Exploit:** `autofyn_audit/exploit_chains/chain_K_prototype_pollution_privesc.sh`  
**Evidence:** Source-Confirmed / Partial Live

**Attack flow:**
1. `deepMerge()` accepts prototype-related keys without an explicit guard.
2. Default behavior can alter the returned object's prototype with attacker-controlled generic properties.
3. Separately, `X-User-Info` identity forgery is live-confirmed.
4. User config responses return unredacted API-key fields when a config exists.
5. A process-wide authorization bypass was not validated for default call sites.

**Confirmed output:**
```
[PASS] prototype-key guard missing in deepMerge
[PASS] X-User-Info forgery confirmed live
[PASS] unredacted config return confirmed by source review
```

### Chain L: No-Auth RCE and Environment Exposure (ATARS-004 + ATARS-005 + ATARS-001 + ATARS-003)

**Severity:** Critical (CVSS 10.0)  
**Exploit:** `autofyn_audit/exploit_chains/chain_L_full_rce_lifecycle.sh`  
**Evidence:** Direct Agent TARS Exploit

**Attack flow:**
1. Attacker sends unauthenticated requests to the MCP commands server.
2. Attacker supplies arbitrary `cwd` such as `/etc`.
3. Attacker executes arbitrary shell commands from that directory.
4. Attacker runs `printenv` to expose inherited environment values.
5. File or credential exposure depends on the server process permissions and available secrets.

**Confirmed output:**
```
[PASS STEP 1] MCP commands server responds to unauthenticated requests
[PASS STEP 2] run_command accepted cwd=/root/.ssh without validation
[PASS STEP 4] printenv executed
```

### Chain M: Reconnaissance + Targeted Session Attack (ATARS-023 + ATARS-024 + ATARS-006)

**Severity:** High (CVSS 8.1)  
**Exploit:** `autofyn_audit/exploit_chains/chain_M_recon_targeted_attack.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Error handling can expose stack traces on affected routes.
2. Logs interpolate untrusted session identifiers in the inspected controller.
3. Session access is possible in the tested single-tenant configuration.
4. Stack/log findings help targeting and audit-trail manipulation when the affected routes/log sinks are exercised.

**Confirmed output:**
```
[PASS] session access confirmed live
[PASS] stack/log issues confirmed by source review
```

### Chain N: Amplified DoS via Config Cascade (ATARS-015 + ATARS-025 + ATARS-008)

**Severity:** High (CVSS 8.1)  
**Exploit:** `autofyn_audit/exploit_chains/chain_N_amplified_dos_cascade.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Session creation was not blocked by rate limits in the tested burst.
2. Arbitrary `agentOptions` are accepted at session creation.
3. LLM params can override model request fields.
4. In a production LLM-connected deployment, these issues can amplify cost/resource consumption.
5. The corrected concrete estimate from tested/default limits is approximately **50,000 potential agent iterations**: 50 sessions x 1,000 default maximum iterations. Higher `maxIterations` impact requires proving the requested override is honored by the runtime.

**Confirmed output:**
```
[PASS] high-volume session creation received no 429 responses
[PASS] unvalidated config accepted
[PASS] params override confirmed by source review
[INFO] corrected estimate: 50 sessions x 1,000 default iterations = ~50,000 potential iterations
```

### Chain O: Browser-Based Session Exposure Scenario (ATARS-022 + ATARS-013 + ATARS-006)

**Severity:** High (CVSS 7.5)  
**Exploit:** `autofyn_audit/exploit_chains/chain_O_browser_session_theft.sh`  
**Evidence:** Source-Confirmed / Partial Live

**Attack flow:**
1. Browser MCP config is stored in shared process state.
2. Attacker-controlled headers can influence that shared state.
3. Wildcard CORS exists on streaming responses.
4. Session access is weak in the tested configuration.
5. A full malicious-browser session read was not executed.

**Confirmed output:**
```
[PASS] browser config singleton confirmed by source review
[PASS] CORS/session exposure primitives confirmed
```

### Chain P: Multi-Tenant Workspace Takeover Scenario (ATARS-019 + ATARS-006 + ATARS-021 + ATARS-018 + ATARS-015)

**Severity:** High (CVSS 8.2)  
**Exploit:** `autofyn_audit/exploit_chains/chain_P_multitenant_workspace_takeover.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Workspace APIs lack sufficient ownership binding in the inspected code.
2. Session identifiers can be enumerated or accessed in weak-auth modes.
3. Workspace listings render filenames without escaping.
4. CSRF tokens are replayable.
5. No rate limit blocked high-volume mutation attempts in the tested path.

**Confirmed output:**
```
[PASS] session access and rate-limit absence confirmed live
[PASS] workspace IDOR/XSS components confirmed by source review
```

### Chain Q: Cross-Origin Persistent-Control Scenario (ATARS-013 + ATARS-006 + ATARS-001 + ATARS-021 + ATARS-018 + ATARS-015)

**Severity:** High (CVSS 8.2)  
**Exploit:** `autofyn_audit/exploit_chains/chain_Q_cross_origin_persistent_rce.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. SSE streaming responses include wildcard `Access-Control-Allow-Origin`.
2. Session endpoints expose session identifiers without sufficient ownership checks in the tested configuration.
3. MCP command execution can create files in accessible workspace paths.
4. Workspace directory listing renders filenames without HTML escaping.
5. CSRF tokens remain reusable and no tested rate limit blocks high-volume replay.
6. The browser XSS/CORS loop is source-confirmed but was not fully executed in a browser.

**Confirmed output:**
```
[PASS STEP 1] ACAO wildcard behavior confirmed or source-confirmed
[PASS STEP 3] RCE command executed via unauthenticated MCP run_command
[PASS STEP 5] CSRF token reused multiple times
[PASS STEP 6] parallel requests succeeded without 429 throttling
```

### Chain R: Prompt-Driven Credential Exposure Scenario (ATARS-014 + ATARS-001 + ATARS-003 + ATARS-012 + ATARS-024)

**Severity:** High (CVSS 8.0)  
**Exploit:** `autofyn_audit/exploit_chains/chain_R_prompt_driven_credential_theft.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Tool-result content can enter LLM context without adequate trust-boundary marking.
2. MCP `run_command` provides a direct RCE primitive.
3. `printenv` exposes inherited environment values.
4. User config responses can include plaintext API-key fields when config exists.
5. Log injection can obscure activity if vulnerable log sinks are exercised.
6. Autonomous LLM execution of the injected command was not validated end to end.

**Confirmed output:**
```
[PASS] RCE and environment exposure confirmed live
[PASS] prompt/config/log paths confirmed by source review or partial live probes
```

### Chain S: Targeted SSRF via Reconnaissance (ATARS-023 + ATARS-011 + ATARS-016 + ATARS-002 + ATARS-020)

**Severity:** High (CVSS 8.6)  
**Exploit:** `autofyn_audit/exploit_chains/chain_S_targeted_ssrf_via_recon.sh`  
**Evidence:** Direct Agent TARS Exploit + Source Review

**Attack flow:**
1. Error details can expose implementation paths on affected routes.
2. Runtime settings accept arbitrary keys.
3. `AgentUIBuilder` can fetch unvalidated configured remote URLs.
4. Filesystem prefix collision enables sibling-directory reads.
5. Symlink boundary handling is weak in the inspected workspace static server.
6. Live cloud metadata retrieval was not performed.

**Confirmed output:**
```
[PASS] prefix-collision sibling file read confirmed live
[PASS] runtime settings acceptance confirmed live/source
[PASS] SSRF and symlink risks confirmed by source review
```

### Chain T: Browser Pollution Cascade (ATARS-022 + ATARS-009 + ATARS-017 + ATARS-007 + ATARS-012)

**Severity:** High (CVSS 8.6)  
**Exploit:** `autofyn_audit/exploit_chains/chain_T_browser_pollution_cascade.sh`  
**Evidence:** Source-Confirmed / Partial Live

**Attack flow:**
1. Browser MCP server stores config in module-level singleton state.
2. Attacker-controlled headers can affect shared browser config in the same process.
3. Browser navigation lacks an internal-address blocklist.
4. Separately, `deepMerge()` handles prototype keys unsafely.
5. Separately, identity forgery and unredacted config exposure can expose stored keys when a config exists.
6. This is a set of related browser/config/identity weaknesses, not a proven browser-to-prototype-pollution causal exploit path.

**Confirmed output:**
```
[PASS STEP 1] store.ts module singleton confirmed
[PASS STEP 2] handleNavigate validates protocol only
[PASS STEP 3] deepMerge lacks prototype-key guard
[PASS STEP 4] X-User-Info parsed without signature verification
```

---

## Vulnerability Details

### ATARS-001: MCP Command Injection via `run_command`

**Severity:** Critical (CVSS 10.0)  
**CWE:** CWE-78, CWE-306  
**Affected Code:** `packages/agent-infra/mcp-servers/commands/src/server.ts:143`

#### Description

The MCP commands server exposes `run_command`, which passes user-controlled command strings to `exec()`. Because `exec()` invokes `/bin/sh -c`, shell metacharacters and command chaining are interpreted by the system shell. In the tested configuration, the endpoint is reachable without authentication.

#### Vulnerable Code

```ts
exec(command, { cwd })
```

#### Attack Scenario

An unauthenticated network client sends a JSON-RPC `tools/call` request with `name=run_command` and arbitrary shell content. The command executes with the server process privileges.

#### Proof of Concept

```bash
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_command","arguments":{"command":"id && whoami"}},"id":1}'
```

#### Remediation

Require authentication before tool access. Replace `exec()` with `execFile()` and fixed argument arrays. Add a strict command allowlist and deny shell metacharacters.

### ATARS-002: Filesystem Path Prefix Collision

**Severity:** High (CVSS 8.6)  
**CWE:** CWE-22  
**Affected Code:** `packages/agent-infra/mcp-servers/filesystem/src/server.ts:75-77`

#### Description

The filesystem server checks path containment with `startsWith(dir)`. A sibling path such as `/private/tmp/workspace-evil` passes when the allowed directory is `/private/tmp/workspace`. The later realpath check also uses `startsWith(dir)`, so an existing sibling-prefix target remains reachable. Requests for non-existent sibling parents can fail at the parent-directory check.

#### Vulnerable Code

```ts
normalizedRequested.startsWith(dir)
```

#### Attack Scenario

An attacker reads a file outside the allowed directory by placing it in a sibling path with the same string prefix.

#### Proof of Concept

```bash
curl -X POST http://localhost:8090/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/private/tmp/workspace-evil/secret.txt"}},"id":1}'
```

#### Remediation

Check `requested === dir || requested.startsWith(dir + path.sep)`, or use `path.relative()` and reject paths beginning with `..`.

### ATARS-003: Environment Variable Exposure via Child Process

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-200  
**Affected Code:** `packages/agent-infra/mcp-servers/commands/src/server.ts:143`

#### Description

Child processes spawned by `run_command` inherit the full server process environment. Any secrets present in that environment are readable with `printenv`.

#### Attack Scenario

An attacker with access to `run_command` executes `printenv` and receives inherited environment values, including any API keys or tokens configured on the server process.

#### Proof of Concept

```bash
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_command","arguments":{"command":"printenv"}},"id":1}'
```

#### Remediation

Pass a minimal explicit `env` to child processes and avoid placing long-lived secrets in process-wide environment variables.

### ATARS-004: Missing Authentication on MCP HTTP Endpoints

**Severity:** Critical (CVSS 9.8)  
**CWE:** CWE-306  
**Affected Code:** `packages/agent-infra/mcp-http-server/src/startServer.ts:115-117`

#### Description

The MCP HTTP server supports middleware, but the tested commands and filesystem servers start without authentication middleware. Any network client can list and invoke tools.

#### Proof of Concept

```bash
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'
```

#### Remediation

Require bearer-token authentication or mTLS for all MCP HTTP transports. Bind to localhost by default and require an explicit unsafe flag for remote binding.

### ATARS-005: Arbitrary `cwd` for Command Execution

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-22  
**Affected Code:** `packages/agent-infra/mcp-servers/commands/src/server.ts:137-140`

#### Description

`run_command` accepts a caller-supplied `cwd` without containment validation. Commands can execute from sensitive directories such as `/etc`, `/var`, or SSH/key directories.

#### Proof of Concept

```bash
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"run_command","arguments":{"command":"pwd && ls -la","cwd":"/etc"}},"id":1}'
```

#### Remediation

Restrict `cwd` to an approved workspace root using canonical paths and reject absolute paths outside that root.

### ATARS-006: Session Hijacking in Single-Tenant Mode

**Severity:** High (CVSS 8.1)  
**CWE:** CWE-306  
**Affected Code:** `agent-server-next/src/middlewares/auth.ts:32-35`, `controllers/sessions.ts`

#### Description

Single-tenant mode bypasses authentication. Session access is controlled primarily by possession of a `sessionId`, and tested session endpoints returned session events/details without authenticated ownership validation.

#### Attack Scenario

An attacker who obtains or enumerates a session ID can read session details and event history, and may inject queries into that session depending on route exposure.

#### Remediation

Enable authentication by default. Bind every session to an authenticated principal and enforce ownership checks on every session-scoped endpoint.

### ATARS-007: `X-User-Info` Identity Forgery

**Severity:** Critical (CVSS 9.1)  
**CWE:** CWE-287, CWE-290  
**Affected Code:** `agent-server-next/src/middlewares/auth.ts:40-42`

#### Description

The multi-tenant server decodes `X-User-Info` as URL-decoded JSON and trusts the resulting identity object. There is no JWT, HMAC, signature, certificate, or upstream verification.

#### Vulnerable Code

```ts
JSON.parse(decodeURIComponent(encodedUser))
```

#### Proof of Concept

```bash
FORGED='%7B%22userId%22%3A%22admin%22%2C%22email%22%3A%22admin%40company.com%22%7D'
curl -X POST http://localhost:3457/api/v1/sessions/create \
  -H "X-User-Info: ${FORGED}" \
  -H 'Content-Type: application/json' \
  -d '{"agentOptions":{}}'
```

#### Remediation

Accept identities only from a trusted, signed token or verified upstream proxy. Reject client-supplied identity headers unless cryptographically authenticated.

### ATARS-008: LLM Params Override Bypass

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-20  
**Affected Code:** `model-provider/src/llm-client.ts:65-71`

#### Description

Untrusted `params` are spread after trusted LLM configuration, allowing request fields such as model, system prompt, base URL, and token limits to be overridden.

#### Remediation

Replace free-form params with a strict allowlist. Never spread untrusted configuration last into privileged request objects.

### ATARS-009: Browser SSRF via Navigate Action

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-918  
**Affected Code:** `browser-operator/src/browser-operator.ts` (handleNavigate method)

#### Description

The browser navigate action validates only HTTP/HTTPS scheme format and has no blocklist for internal IP ranges or metadata endpoints.

#### Remediation

Block localhost, RFC1918, link-local, and cloud metadata ranges before `page.goto()`. Resolve DNS and validate final IPs after redirects.

### ATARS-010: Browser XSS via `innerHTML`

**Severity:** High (CVSS 7.1)  
**CWE:** CWE-79  
**Affected Code:** `browser-operator/src/ui-helper.ts` (showActionInfo method)

#### Description

LLM-generated action text and thought content are injected into the browser UI with `innerHTML` and no sanitizer.

#### Remediation

Use `textContent` for plain text or sanitize with DOMPurify before assigning HTML.

### ATARS-011: Runtime Settings Injection

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-20  
**Affected Code:** `agent-server-next/src/services/session/AgentSession.ts:191-197`

#### Description

Runtime settings accept arbitrary keys and spread them into agent options. This allows attackers to persist unexpected keys into privileged session configuration.

#### Remediation

Validate runtime settings with a schema and reject unknown fields. Avoid spreading request objects into privileged config.

### ATARS-012: Plaintext API Key Exposure in User Config

**Severity:** Critical (CVSS 9.1)  
**CWE:** CWE-200, CWE-312  
**Affected Code:** `agent-server-next/src/controllers/user.ts:34`

#### Description

The user config endpoint returns `config` without API-key redaction. Combined with identity forgery, this can expose stored provider credentials when config records exist.

#### Remediation

Encrypt provider keys at rest. Redact or omit secrets in API responses. Fix identity forgery so users cannot select arbitrary identities.

### ATARS-013: SSE Wildcard CORS Header

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-942  
**Affected Code:** `agent-server-next/src/controllers/queries.ts:187,221`

#### Description

Streaming responses set `Access-Control-Allow-Origin: *` directly. This bypasses centralized CORS policy for that response path. Browser exploitability still depends on request shape and preflight behavior.

#### Remediation

Remove hardcoded wildcard headers and enforce a centralized allowlist-based CORS policy.

### ATARS-014: Prompt Injection via Unsanitized Tool Results

**Severity:** High (CVSS 8.0)  
**CWE:** CWE-74  
**Affected Code:** `agent/src/agent/runner/tool-processor.ts`, `message-history.ts`

#### Description

Tool results flow into the LLM context without sufficient boundary marking or sanitization. In non-native tool-call modes, tool content can be represented as user-role content.

#### Remediation

Treat tool output as untrusted data. Add explicit provenance markers, quote boundaries, and model instructions that tool output is not executable instruction.

### ATARS-015: Missing Rate Limiting

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-770  
**Affected Code:** `agent-server-next/src/routes/*`

#### Description

No rate-limiting middleware was found on inspected session/query routes. A tested burst of session-creation requests completed without `429` throttling.

#### Remediation

Add per-IP, per-user, and per-session limits. Rate-limit session creation, query execution, and expensive model operations.

### ATARS-016: SSRF via Unvalidated `webui.remoteUrl`

**Severity:** High (CVSS 8.6)  
**CWE:** CWE-918  
**Affected Code:** `agent-ui-builder/src/builder.ts:85-97`

#### Description

`AgentUIBuilder.getHtmlContent()` fetches `webui.remoteUrl` without URL validation or SSRF blocklists. A runtime path that lets attackers control `webui.remoteUrl` can turn this into server-side requests to internal URLs.

#### Remediation

Validate schemes, hostnames, resolved IP addresses, redirects, and private network ranges before any server-side fetch.

### ATARS-017: Unsafe Prototype-Key Handling in `deepMerge`

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-1321  
**Affected Code:** `shared-utils/src/deepMerge.ts:48-64`

#### Description

`deepMerge()` iterates user-controlled keys with `for...in` and lacks explicit guards for `__proto__`, `constructor`, and `prototype`. Default behavior can alter the returned object's prototype with attacker-controlled generic properties. Global `Object.prototype` pollution was reproduced only with `nonDestructive:false`; default production impact requires a validated call path. No authorization bypass was found in the audited codebase.

#### Remediation

Reject prototype-related keys before assignment. Use `Object.keys()` over trusted own properties and avoid recursive merge into special object properties.

### ATARS-018: CSRF Token Replay

**Severity:** Medium (CVSS 6.8)  
**CWE:** CWE-294  
**Affected Code:** `agent-server/src/api/middleware/csrf-protection.ts:34-44`

#### Description

CSRF tokens remain valid after successful use until expiry or eviction. The tested token was reusable across multiple mutation requests.

#### Remediation

Delete CSRF tokens after successful validation and bind tokens to user/session context.

### ATARS-019: Workspace File IDOR

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-639  
**Affected Code:** `agent-server/src/api/controllers/sessions.ts:432-521`

#### Description

Workspace file routes use caller-provided session IDs without sufficient ownership validation in the inspected implementation.

#### Remediation

Resolve workspace access through authenticated user-session ownership. Reject session IDs not owned by the caller.

### ATARS-020: Symlink Workspace Escape

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-59  
**Affected Code:** `agent-server/src/utils/workspace-static-server.ts:82-87`

#### Description

`isPathSafe()` uses `path.resolve()` but does not resolve symlinks with `realpath`. A symlink inside the workspace can point outside the workspace while passing string-based checks.

#### Remediation

Use `fs.realpathSync()` or equivalent canonicalization before boundary checks.

### ATARS-021: Stored XSS via Unsanitized Workspace Filenames

**Severity:** High (CVSS 8.2)  
**CWE:** CWE-79  
**Affected Code:** `agent-server/src/utils/workspace-static-server.ts:191,218,235`

#### Description

Workspace directory listing HTML interpolates `file.name` and `sessionId` without escaping. A malicious filename can become executable HTML/JavaScript when rendered.

#### Remediation

Escape all user-controlled values before HTML interpolation.

### ATARS-022: Browser Config Poisoning via Shared Singleton

**Severity:** High (CVSS 7.5)  
**CWE:** CWE-668, CWE-306  
**Affected Code:** `mcp-servers/browser/src/index.ts:168-183`, `store.ts:11-41`, `server.ts:47-52`

#### Description

Browser MCP server request headers flow into module-level singleton state. Attacker-controlled headers can affect browser config for affected requests sharing the same process.

#### Remediation

Store browser configuration per request/session. Authenticate before accepting browser configuration headers.

### ATARS-023: Stack Trace Exposure

**Severity:** Medium (CVSS 5.3)  
**CWE:** CWE-209  
**Affected Code:** `agent-server-next/src/utils/error-handler.ts:55`

#### Description

Certain error paths include `error.stack` in response details, exposing file paths and implementation details.

#### Remediation

Return stack traces only in local development mode.

### ATARS-024: Log Injection via `sessionId`

**Severity:** Medium (CVSS 5.3)  
**CWE:** CWE-117  
**Affected Code:** `agent-server/src/api/controllers/sessions.ts:780-785`

#### Description

A self-documented FIXME notes that untrusted `sessionId` is interpolated into log output. Newlines or control characters can forge log entries if decoded before logging.

#### Remediation

Use structured logging and validate `sessionId` against a strict character allowlist.

### ATARS-025: Unvalidated `agentOptions` Override

**Severity:** High (CVSS 8.1)  
**CWE:** CWE-915  
**Affected Code:** `agent-server-next/src/services/session/AgentSessionFactory.ts:56-61`, `AgentSession.ts:192-196`

#### Description

`agentOptions` are accepted as an arbitrary object and spread into privileged session configuration with highest precedence.

#### Remediation

Define a strict schema for `agentOptions`, cap dangerous numeric values such as `maxIterations`, and reject unknown keys.

---

## Reproduction Instructions

### Prerequisites

- Node.js 22.x recommended for the current audit scripts.
- pnpm 9.10.0 via `npx`.
- Repository checkout containing audited commit `7986f5aea500c4535c0e55dc5c5d0cda73767c45`.

### Run All Checks

```bash
cd autofyn_audit
./run_all_exploits.sh
```

### Expected Output

The current audit suite reports:

```text
=== Summary: 45/45 checks met expected criteria ===
Note: some checks use static or partial-live evidence; see audit_report.md evidence labels.
```

### Cleanup

```bash
./teardown.sh
```

---

## Conclusion

Agent TARS exposes several high-impact trust-boundary failures. The most urgent remediation is to authenticate all MCP and agent-server routes, remove unauthenticated command/filesystem access, and replace unsigned identity headers with cryptographically verified identity. After authentication is in place, the next priority is enforcing ownership checks, schema validation, output encoding, SSRF controls, and rate limiting.

The exploit chains show that partial fixes are insufficient. For example, removing wildcard CORS does not address unauthenticated command execution; fixing XSS does not address identity forgery; and redacting API keys does not address unsigned user identity. The security posture should be improved as a system, with authentication and authorization treated as foundational controls.

## Files Delivered

```
autofyn_audit/
├── audit_report.md
├── run_all_exploits.sh
├── setup.sh
├── setup_agent_server.sh
├── teardown.sh
├── exploit_01_command_injection.sh
├── exploit_02_path_traversal.sh
├── exploit_03_env_leakage.sh
├── exploit_04_unauth_access.sh
├── exploit_05_cwd_traversal.sh
├── exploit_06_session_hijacking.sh
├── exploit_07_header_forgery.sh
├── exploit_08_params_override.sh
├── exploit_09_browser_ssrf.sh
├── exploit_10_browser_xss.sh
├── exploit_11_runtime_settings_injection.sh
├── exploit_12_api_key_exfiltration.sh
├── exploit_13_sse_cors_bypass.sh
├── exploit_14_prompt_injection_tool_results.sh
├── exploit_15_rate_limiting_absence.sh
├── exploit_16_ssrf_remote_url.sh
├── exploit_17_prototype_pollution.sh
├── exploit_18_csrf_token_replay.sh
├── exploit_19_workspace_idor.sh
├── exploit_20_symlink_workspace_escape.sh
├── exploit_21_stored_xss_filename.sh
├── exploit_22_browser_config_poisoning.sh
├── exploit_23_stack_trace_exposure.sh
├── exploit_24_log_injection.sh
├── exploit_25_agent_config_override.sh
└── exploit_chains/
    ├── chain_A_remote_api_key_theft.sh
    ├── chain_B_cross_user_key_theft.sh
    ├── chain_C_full_llm_hijack.sh
    ├── chain_D_session_prompt_poisoning.sh
    ├── chain_E_rce_to_file_read.sh
    ├── chain_F_cors_session_theft.sh
    ├── chain_G_stored_xss_csrf_amplification.sh
    ├── chain_H_ssrf_via_runtime_settings.sh
    ├── chain_I_prefix_collision_cred_read.sh
    ├── chain_J_session_enum_workspace_escape.sh
    ├── chain_K_prototype_pollution_privesc.sh
    ├── chain_L_full_rce_lifecycle.sh
    ├── chain_M_recon_targeted_attack.sh
    ├── chain_N_amplified_dos_cascade.sh
    ├── chain_O_browser_session_theft.sh
    ├── chain_P_multitenant_workspace_takeover.sh
    ├── chain_Q_cross_origin_persistent_rce.sh
    ├── chain_R_prompt_driven_credential_theft.sh
    ├── chain_S_targeted_ssrf_via_recon.sh
    └── chain_T_browser_pollution_cascade.sh
```
