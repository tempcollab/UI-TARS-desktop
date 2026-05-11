/**
 * Agent TARS Security Audit - Minimal Agent Server Bootstrap
 * Pinned commit SHA: 7986f5aea500c4535c0e55dc5c5d0cda73767c45
 *
 * Starts agent-server-next in single-tenant or multi-tenant mode.
 *
 * Single-tenant (default): No auth, no CSRF - demonstrates session hijacking.
 *   - tenantConfig.auth=false bypasses authMiddleware entirely
 *   - No authentication on any endpoint
 *
 * Multi-tenant (AUDIT_MULTI_TENANT=true): AuthHook registered (auth.ts enforces X-User-Info)
 *   - tenantConfig.auth=true enables authMiddleware
 *   - X-User-Info header is accepted without any signature/HMAC verification
 *   - Any client can forge any userId by setting the header
 *   - Note: Uses SQLite+fake sandbox config to bypass MongoDB requirement
 *
 * Uses SQLite storage (no MongoDB required).
 * No CSRF protection registered - POST requests work directly (demonstrates bypass).
 */
import { AgentServer, ContextStorageHook, AuthHook } from '../multimodal/tarko/agent-server-next/src/index';
import { resolve } from 'path';

const PORT = parseInt(process.env.AUDIT_AGENT_PORT || '3456', 10);
const MULTI_TENANT = process.env.AUDIT_MULTI_TENANT === 'true';
const workspace = resolve('/tmp/autofyn_audit_workspace');

// In multi-tenant mode we need a sandbox config to avoid initializeMultiTenantServices throwing.
// We provide a fake one - it fails silently in the catch block, server still starts.
// The critical auth.ts vulnerability works regardless of sandbox scheduler.
const sandboxConfig = MULTI_TENANT
  ? {
      sandbox: {
        baseUrl: 'http://localhost:1/fake-sandbox',
        getJwtToken: async () => 'fake-jwt-token',
      },
    }
  : {};

const server = new AgentServer({
  appConfig: {
    agent: {
      type: 'modulePath',
      value: '@omni-tars/agent',
    },
    workspace,
    // Required by omni-agent code-agent plugin assertion check.
    // ignoreSandboxCheck=true skips health check. sandboxUrl must be set (even if fake)
    // because CodeAgentPlugin asserts sandboxUrl truthy in constructor (line 26).
    ignoreSandboxCheck: true,
    sandboxUrl: process.env.AIO_SANDBOX_URL || 'http://localhost:1/fake-sandbox-audit',
    server: {
      port: PORT,
      storage: {
        type: 'sqlite',
      },
      tenant: MULTI_TENANT
        ? { mode: 'multi', auth: true }
        : { mode: 'single', auth: false },
      models: [
        {
          id: 'gpt-4o-mini',
          provider: 'openai',
          displayName: 'GPT-4o-mini (audit)',
          baseURL: process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1',
          apiKey: process.env.OPENAI_API_KEY || 'audit-no-key',
        },
      ],
      ...sandboxConfig,
    },
  },
});

// Always register ContextStorageHook
server.registerHook(ContextStorageHook);

// In multi-tenant mode, register AuthHook - but it only reads X-User-Info header
// without any signature verification (the vulnerability being demonstrated in exploit_07)
if (MULTI_TENANT) {
  server.registerHook(AuthHook);
}

// NOTE: No CSRF hook registered - POST requests go through directly
// This demonstrates that CSRF protection is optional (not enforced by default)

console.log(`Starting audit agent server on port ${PORT} (multi-tenant=${MULTI_TENANT})`);
server.start().catch((err: Error) => {
  console.error('Failed to start agent server:', err);
  process.exit(1);
});
