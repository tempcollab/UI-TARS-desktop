#!/usr/bin/env bash
# Agent TARS Security Audit - Agent Server Setup
# Pinned commit SHA: 7986f5aea500c4535c0e55dc5c5d0cda73767c45
# Starts agent-server-next for Round 2 exploit testing.
# Modes:
#   single-tenant (default): No auth. Exposes session hijacking.
#   multi-tenant (AUDIT_MULTI_TENANT=true): Auth via X-User-Info header. Forgery possible.
set -euo pipefail

REPO_DIR="/home/agentuser/repo"
AUDIT_DIR="${REPO_DIR}/autofyn_audit"
AGENT_PID_FILE="/tmp/autofyn_audit_agent_pids.txt"
AGENT_PORT="${AUDIT_AGENT_PORT:-3456}"
MULTI_TENANT="${AUDIT_MULTI_TENANT:-false}"
PINNED_SHA="7986f5aea500c4535c0e55dc5c5d0cda73767c45"
# Use tsx from multimodal workspace where agent-server-next deps are installed
TSX="${REPO_DIR}/multimodal/node_modules/.bin/tsx"

echo "=== Agent TARS Security Audit - Agent Server Setup ==="
echo "Pinned commit: ${PINNED_SHA}"
echo "Agent server port: ${AGENT_PORT}"
echo "Multi-tenant mode: ${MULTI_TENANT}"
echo ""

# --- Verify pinned commit ---
CURRENT_SHA=$(git -C "${REPO_DIR}" rev-parse HEAD)
if [ "${CURRENT_SHA}" != "${PINNED_SHA}" ]; then
  echo "WARNING: Current HEAD ${CURRENT_SHA} differs from pinned SHA ${PINNED_SHA}"
  echo "Audit was validated against pinned commit. Results may differ."
fi

# --- Check tsx is available ---
if [ ! -x "${TSX}" ]; then
  echo "tsx not found at ${TSX} - installing multimodal workspace dependencies..."
  cd "${REPO_DIR}/multimodal"
  npx pnpm@9.10.0 install --ignore-scripts
  if [ ! -x "${TSX}" ]; then
    echo "ERROR: tsx still not found at ${TSX} after install"
    exit 1
  fi
fi

# --- Build agent-server-next and its dependencies if not already built ---
AGENT_SERVER_DIST="${REPO_DIR}/multimodal/tarko/agent-server-next/dist/index.js"
OMNI_AGENT_DIST="${REPO_DIR}/multimodal/omni-tars/omni-agent/dist/index.js"

if [ ! -f "${AGENT_SERVER_DIST}" ] || [ ! -f "${OMNI_AGENT_DIST}" ]; then
  echo ""
  echo "Building agent-server-next and dependencies..."
  cd "${REPO_DIR}/multimodal"
  # Build tarko packages (agent-server-next and its internal deps)
  npx pnpm@9.10.0 --filter "./tarko/**" build 2>&1 | grep -E "Done|Failed|ERR_PNPM" | head -30 || true
  # Build gui-agent packages (required by omni-tars/gui-agent)
  npx pnpm@9.10.0 --filter "@gui-agent/*" build 2>&1 | grep -E "Done|Failed|ERR_PNPM" | head -10 || true
  # Build omni-tars packages (the agent implementation)
  npx pnpm@9.10.0 --filter "@omni-tars/core" --filter "@omni-tars/gui-agent" --filter "@omni-tars/agent" build 2>&1 | grep -E "Done|Failed|ERR_PNPM" | head -10 || true

  if [ ! -f "${AGENT_SERVER_DIST}" ]; then
    echo "ERROR: agent-server-next build failed - dist/index.js not found"
    exit 1
  fi
  echo "Build complete"
else
  echo "Agent server dist already exists, skipping build"
fi

# --- Clean up stale agent server PIDs ---
if [ -f "${AGENT_PID_FILE}" ]; then
  echo "Cleaning up previous agent server PIDs..."
  while IFS= read -r pid; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      echo "  Killing stale process ${pid}"
      kill "${pid}" 2>/dev/null || true
    fi
  done < "${AGENT_PID_FILE}"
  rm -f "${AGENT_PID_FILE}"
  sleep 1
fi

# --- Ensure workspace directory exists ---
mkdir -p /tmp/autofyn_audit_workspace
echo "Workspace: /tmp/autofyn_audit_workspace"

# --- Check if port is already in use ---
if nc -z localhost "${AGENT_PORT}" 2>/dev/null; then
  echo "WARNING: Port ${AGENT_PORT} already in use. Attempting to kill existing process..."
  fuser -k "${AGENT_PORT}/tcp" 2>/dev/null || true
  sleep 2
fi

# --- Start agent server via tsx ---
echo ""
echo "Starting agent server (tsx agent_server_bootstrap.ts)..."
AUDIT_AGENT_PORT="${AGENT_PORT}" \
AUDIT_MULTI_TENANT="${MULTI_TENANT}" \
  "${TSX}" "${AUDIT_DIR}/agent_server_bootstrap.ts" \
  > /tmp/autofyn_audit_agent.log 2>&1 &
AGENT_PID=$!
echo "${AGENT_PID}" >> "${AGENT_PID_FILE}"
echo "  Agent server PID: ${AGENT_PID}"

# --- Wait for agent server to be ready ---
echo ""
echo "Waiting for agent server to be ready on port ${AGENT_PORT}..."

ATTEMPTS=0
MAX_ATTEMPTS=60

while [ "${ATTEMPTS}" -lt "${MAX_ATTEMPTS}" ]; do
  # Try health check endpoint (200 = single-tenant, 401 = multi-tenant auth enforced)
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m 2 \
    "http://localhost:${AGENT_PORT}/api/v1/health" 2>/dev/null || echo "000")
  if [ "${HTTP_STATUS}" = "200" ] || [ "${HTTP_STATUS}" = "401" ]; then
    echo "  Agent server is ready (HTTP ${HTTP_STATUS} from /api/v1/health)"
    break
  fi

  # Also try TCP connection as fallback
  if nc -z localhost "${AGENT_PORT}" 2>/dev/null; then
    echo "  Agent server is ready (TCP connection accepted on port ${AGENT_PORT})"
    break
  fi

  ATTEMPTS=$((ATTEMPTS + 1))
  sleep 0.5

  # Check if process died
  if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
    echo "ERROR: Agent server process ${AGENT_PID} exited unexpectedly"
    echo "  Check logs: /tmp/autofyn_audit_agent.log"
    tail -30 /tmp/autofyn_audit_agent.log
    exit 1
  fi
done

if [ "${ATTEMPTS}" -ge "${MAX_ATTEMPTS}" ]; then
  echo "ERROR: Agent server failed to start after ${MAX_ATTEMPTS} attempts"
  echo "  Check logs: /tmp/autofyn_audit_agent.log"
  tail -30 /tmp/autofyn_audit_agent.log
  exit 1
fi

echo ""
echo "=== Agent server setup complete ==="
echo "Health: http://localhost:${AGENT_PORT}/api/v1/health"
echo "Sessions: http://localhost:${AGENT_PORT}/api/v1/sessions"
echo "Logs: /tmp/autofyn_audit_agent.log"
echo "PID file: ${AGENT_PID_FILE}"
echo ""
echo "Mode: $([ "${MULTI_TENANT}" = "true" ] && echo "multi-tenant (auth=true, X-User-Info forgery possible)" || echo "single-tenant (auth=false, session hijacking possible)")"
