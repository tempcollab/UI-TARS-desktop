#!/usr/bin/env bash
# Agent TARS Security Audit - Environment Setup
# Pinned commit SHA: 7986f5aea500c4535c0e55dc5c5d0cda73767c45
# Requires: bash >= 4.0, node, pnpm, curl or nc
set -euo pipefail

REPO_DIR="/home/agentuser/repo"
AUDIT_DIR="${REPO_DIR}/autofyn_audit"
PID_FILE="/tmp/autofyn_audit_pids.txt"
COMMANDS_PORT=8089
FS_PORT=8090
PINNED_SHA="7986f5aea500c4535c0e55dc5c5d0cda73767c45"

echo "=== Agent TARS Security Audit Setup ==="
echo "Pinned commit: ${PINNED_SHA}"
echo "Repo: ${REPO_DIR}"

# --- Verify pinned commit ---
CURRENT_SHA=$(git -C "${REPO_DIR}" rev-parse HEAD)
if [ "${CURRENT_SHA}" != "${PINNED_SHA}" ]; then
  echo "WARNING: Current HEAD ${CURRENT_SHA} differs from pinned SHA ${PINNED_SHA}"
  echo "Audit was validated against pinned commit. Results may differ."
fi

# --- Clean up stale PIDs from previous run ---
if [ -f "${PID_FILE}" ]; then
  echo "Cleaning up previous run PIDs..."
  while IFS= read -r pid; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      echo "  Killing stale process ${pid}"
      kill "${pid}" 2>/dev/null || true
    fi
  done < "${PID_FILE}"
  rm -f "${PID_FILE}"
  sleep 1
fi

# --- Build MCP servers ---
echo ""
echo "Building MCP servers..."
cd "${REPO_DIR}"
npx pnpm@9.10.0 \
  --filter @agent-infra/mcp-http-server \
  --filter @agent-infra/mcp-server-commands \
  --filter @agent-infra/mcp-server-filesystem \
  run build

COMMANDS_DIST="${REPO_DIR}/packages/agent-infra/mcp-servers/commands/dist/index.cjs"
FS_DIST="${REPO_DIR}/packages/agent-infra/mcp-servers/filesystem/dist/index.cjs"

if [ ! -f "${COMMANDS_DIST}" ]; then
  echo "ERROR: Commands server dist not found: ${COMMANDS_DIST}"
  exit 1
fi

if [ ! -f "${FS_DIST}" ]; then
  echo "ERROR: Filesystem server dist not found: ${FS_DIST}"
  exit 1
fi

# --- Create test directories ---
echo ""
echo "Creating test directories..."
mkdir -p /tmp/workspace
mkdir -p /tmp/workspace-evil
echo "SECRET_DATA_12345" > /tmp/workspace-evil/secret.txt
echo "  Created /tmp/workspace (allowed directory)"
echo "  Created /tmp/workspace-evil/secret.txt (sibling - outside allowed, prefix collision target)"

# --- Start MCP commands server ---
echo ""
echo "Starting MCP commands server on port ${COMMANDS_PORT}..."
node "${COMMANDS_DIST}" --port "${COMMANDS_PORT}" \
  > /tmp/mcp_commands.log 2>&1 &
COMMANDS_PID=$!
echo "${COMMANDS_PID}" >> "${PID_FILE}"
echo "  Commands server PID: ${COMMANDS_PID}"

# --- Start MCP filesystem server ---
echo "Starting MCP filesystem server on port ${FS_PORT}..."
node "${FS_DIST}" --port "${FS_PORT}" --allowed-directories /tmp/workspace \
  > /tmp/mcp_filesystem.log 2>&1 &
FS_PID=$!
echo "${FS_PID}" >> "${PID_FILE}"
echo "  Filesystem server PID: ${FS_PID}"

# --- Wait for servers to be ready (TCP check) ---
echo ""
echo "Waiting for servers to be ready..."

wait_for_port() {
  local port="$1"
  local label="$2"
  local attempts=0
  local max_attempts=50

  while [ "${attempts}" -lt "${max_attempts}" ]; do
    if nc -z localhost "${port}" 2>/dev/null; then
      echo "  ${label} is ready on port ${port}"
      return 0
    fi
    # Fallback: try curl POST if nc not available
    if curl -s -m 1 -X POST "http://localhost:${port}/mcp" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":0}' \
        2>/dev/null | grep -q 'tools\|result\|error'; then
      echo "  ${label} is ready on port ${port}"
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.2
  done

  echo "ERROR: ${label} failed to start on port ${port} after ${max_attempts} attempts"
  echo "  Check logs:"
  echo "    Commands: /tmp/mcp_commands.log"
  echo "    Filesystem: /tmp/mcp_filesystem.log"
  return 1
}

wait_for_port "${COMMANDS_PORT}" "MCP commands server"
wait_for_port "${FS_PORT}" "MCP filesystem server"

echo ""
echo "=== Setup complete ==="
echo "Commands server: http://localhost:${COMMANDS_PORT}/mcp"
echo "Filesystem server: http://localhost:${FS_PORT}/mcp"
echo "PIDs stored in: ${PID_FILE}"
echo ""
echo "Run exploits with: ${AUDIT_DIR}/run_all_exploits.sh"
echo "Cleanup with: ${AUDIT_DIR}/teardown.sh"
