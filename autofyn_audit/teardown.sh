#!/usr/bin/env bash
# Agent TARS Security Audit - Cleanup Script
# Pinned commit SHA: 7986f5aea500c4535c0e55dc5c5d0cda73767c45
set -euo pipefail

PID_FILE="/tmp/autofyn_audit_pids.txt"

echo "=== Agent TARS Security Audit Teardown ==="

# --- Kill server processes ---
if [ -f "${PID_FILE}" ]; then
  echo "Stopping server processes..."
  while IFS= read -r pid; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      echo "  Stopping PID ${pid}"
      kill "${pid}" 2>/dev/null || true
    else
      echo "  PID ${pid} not running (already stopped)"
    fi
  done < "${PID_FILE}"
  rm -f "${PID_FILE}"
  echo "  PID file removed"
else
  echo "  No PID file found at ${PID_FILE}"
fi

# --- Clean up test directories ---
echo "Cleaning up test directories..."
if [ -d /tmp/workspace ]; then
  rm -rf /tmp/workspace
  echo "  Removed /tmp/workspace"
fi
if [ -d /tmp/workspace-evil ]; then
  rm -rf /tmp/workspace-evil
  echo "  Removed /tmp/workspace-evil"
fi

# --- Clean up agent server PIDs ---
AGENT_PID_FILE="/tmp/autofyn_audit_agent_pids.txt"
if [ -f "${AGENT_PID_FILE}" ]; then
  echo "Cleaning up agent server PIDs..."
  while IFS= read -r pid; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      echo "  Stopping agent server PID ${pid}"
      kill "${pid}" 2>/dev/null || true
    fi
  done < "${AGENT_PID_FILE}"
  rm -f "${AGENT_PID_FILE}"
  echo "  Agent PID file removed"
fi

# --- Clean up log files ---
echo "Cleaning up log files..."
rm -f /tmp/mcp_commands.log /tmp/mcp_filesystem.log /tmp/autofyn_audit_agent.log
echo "  Removed server log files"

echo ""
echo "=== Teardown complete ==="
