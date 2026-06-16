#!/usr/bin/env bash
set -euo pipefail

log() {
  systemd-cat -t tuskscan-healthcheck echo "$*"
}

restart_unit() {
  local unit="$1"
  local reason="$2"
  log "Restarting ${unit}: ${reason}"
  systemctl restart "$unit"
}

if ! curl -fsS --max-time 10 http://127.0.0.1:8787/health >/dev/null; then
  restart_unit tuskscan-api.service "API health endpoint failed"
fi

if ! curl -fsS --max-time 10 http://127.0.0.1:3000/ >/dev/null; then
  restart_unit tuskscan-web.service "Next.js local page failed"
fi

if ! systemctl is-active --quiet tuskscan-worker.service; then
  restart_unit tuskscan-worker.service "worker service inactive"
fi

if ! curl -fsS --max-time 10 http://127.0.0.1/ >/dev/null; then
  restart_unit caddy.service "Caddy public proxy failed"
fi
