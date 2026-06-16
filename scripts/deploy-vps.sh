#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/tuskscan/app}"
APP_USER="${APP_USER:-tuskscan}"
BRANCH="${BRANCH:-main}"
REPO_URL="${REPO_URL:-https://github.com/kezuflow/tuskscan.git}"
API_ENV="${API_ENV:-/etc/tuskscan/api.env}"
WEB_ENV="${WEB_ENV:-/etc/tuskscan/web.env}"

export CI=1
export NODE_ENV=production
export NEXT_TELEMETRY_DISABLED=1

if ! command -v git >/dev/null 2>&1; then
  echo "git is required on the VPS" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "node is required on the VPS" >&2
  exit 1
fi

corepack enable
corepack prepare pnpm@9.0.0 --activate

mkdir -p "$(dirname "$APP_DIR")"

if [ ! -d "$APP_DIR/.git" ]; then
  rm -rf "$APP_DIR"
  git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

cd "$APP_DIR"
git fetch origin "$BRANCH"

current_rev="$(git rev-parse HEAD 2>/dev/null || true)"
target_rev="$(git rev-parse "origin/$BRANCH")"
if [ "${FORCE_DEPLOY:-0}" != "1" ] &&
  [ "$current_rev" = "$target_rev" ] &&
  systemctl is-active --quiet tuskscan-api.service &&
  systemctl is-active --quiet tuskscan-worker.service &&
  systemctl is-active --quiet tuskscan-web.service; then
  echo "TuskScan already deployed at ${target_rev:0:7}"
  exit 0
fi

git reset --hard "origin/$BRANCH"

if [ ! -f "$API_ENV" ]; then
  echo "Missing API env file: $API_ENV" >&2
  exit 1
fi

if [ ! -f "$WEB_ENV" ]; then
  echo "Missing web env file: $WEB_ENV" >&2
  exit 1
fi

ln -sfn "$API_ENV" apps/api/.env
ln -sfn "$WEB_ENV" apps/web/.env

pnpm install --frozen-lockfile
pnpm --filter api db:generate
pnpm build

if id "$APP_USER" >/dev/null 2>&1; then
  chown -R "$APP_USER:$APP_USER" "$APP_DIR"
fi

systemctl restart tuskscan-api.service
systemctl restart tuskscan-worker.service
systemctl restart tuskscan-web.service
systemctl --no-pager --full status tuskscan-api.service >/dev/null
systemctl --no-pager --full status tuskscan-worker.service >/dev/null
systemctl --no-pager --full status tuskscan-web.service >/dev/null

echo "TuskScan deployed from origin/$BRANCH at $(git rev-parse --short HEAD)"
