#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pnpm --dir web/guard-dashboard build
rm -rf internal/guard/web/assets/dist
cp -R web/guard-dashboard/dist internal/guard/web/assets/dist
