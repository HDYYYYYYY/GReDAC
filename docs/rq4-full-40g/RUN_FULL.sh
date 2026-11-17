#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
if [[ $# -lt 1 ]]; then
  printf 'Usage: PYTHON=.venv/bin/python bash docs/rq4-full-40g/RUN_FULL.sh NEW_OUTPUT [--check-only]\n' >&2
  exit 2
fi
OUT="$1"
shift
unset GREDAC_BUFFER_DIAGNOSTICS
export GREDAC_COMMIT_DELAY_BOUND=0.05
exec "${PYTHON:-.venv/bin/python}" -u -m experiments.rq4_full_40g --out "$OUT" "$@"
