#!/usr/bin/env bash
# Start the Ghrab VOC backend (FastAPI) and frontend (Vite) together for local dev.
set -euo pipefail
cd "$(dirname "$0")"

VENV="${VENV:-.venv}"
[ -d "$VENV" ] || python3 -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install -q -r backend/requirements.txt

( cd backend && uvicorn main:app --reload --port 8000 ) &
BACK=$!
( cd frontend && { [ -d node_modules ] || npm install; } && npm run dev ) &
FRONT=$!

trap 'kill $BACK $FRONT 2>/dev/null || true' EXIT INT TERM
echo "Backend  → http://localhost:8000/docs"
echo "Frontend → http://localhost:5173"
wait
