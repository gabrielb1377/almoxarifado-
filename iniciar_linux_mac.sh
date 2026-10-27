#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
echo 'Abra: http://127.0.0.1:8000'
python -m uvicorn main:app --host 127.0.0.1 --port 8000
