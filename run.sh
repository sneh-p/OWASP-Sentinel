#!/usr/bin/env bash
# OWASP Sentinel launcher script

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install -r requirements.txt
fi

echo "=========================================================="
echo "  Starting OWASP Sentinel - Repository Security Scanner   "
echo "  Web Interface running on http://127.0.0.1:5000         "
echo "=========================================================="

export PYTHONPATH="$DIR"
exec .venv/bin/python app.py "$@"
