#!/bin/bash
cd "$(dirname "$0")"
echo "========================================"
echo "Starting Network QA Suite..."
echo "========================================"

if [ ! -d "venv" ]; then
    echo "Error: Virtual environment (venv) not found."
    exit 1
fi

source venv/bin/activate
echo "[*] Environment activated."
echo "[*] Running Network Analysis..."

python3 analyzer.py
deactivate
echo "Tests completed."
echo "========================================"
