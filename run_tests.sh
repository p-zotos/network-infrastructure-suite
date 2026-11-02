#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Always operate from the project root, regardless of where the script is called from
cd "$(dirname "$0")"

echo "=================================================="
echo "[*] Initializing QA Automation Workspace..."
echo "=================================================="
mkdir -p mock_data test_results pcaps

# Ensure virtual environment exists and dependencies are satisfied
if [ ! -d venv ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install --quiet -r requirements.txt

echo "[*] Generating deterministic network telemetry assets..."
python3 mock_generation_scripts/generate_normal_mock_pcap.py
python3 mock_generation_scripts/generate_stress_mock_pcap.py
# Pass SEED=<n> to replay a specific fuzzing run (the seed is printed on every run)
python3 mock_generation_scripts/generate_exploratory_mock_pcap.py ${SEED:+--seed "$SEED"}

echo "=================================================="
echo "[*] Launching PyTest Network Validation Automation Suite"
echo "=================================================="

# Check if the user provided a specific mode argument (e.g., ./run_tests.sh stress)
if [ "$1" == "real" ]; then
    echo "[*] Real Mode Selected. Initializing live network telemetry capture..."

    # Run the sniffer with sudo to hook network interface frames.
    # Override with e.g. CAPTURE_DURATION=30 CAPTURE_INTERFACE=eth0 ./run_tests.sh real
    sudo -E venv/bin/python3 capture_traffic.py \
        --duration "${CAPTURE_DURATION:-15}" \
        ${CAPTURE_INTERFACE:+--interface "$CAPTURE_INTERFACE"}

    echo -e "\n[*] Analyzing captured E2E production footprint..."
    pytest test_network.py -v -k "real"

elif [ "$1" == "unit" ]; then
    echo "[*] Running analyzer engine unit tests..."
    pytest test_analyzer.py -v

elif [ -z "$1" ]; then
    echo "[*] No mode specified. Running analyzer unit tests and all network test profiles..."
    pytest -v

else
    echo "[*] Targeted execution detected. Launching test profile: $1"
    pytest test_network.py -v -k "$1"
fi

echo -e "\n=================================================="
echo -e "\e[32m[PASSED] All QA Suites Executed Successfully.\e[0m"
echo "=================================================="
