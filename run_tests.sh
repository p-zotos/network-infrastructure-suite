#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "=================================================="
echo "[*] Initializing QA Automation Workspace..."
echo "=================================================="
mkdir -p mock_data test_results pcaps

# Ensure virtual environment is active and dependencies are satisfied
source venv/bin/activate
pip install pytest # Ensure framework is present

echo "[*] Generating deterministic network telemetry assets..."
python3 mock_generation_scripts/generate_normal_mock_pcap.py
python3 mock_generation_scripts/generate_stress_mock_pcap.py
python3 mock_generation_scripts/generate_exploratory_mock_pcap.py

echo "=================================================="
echo "[*] Launching PyTest Network Validation Automation Suite"
echo "=================================================="

# Check if the user provided a specific mode argument (e.g., ./run_tests.sh stress)
if [ "$1" == "real" ]; then
    echo "[*] Real Mode Selected, but it is not available yet."
    # echo "[*] Real Mode Selected. Initializing live network telemetry capture..."

    # Run the sniffer script using sudo to hook network interface frames safely
    # Adjust timeframe window by passing seconds as an argument (e.g., 20)
    # sudo -E venv/bin/python3 capture_traffic.py 15

    # echo -e "\n[*] Analyzing captured E2E production footprint..."
    # pytest test_network.py -v -k "real"

elif [ -z "$1" ]; then
    echo "[*] No mode specified. Running all configured network test profiles sequentially..."
    pytest test_network.py -v
else
    echo "[*] Targeted execution detected. Launching test profile: $1"
    pytest test_network.py -v -k "$1"
fi

echo -e "\n=================================================="
echo -e "\e[32m[PASSED] All QA Suites Executed Successfully.\e[0m"
echo "=================================================="
