#!/bin/bash
# Alternative live capture using tshark (equivalent to capture_traffic.py)

FINAL_OUTPUT="pcaps/real_traffic.pcap"
TMP_OUTPUT="/tmp/real_traffic_temp.pcap"
CAPTURE_DURATION=${CAPTURE_DURATION:-20}

echo "[*] Capturing live TCP traffic for ${CAPTURE_DURATION} seconds..."
mkdir -p pcaps

# Clean up any leftovers from previous runs
rm -f "$FINAL_OUTPUT"
sudo rm -f "$TMP_OUTPUT"

# Capture into /tmp: the root-owned tshark process can always write there.
# -F pcap forces classic PCAP output instead of tshark's default pcapng
sudo tshark -a duration:${CAPTURE_DURATION} -F pcap -w "$TMP_OUTPUT" -f "tcp"

echo "[*] Processing capture status..."

# If the capture file was created and is non-empty
if [ -s "$TMP_OUTPUT" ]; then
    # Move it into the project and hand ownership back to the invoking user for the parser
    sudo mv "$TMP_OUTPUT" "$FINAL_OUTPUT"
    sudo chown "$(id -u):$(id -g)" "$FINAL_OUTPUT"
    echo "[+] Live traffic captured successfully saved to: $FINAL_OUTPUT"
else
    # Fail loudly instead of faking a trace: the 'real' test will skip when no capture exists
    echo "[ERROR] Capture finished, but file is empty or missing. Is traffic flowing?"
    exit 1
fi
