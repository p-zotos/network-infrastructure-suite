#!/bin/bash

FINAL_OUTPUT="pcaps/real_traffic.pcap"
TMP_OUTPUT="/tmp/real_traffic_temp.pcap"
CAPTURE_DURATION=20

echo "[*] Capturing live TCP traffic for ${CAPTURE_DURATION} seconds..."
mkdir -p pcaps

# Καθαρίζουμε τυχόν παλιά αρχεία
rm -f "$FINAL_OUTPUT"
sudo rm -f "$TMP_OUTPUT"

# Καταγράφουμε στον κοινόχρηστο φάκελο /tmp που δεν έχει ποτέ Permission Denied
sudo tshark -a duration:${CAPTURE_DURATION} -w "$TMP_OUTPUT" -f "tcp"

echo "[*] Processing capture status..."
sleep 1

# Αν το αρχείο δημιουργήθηκε επιτυχώς στο /tmp
if [ -f "$TMP_OUTPUT" ] && [ -s "$TMP_OUTPUT" ]; then
    # Το μεταφέρουμε στο project folder και αλλάζουμε τα δικαιώματα για τον parser
    sudo mv "$TMP_OUTPUT" "$FINAL_OUTPUT"
    sudo chmod 644 "$FINAL_OUTPUT"
    echo "[+] Live traffic captured successfully saved to: $FINAL_OUTPUT"
else
    echo "[WARNING] Capture finished, but file is empty or missing."
    echo "[*] Creating a dummy fallback TCP packet so the parser won't crash..."
    echo "000000 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 00 28 00 01 00 00 40 06 7c 7c 7f 00 00 01 7f 00 00 01 00 50 00 50 00 00 00 00 00 00 00 00 50 02 20 00 55 3f 00 00" | xxd -r -p > "$FINAL_OUTPUT"
    sudo chmod 644 "$FINAL_OUTPUT"
fi
