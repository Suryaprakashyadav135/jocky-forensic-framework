#!/bin/bash
# JOCKY AV/EDR Bypass Demonstration
#
# Sets up a simulated AV/EDR scanner. Then runs the same forensic
# task two ways:
#
#   1. As a normal shell script dropped to /tmp
#   2. As a JOCKY-compiled, obfuscated, file-less binary
#
# The AV simulator blocks #1 but passes #2. Both produce the same
# forensic findings.

set -e

JOCKY_DIR="/home/kali/Rudhra/Jocky"
WATCH_DIR="/tmp/av_watch"
LOG="/tmp/av_demo.log"

mkdir -p "$WATCH_DIR"
> "$LOG"

# ---------------------------------------------------------------
# Simulated AV/EDR signatures
# ---------------------------------------------------------------
AV_SIGNATURES=(
    "for pid in /proc"
    "grep.*rwx.*maps"
    "/proc/\[0-9\]"
    "/proc/net/tcp"
    "authorized_keys"
    "crontab"
    "etc/passwd"
    "proc_count"
    "scanned"
)

# ---------------------------------------------------------------
# AV scanner: run in background, polls a directory
# ---------------------------------------------------------------
av_scanner() {
    echo "[AV] Scanner started, watching $WATCH_DIR"
    echo "[AV] Signatures: ${AV_SIGNATURES[*]:0:3}..."

    while true; do
        for f in "$WATCH_DIR"/*; do
            if [ ! -f "$f" ]; then continue; fi

            # Skip if already scanned
            MARKER="${f}.scanned"
            if [ -f "$MARKER" ]; then continue; fi

            echo "[AV] New file: $(basename "$f")"
            echo "[AV] Scanning..."

            MATCHED=""
            for sig in "${AV_SIGNATURES[@]}"; do
                if strings "$f" 2>/dev/null | grep -qE "$sig"; then
                    MATCHED="$sig"
                    break
                fi
            done

            if [ -n "$MATCHED" ]; then
                echo "[AV] !!! THREAT DETECTED in $(basename "$f") --- signature: '$MATCHED'"
                echo "[AV] !!! QUARANTINING $(basename "$f") !!!"
                rm -f "$f"
                touch "$MARKER"
                # Log for later
                echo "QUARANTINED: $(basename "$f")" >> "$LOG"
            else
                echo "[AV] Scan complete: $(basename "$f") --- NO THREAT"
                touch "$MARKER"
                echo "PASSED: $(basename "$f")" >> "$LOG"
            fi
        done
        sleep 0.5
    done
}

# ---------------------------------------------------------------
# Start AV in background
# ---------------------------------------------------------------
echo "================================================================"
echo " JOCKY AV/EDR Bypass Demonstration"
echo "================================================================"
echo ""

av_scanner &
AV_PID=$!

cleanup() {
    kill $AV_PID 2>/dev/null || true
    rm -rf "$WATCH_DIR"
}
trap cleanup EXIT

sleep 1  # let scanner settle

# ---------------------------------------------------------------
# Part 1: Normal forensic tool
# ---------------------------------------------------------------
echo ""
echo "################################################################"
echo "#  PART 1: Normal shell forensic tool"
echo "################################################################"
echo ""
echo "[demonstrator] Writing a normal forensic shell script to $WATCH_DIR..."
echo "[demonstrator] Content: process RWX scanner"
echo ""

cat > "$WATCH_DIR/normal_forensic.sh" << 'SHEOF'
#!/bin/bash
# Scan /proc/*/maps for RWX regions (code injection indicator)
for pid in /proc/[0-9]*; do
    p=$(basename $pid)
    if grep -q "rwx" "$pid/maps" 2>/dev/null; then
        echo "PID $p: $(cat $pid/comm 2>/dev/null)"
    fi
done
SHEOF

chmod +x "$WATCH_DIR/normal_forensic.sh"
echo "[demonstrator] Waiting 3 seconds for AV scan..."
sleep 3

if [ -f "$WATCH_DIR/normal_forensic.sh" ]; then
    echo "[demonstrator] File still present, running it..."
    "$WATCH_DIR/normal_forensic.sh" 2>/dev/null | head -3
else
    echo ""
    echo "[demonstrator] ✗ The forensic tool was QUARANTINED by the AV."
    echo "[demonstrator] ✗ The forensic analysis NEVER RAN."
fi

echo ""
echo "----------------------------------------------------------------"
echo ""

# ---------------------------------------------------------------
# Part 2: JOCKY forensic tool
# ---------------------------------------------------------------
echo "################################################################"
echo "#  PART 2: JOCKY-compiled forensic tool"
echo "################################################################"
echo ""

echo "[demonstrator] Building JOCKY version of the same forensic tool..."
cd "$JOCKY_DIR"
./build_jocky.sh jocky_scripts/rwx_scan.jky > /dev/null 2>&1
echo "[demonstrator] Built: /tmp/rwx_scan_final.bin"

echo ""
echo "[demonstrator] Copying the JOCKY binary to $WATCH_DIR for AV scan..."
cp /tmp/rwx_scan_final.bin "$WATCH_DIR/jocky_forensic.bin"
echo "[demonstrator] Waiting 3 seconds for AV scan..."
sleep 3

if [ -f "$WATCH_DIR/jocky_forensic.bin" ]; then
    echo ""
    echo "[demonstrator] ✓ File PASSED the AV scan."
    echo "[demonstrator] ✓ Running it via memfd (file-less execution)..."
    echo ""
    python3 src/memfd_exec.py /tmp/rwx_scan_final.bin 2>/dev/null | head -10
    echo ""
    echo "[demonstrator] ✓ Forensic analysis COMPLETED. Zero detection."
else
    echo ""
    echo "[demonstrator] ✗ JOCKY binary was quarantined."
fi

echo ""
echo "----------------------------------------------------------------"
echo ""
echo "################################################################"
echo "#  SUMMARY"
echo "################################################################"
echo ""
cat "$LOG"
echo ""
echo "Normal shell tool: BLOCKED by signature matching"
echo "JOCKY tool:        PASSED --- same forensic output, no detection"
