#!/bin/bash
# Deploy Ken device code to Pi via Tailscale
# Usage: bash deploy.sh [PI_IP]
# Default IP: 100.109.60.63 (Tailscale)

PI_IP="${1:-100.109.60.63}"
PI_USER="pi"
PI_DIR="/home/pi/ken-minimal"
LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== The Ken — Deploy to Pi ==="
echo "Target: $PI_USER@$PI_IP:$PI_DIR"
echo ""

# Check connectivity
echo "[1/4] Checking Pi connectivity..."
if ! ping -c 1 -W 5 "$PI_IP" > /dev/null 2>&1; then
    echo "ERROR: Cannot reach Pi at $PI_IP"
    echo "Check Tailscale is running on both devices."
    exit 1
fi
echo "  Pi is reachable."

# Copy files (exclude node_modules, .git, data files that live on Pi)
echo "[2/4] Copying files..."
scp -o ConnectTimeout=10 \
    "$LOCAL_DIR/main.js" \
    "$LOCAL_DIR/server.js" \
    "$LOCAL_DIR/index.html" \
    "$LOCAL_DIR/config.json" \
    "$LOCAL_DIR/package.json" \
    "$LOCAL_DIR/add-contact.html" \
    "$LOCAL_DIR/setup-kiosk.sh" \
    "$PI_USER@$PI_IP:$PI_DIR/"

# Copy photos directory if it exists
if [ -d "$LOCAL_DIR/photos" ]; then
    scp -r "$LOCAL_DIR/photos" "$PI_USER@$PI_IP:$PI_DIR/"
fi

echo "  Files copied."

# Verify key files
echo "[3/4] Verifying..."
LOCAL_MAIN=$(md5sum "$LOCAL_DIR/main.js" | cut -d' ' -f1)
LOCAL_SERVER=$(md5sum "$LOCAL_DIR/server.js" | cut -d' ' -f1)
REMOTE_HASHES=$(ssh "$PI_USER@$PI_IP" "md5sum $PI_DIR/main.js $PI_DIR/server.js" 2>/dev/null)
REMOTE_MAIN=$(echo "$REMOTE_HASHES" | grep main.js | cut -d' ' -f1)
REMOTE_SERVER=$(echo "$REMOTE_HASHES" | grep server.js | cut -d' ' -f1)

if [ "$LOCAL_MAIN" = "$REMOTE_MAIN" ] && [ "$LOCAL_SERVER" = "$REMOTE_SERVER" ]; then
    echo "  Verified: files match."
else
    echo "  WARNING: Hash mismatch! Check deployment."
    exit 1
fi

# Restart Electron
echo "[4/4] Restarting Electron..."
ssh "$PI_USER@$PI_IP" "pkill -f electron 2>/dev/null; sleep 2; cd $PI_DIR && DISPLAY=:0 nohup npx electron . > /tmp/ken-electron.log 2>&1 &"
sleep 3

RUNNING=$(ssh "$PI_USER@$PI_IP" "pgrep -c electron 2>/dev/null")
if [ "$RUNNING" -gt 0 ]; then
    echo "  Electron running ($RUNNING processes)."
else
    echo "  WARNING: Electron may not have started. Check /tmp/ken-electron.log on Pi."
fi

echo ""
echo "=== Deploy complete ==="
