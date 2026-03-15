#!/bin/bash
# Deploy pi-code/ to Raspberry Pi
# Usage: bash deploy.sh [PI_IP]
# Default IP: 172.20.10.2 (Howie hotspot)

PI_IP="${1:-172.20.10.2}"
PI_USER="pi"
PI_DEST="/home/pi/ken-minimal"

echo "=== The Ken — Deploy ==="
echo ""

# Check connectivity
echo "Checking Pi connectivity..."
if ! ssh -o ConnectTimeout=5 "$PI_USER@$PI_IP" "echo ok" > /dev/null 2>&1; then
  echo "ERROR: Cannot reach Pi at $PI_IP"
  echo "Make sure:"
  echo "  - Pi is powered on"
  echo "  - Both Pi and this laptop are on the same network (Howie hotspot)"
  echo "  - Try: ssh $PI_USER@$PI_IP"
  exit 1
fi
echo "Pi is reachable."
echo ""

# Create directories on Pi
ssh "$PI_USER@$PI_IP" "mkdir -p $PI_DEST/photos"

# Copy project files
echo "Copying files..."
scp pi-code/index.html pi-code/main.js pi-code/package.json pi-code/server.js pi-code/add-contact.html "$PI_USER@$PI_IP:$PI_DEST/"

# Copy config.json only if it doesn't exist on Pi (don't overwrite)
ssh "$PI_USER@$PI_IP" "test -f $PI_DEST/config.json" || scp pi-code/config.json "$PI_USER@$PI_IP:$PI_DEST/"

# Copy contacts.json only if it doesn't exist on Pi (don't overwrite user data)
ssh "$PI_USER@$PI_IP" "test -f $PI_DEST/contacts.json" || scp pi-code/contacts.json "$PI_USER@$PI_IP:$PI_DEST/"

# Copy kiosk setup files if they exist
[ -f pi-code/ken.service ] && scp pi-code/ken.service "$PI_USER@$PI_IP:$PI_DEST/"
[ -f pi-code/setup-kiosk.sh ] && scp pi-code/setup-kiosk.sh "$PI_USER@$PI_IP:$PI_DEST/"

# Install npm dependencies (only if needed)
echo "Checking dependencies..."
ssh "$PI_USER@$PI_IP" "cd $PI_DEST && npm install --production 2>&1 | tail -3"

echo ""
echo "Deploy complete."
echo ""

# Show what's on the Pi
echo "Files on Pi:"
ssh "$PI_USER@$PI_IP" "ls -la $PI_DEST/*.js $PI_DEST/*.html $PI_DEST/*.json 2>/dev/null | awk '{print \$NF, \$5}'"

echo ""
echo "Restarting app..."
# Try systemd service first, fall back to manual launch
ssh "$PI_USER@$PI_IP" "sudo systemctl restart ken 2>/dev/null && echo 'Restarted via systemd' || (pkill -f electron 2>/dev/null; sleep 2; cd $PI_DEST && DISPLAY=:0 setsid npx electron . --disable-gpu > /tmp/ken.log 2>&1 < /dev/null & echo 'Started manually')"
sleep 8

# Verify
RUNNING=$(ssh "$PI_USER@$PI_IP" "pgrep -c electron 2>/dev/null || echo 0" | tr -d '[:space:]')
if [ "$RUNNING" -gt 0 ] 2>/dev/null; then
  echo "App is running ($RUNNING processes)"
  echo ""
  echo "Server log:"
  ssh "$PI_USER@$PI_IP" "grep -E 'Contact server|Device ID|room URL|Room registered|Settings updated' /tmp/ken.log 2>/dev/null | tail -5"
else
  echo "WARNING: App may not have started. Check with: ssh $PI_USER@$PI_IP 'pgrep -c electron'"
fi

echo ""
echo "=== Deploy complete ==="
