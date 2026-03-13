#!/bin/bash
# Deploy pi-code/ to Raspberry Pi
# Usage: bash deploy.sh [PI_IP]
# Default IP: 172.20.10.2

PI_IP="${1:-172.20.10.2}"
PI_USER="pi"
PI_DEST="/home/pi/ken-minimal"

echo "Deploying to $PI_USER@$PI_IP:$PI_DEST ..."

# Create directories on Pi
ssh "$PI_USER@$PI_IP" "mkdir -p $PI_DEST/photos"

# Copy project files
scp pi-code/index.html pi-code/main.js pi-code/package.json pi-code/contacts.json "$PI_USER@$PI_IP:$PI_DEST/"

# Download placeholder avatar images (160x160, brand-coloured initials)
ssh "$PI_USER@$PI_IP" "cd $PI_DEST/photos && \
  wget -q 'https://ui-avatars.com/api/?name=S&size=160&background=F5F0E8&color=1A1714&format=png&rounded=false' -O sarah.jpg && \
  wget -q 'https://ui-avatars.com/api/?name=Dr+W&size=160&background=F5F0E8&color=1A1714&format=png&rounded=false' -O drwilson.jpg && \
  wget -q 'https://ui-avatars.com/api/?name=M&size=160&background=F5F0E8&color=1A1714&format=png&rounded=false' -O michael.jpg && \
  wget -q 'https://ui-avatars.com/api/?name=E&size=160&background=F5F0E8&color=1A1714&format=png&rounded=false' -O emma.jpg && \
  echo 'Avatars downloaded' || echo 'Avatar download failed - fallback gradients will be used'"

# Install npm dependencies
ssh "$PI_USER@$PI_IP" "cd $PI_DEST && npm install"

echo ""
echo "Deploy complete. Files on Pi:"
ssh "$PI_USER@$PI_IP" "ls -la $PI_DEST/ && echo '---' && ls -la $PI_DEST/photos/"

echo ""
read -p "Reboot Pi now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  ssh "$PI_USER@$PI_IP" "sudo reboot"
  echo "Rebooting... check VNC in ~30 seconds."
fi
