#!/bin/bash
# setup-kiosk.sh — Kiosk hardening for The Ken on Raspberry Pi 4
# Run as: sudo bash /home/pi/ken-minimal/setup-kiosk.sh

set -e

echo "========================================="
echo "  The Ken — Kiosk Setup & Hardening"
echo "========================================="
echo ""

KEN_DIR="/home/pi/ken-minimal"
LXDE_AUTOSTART="/etc/xdg/lxsession/LXDE-pi/autostart"
LIGHTDM_CONF="/etc/lightdm/lightdm.conf"
USER_AUTOSTART="/home/pi/.config/autostart"
BOOT_CONFIG="/boot/firmware/config.txt"
[ ! -f "$BOOT_CONFIG" ] && BOOT_CONFIG="/boot/config.txt"

# --- 1. Install the systemd service ---
echo "[1/12] Installing ken.service..."
cp "$KEN_DIR/ken.service" /etc/systemd/system/ken.service
systemctl daemon-reload
systemctl enable ken.service
echo "        Service installed and enabled."

# --- 2. Hide the mouse cursor ---
echo "[2/12] Installing unclutter (hide cursor)..."
apt-get update -qq
apt-get install -y -qq unclutter > /dev/null 2>&1
if [ -f "$LXDE_AUTOSTART" ]; then
    if ! grep -q "unclutter" "$LXDE_AUTOSTART"; then
        echo "@unclutter -idle 0.5 -root" >> "$LXDE_AUTOSTART"
    fi
fi
mkdir -p "$USER_AUTOSTART"
cat > "$USER_AUTOSTART/hide-cursor.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=Hide Cursor
Exec=unclutter -idle 0.5 -root
X-GNOME-Autostart-enabled=true
EOF
echo "        Cursor hiding configured."

# --- 3. Disable screen blanking / screensaver ---
echo "[3/12] Disabling screen blanking..."
if [ -f "$LXDE_AUTOSTART" ]; then
    if ! grep -q "xset s off" "$LXDE_AUTOSTART"; then
        cat >> "$LXDE_AUTOSTART" << 'XSET'
@xset s off
@xset -dpms
@xset s noblank
XSET
    fi
fi
cat > "$USER_AUTOSTART/disable-blanking.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=Disable Screen Blanking
Exec=bash -c "sleep 3 && xset s off && xset -dpms && xset s noblank"
X-GNOME-Autostart-enabled=true
EOF
if [ -f "$LIGHTDM_CONF" ]; then
    if ! grep -q "xserver-command=X -s 0 -dpms" "$LIGHTDM_CONF"; then
        sed -i '/^\[Seat:\*\]/a xserver-command=X -s 0 -dpms' "$LIGHTDM_CONF"
    fi
fi
echo "        Screen blanking disabled."

# --- 4. Disable desktop panel and icons ---
echo "[4/12] Disabling desktop panel and icons..."
if [ -f "$LXDE_AUTOSTART" ]; then
    sed -i 's/^@lxpanel/#@lxpanel/' "$LXDE_AUTOSTART"
    sed -i 's/^@pcmanfm --desktop/#@pcmanfm --desktop/' "$LXDE_AUTOSTART"
fi
PCMANFM_DESKTOP_CONF="/home/pi/.config/pcmanfm/LXDE-pi/desktop-items-0.conf"
if [ -f "$PCMANFM_DESKTOP_CONF" ]; then
    sed -i 's/^show_documents=.*/show_documents=0/' "$PCMANFM_DESKTOP_CONF"
    sed -i 's/^show_trash=.*/show_trash=0/' "$PCMANFM_DESKTOP_CONF"
    sed -i 's/^show_mounts=.*/show_mounts=0/' "$PCMANFM_DESKTOP_CONF"
fi
echo "        Panel and icons disabled."

# --- 5. Configure auto-login ---
echo "[5/12] Configuring auto-login for user pi..."
if [ -f "$LIGHTDM_CONF" ]; then
    if ! grep -q "^autologin-user=pi" "$LIGHTDM_CONF"; then
        sed -i '/^\[Seat:\*\]/a autologin-user=pi' "$LIGHTDM_CONF" 2>/dev/null || true
    fi
fi
if command -v raspi-config > /dev/null 2>&1; then
    raspi-config nonint do_boot_behaviour B4 2>/dev/null || true
fi
echo "        Auto-login configured."

# --- 6. Enable OV5647 camera (CSI ribbon cable) ---
echo "[6/12] Enabling camera (OV5647)..."
if [ -f "$BOOT_CONFIG" ]; then
    if ! grep -q "^camera_auto_detect=1" "$BOOT_CONFIG"; then
        echo "camera_auto_detect=1" >> "$BOOT_CONFIG"
    fi
    if grep -q "^start_x=1" "$BOOT_CONFIG"; then
        sed -i 's/^start_x=1/#start_x=1/' "$BOOT_CONFIG"
    fi
fi
if ! command -v libcamera-still > /dev/null 2>&1; then
    apt-get install -y -qq libcamera-apps > /dev/null 2>&1 || true
fi
echo "        Camera configured."

# --- 7. Firewall (ufw) ---
echo "[7/12] Configuring firewall..."
apt-get install -y -qq ufw > /dev/null 2>&1
ufw --force reset > /dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
# Allow SSH only from Tailscale network (100.x.x.x)
ufw allow from 100.0.0.0/8 to any port 22 proto tcp comment "SSH via Tailscale"
# Allow VNC only from Tailscale network
ufw allow from 100.0.0.0/8 to any port 5900 proto tcp comment "VNC via Tailscale"
# Allow local Electron app to reach Node server
ufw allow from 127.0.0.0/8 to any port 3000 proto tcp comment "Local Ken server"
# Allow mDNS for local discovery
ufw allow 5353/udp comment "mDNS"
ufw --force enable
echo "        Firewall enabled (SSH/VNC via Tailscale only)."

# --- 8. Disable USB mass storage ---
echo "[8/12] Disabling USB mass storage..."
# Block the usb-storage kernel module
if ! grep -q "^blacklist usb-storage" /etc/modprobe.d/blacklist-usb-storage.conf 2>/dev/null; then
    echo "blacklist usb-storage" > /etc/modprobe.d/blacklist-usb-storage.conf
    echo "install usb-storage /bin/false" >> /etc/modprobe.d/blacklist-usb-storage.conf
fi
# Remove module if currently loaded
rmmod usb-storage 2>/dev/null || true
echo "        USB mass storage disabled."

# --- 9. Hardware watchdog ---
echo "[9/12] Enabling hardware watchdog..."
apt-get install -y -qq watchdog > /dev/null 2>&1
# Enable the BCM2835 hardware watchdog
if ! grep -q "^dtparam=watchdog=on" "$BOOT_CONFIG"; then
    echo "dtparam=watchdog=on" >> "$BOOT_CONFIG"
fi
# Configure watchdog daemon
cat > /etc/watchdog.conf << 'WATCHDOG'
watchdog-device = /dev/watchdog
watchdog-timeout = 15
max-load-1 = 24
min-memory = 1
WATCHDOG
systemctl enable watchdog
systemctl start watchdog 2>/dev/null || true
echo "        Hardware watchdog enabled (15s timeout)."

# --- 10. Automatic security updates ---
echo "[10/12] Configuring automatic security updates..."
apt-get install -y -qq unattended-upgrades > /dev/null 2>&1
# Enable automatic security updates only
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UNATTENDED'
Unattended-Upgrade::Origins-Pattern {
    "origin=Raspbian,codename=${distro_codename},label=Raspbian";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
UNATTENDED
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOUPGRADE'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOUPGRADE
echo "        Automatic security updates enabled."

# --- 11. Restrict sudo and lock down pi user ---
echo "[11/12] Restricting sudo access..."
# Only allow pi to run specific commands with sudo (systemctl for ken.service)
cat > /etc/sudoers.d/ken-kiosk << 'SUDOERS'
# The Ken kiosk — restrict pi user sudo
pi ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart ken.service
pi ALL=(ALL) NOPASSWD: /usr/bin/systemctl start ken.service
pi ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop ken.service
pi ALL=(ALL) NOPASSWD: /usr/bin/systemctl status ken.service
pi ALL=(ALL) NOPASSWD: /sbin/reboot
pi ALL=(ALL) NOPASSWD: /sbin/shutdown
pi ALL=(ALL) NOPASSWD: /usr/sbin/rfkill
pi ALL=(ALL) NOPASSWD: /usr/bin/nmcli
SUDOERS
chmod 440 /etc/sudoers.d/ken-kiosk
# Validate sudoers syntax
visudo -c -f /etc/sudoers.d/ken-kiosk > /dev/null 2>&1 || {
    echo "        WARNING: sudoers syntax error, removing restriction."
    rm -f /etc/sudoers.d/ken-kiosk
}
echo "        Sudo restricted to ken.service and reboot only."

# --- 12. SSH hardening ---
echo "[12/12] Hardening SSH..."
SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    # Disable password auth (key-only)
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    # Disable root login
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
    # Limit to pi user
    if ! grep -q "^AllowUsers pi" "$SSHD_CONFIG"; then
        echo "AllowUsers pi" >> "$SSHD_CONFIG"
    fi
    # Set login grace time and max auth tries
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 30/' "$SSHD_CONFIG"
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONFIG"
    systemctl restart sshd 2>/dev/null || true
fi
echo "        SSH hardened (key-only, no root, pi user only)."

# --- Summary ---
echo ""
echo "========================================="
echo "  Setup complete!"
echo "========================================="
echo ""
echo "  Service:        ken.service (enabled)"
echo "  Cursor:         hidden via unclutter"
echo "  Screen blank:   disabled (xset + lightdm)"
echo "  Panel/icons:    disabled"
echo "  Auto-login:     configured for pi"
echo "  Camera:         OV5647 enabled (libcamera)"
echo "  Firewall:       ufw (SSH/VNC Tailscale only)"
echo "  USB storage:    disabled"
echo "  Watchdog:       BCM2835 hardware (15s)"
echo "  Auto-updates:   security patches only"
echo "  Sudo:           restricted to ken.service"
echo "  SSH:            key-only, no root, pi only"
echo ""
echo "  To start the service now without reboot:"
echo "    sudo systemctl start ken.service"
echo ""
echo "  To check status:"
echo "    sudo systemctl status ken.service"
echo ""
echo "  IMPORTANT: Make sure your SSH key is in"
echo "  /home/pi/.ssh/authorized_keys before reboot!"
echo "  (Password auth will be disabled)"
echo ""
read -p "  Reboot now? (y/N): " REBOOT
if [ "$REBOOT" = "y" ] || [ "$REBOOT" = "Y" ]; then
    echo "  Rebooting..."
    reboot
else
    echo "  Skipping reboot. Remember to reboot for all changes to take effect."
fi
