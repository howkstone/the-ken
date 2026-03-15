#!/bin/bash
# setup-kiosk.sh — Kiosk hardening for The Ken on Raspberry Pi 4
# Run as: sudo bash /home/pi/ken-minimal/setup-kiosk.sh

set -e

echo "========================================="
echo "  The Ken — Kiosk Setup"
echo "========================================="
echo ""

# --- 1. Install the systemd service ---
echo "[1/6] Installing ken.service..."
cp /home/pi/ken-minimal/ken.service /etc/systemd/system/ken.service
systemctl daemon-reload
systemctl enable ken.service
echo "       Service installed and enabled."

# --- 2. Hide the mouse cursor ---
echo "[2/6] Installing unclutter (hide cursor)..."
apt-get update -qq
apt-get install -y -qq unclutter > /dev/null 2>&1
# Add unclutter to LXDE autostart
LXDE_AUTOSTART="/etc/xdg/lxsession/LXDE-pi/autostart"
if [ -f "$LXDE_AUTOSTART" ]; then
    if ! grep -q "unclutter" "$LXDE_AUTOSTART"; then
        echo "@unclutter -idle 0.5 -root" >> "$LXDE_AUTOSTART"
        echo "       Added unclutter to LXDE autostart."
    else
        echo "       unclutter already in LXDE autostart."
    fi
else
    echo "       WARNING: $LXDE_AUTOSTART not found. You may need to add unclutter manually."
fi
echo "       Cursor hiding configured."

# --- 3. Disable screen blanking / screensaver ---
echo "[3/6] Disabling screen blanking and screensaver..."
# Disable via LXDE autostart
if [ -f "$LXDE_AUTOSTART" ]; then
    if ! grep -q "xset s off" "$LXDE_AUTOSTART"; then
        cat >> "$LXDE_AUTOSTART" << 'XSET'
@xset s off
@xset -dpms
@xset s noblank
XSET
        echo "       Added xset commands to LXDE autostart."
    else
        echo "       xset commands already present."
    fi
fi

# Also disable via lightdm config if available
LIGHTDM_CONF="/etc/lightdm/lightdm.conf"
if [ -f "$LIGHTDM_CONF" ]; then
    if ! grep -q "xserver-command=X -s 0 -dpms" "$LIGHTDM_CONF"; then
        sed -i '/^\[Seat:\*\]/a xserver-command=X -s 0 -dpms' "$LIGHTDM_CONF"
        echo "       Disabled DPMS in lightdm.conf."
    else
        echo "       lightdm DPMS already disabled."
    fi
fi
echo "       Screen blanking disabled."

# --- 4. Disable desktop panel and icons ---
echo "[4/6] Disabling desktop panel and icons..."
# Disable the lxpanel (taskbar) from autostart
if [ -f "$LXDE_AUTOSTART" ]; then
    sed -i 's/^@lxpanel/#@lxpanel/' "$LXDE_AUTOSTART"
    echo "       Commented out lxpanel in autostart."
fi

# Disable pcmanfm desktop icons
PCMANFM_DESKTOP_CONF="/home/pi/.config/pcmanfm/LXDE-pi/desktop-items-0.conf"
if [ -f "$PCMANFM_DESKTOP_CONF" ]; then
    sed -i 's/^show_documents=.*/show_documents=0/' "$PCMANFM_DESKTOP_CONF"
    sed -i 's/^show_trash=.*/show_trash=0/' "$PCMANFM_DESKTOP_CONF"
    sed -i 's/^show_mounts=.*/show_mounts=0/' "$PCMANFM_DESKTOP_CONF"
    echo "       Disabled desktop icons in pcmanfm."
else
    echo "       pcmanfm desktop config not found (may not be needed)."
fi

# Disable pcmanfm --desktop from autostart
if [ -f "$LXDE_AUTOSTART" ]; then
    sed -i 's/^@pcmanfm --desktop/#@pcmanfm --desktop/' "$LXDE_AUTOSTART"
    echo "       Commented out pcmanfm desktop in autostart."
fi
echo "       Panel and icons disabled."

# --- 5. Configure auto-login ---
echo "[5/6] Configuring auto-login for user pi..."
RASPI_CONF="/etc/lightdm/lightdm.conf"
if [ -f "$RASPI_CONF" ]; then
    if grep -q "^autologin-user=pi" "$RASPI_CONF"; then
        echo "       Auto-login already configured."
    else
        # Enable autologin under [Seat:*]
        sed -i '/^\[Seat:\*\]/a autologin-user=pi' "$RASPI_CONF" 2>/dev/null || true
        echo "       Auto-login set for user pi."
    fi
else
    echo "       WARNING: lightdm.conf not found. Use raspi-config to set auto-login."
fi

# Also try raspi-config non-interactive method
if command -v raspi-config > /dev/null 2>&1; then
    raspi-config nonint do_boot_behaviour B4 2>/dev/null || true
    echo "       raspi-config auto-login to desktop enabled."
fi

# --- 6. Summary ---
echo ""
echo "========================================="
echo "  Setup complete!"
echo "========================================="
echo ""
echo "  Service:        ken.service (enabled)"
echo "  Cursor:         hidden via unclutter"
echo "  Screen blank:   disabled"
echo "  Panel/icons:    disabled"
echo "  Auto-login:     configured for pi"
echo ""
echo "  To start the service now without reboot:"
echo "    sudo systemctl start ken.service"
echo ""
echo "  To check status:"
echo "    sudo systemctl status ken.service"
echo ""
read -p "  Reboot now? (y/N): " REBOOT
if [ "$REBOOT" = "y" ] || [ "$REBOOT" = "Y" ]; then
    echo "  Rebooting..."
    reboot
else
    echo "  Skipping reboot. Remember to reboot for all changes to take effect."
fi
