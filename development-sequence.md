# THE KEN - DEVELOPMENT SEQUENCE

## DESIGN CONSTRAINTS (CRITICAL)

**Interaction model:**
- Single-tap only (no double-tap, long-press, swipe, scroll)
- Large touch targets (minimum 280x320px per tile)
- People shake - forgive imprecise taps
- Physical button only: 3 sec on/off, 10 sec reset
- Single tap on screen: sleep/wake
- Mic always listening for voice commands

**Screen:**
- 10.1" portrait (600x1024px effective)
- 4 contacts maximum on home screen
- No pagination, no "see more" - if you need >4 contacts, solve differently

**Visual:**
- Square photos with rounded corners + borders (not circles)
- Function-first aesthetic ("function with style")
- Brand colours: cream, warm-white, ink, mid grey, gold
- No blue/green (user has deuteranopia)

---

## PHASE 1: CORE INTERFACE (WEEKS 1-2)

### 1.1 Home Screen (HTML mock complete ✓)
- Small clock + date (top-right, not dominant)
- Phone icon (traditional handset, gold, centre)
- "Ask Ken who you'd like to call" prompt
- 4 contact tiles (2x2 grid, square photos with rounded corners)
- Live updating clock
- Single-tap to initiate call

**Files:**
- `index.html` - home screen UI ✓
- `main.js` - Electron launcher ✓
- `contacts.json` - contact data structure (next)

### 1.2 Contact Data Structure
```json
{
  "contacts": [
    {
      "id": "1",
      "name": "Sarah",
      "relationship": "Daughter",
      "photo": "/photos/sarah.jpg",
      "dailyRoomUrl": "https://theken.daily.co/sarah-mum",
      "phoneNumber": "+447700900123",
      "emergencyContact": true,
      "position": 1
    }
  ],
  "maxVisibleContacts": 4
}
```

**Storage:** SQLite database (encrypted at rest)

### 1.3 Contact Management UI (Admin Portal Only)
- Family adds/edits contacts via web dashboard
- Upload photos (auto-resize to 480x480px, compress to <100KB)
- Set emergency contact flag
- Reorder contacts (affects position on home screen)
- NO on-device contact editing for elderly user

---

## PHASE 2: VIDEO CALLING (WEEKS 2-4)

### 2.1 Daily.co Integration
**Account setup:**
- Create Daily.co account (free tier: 10,000 min/month)
- Generate unique room URL per contact
- Pre-create rooms during contact setup (admin portal)

**Call flow:**
1. User taps contact tile (single tap)
2. Screen shows "Calling Sarah..." (3 seconds)
3. Auto-connect to Daily.co room
4. Full-screen video (other person)
5. Small preview window (user, bottom-right, 150x200px)

**Call UI:**
- No buttons visible initially (clean full-screen video)
- Single tap anywhere on screen → reveals controls (5-second timeout)
- Controls: End Call (red, 200x80px), Mute (150x80px), Camera Off (150x80px)
- Large touch targets, gold borders
- End Call always works (even if Daily.co frozen)

### 2.2 Incoming Calls
**Auto-answer flow:**
1. Incoming call triggers full-screen caller photo
2. Ring tone (adjustable volume, default 70%)
3. Text overlay: "Sarah is calling..."
4. Countdown: "Answering in 5... 4... 3... 2... 1..."
5. Auto-answer (no button press)

**Reject option:**
- Single "Not now" button (bottom, 280x100px, mid grey)
- Tapping this sends call to voicemail
- Sends notification to family ("Mum rejected Sarah's call at 14:23")

**Implementation:**
- WebRTC signalling via Daily.co webhook
- Pi receives incoming call notification
- Electron app handles UI + auto-answer logic

### 2.3 Call Quality Optimisation
- Adaptive bitrate (Daily.co handles this)
- Audio priority over video (if bandwidth limited)
- Echo cancellation (browser native)
- Noise suppression (browser native)
- Test with 2Mbps+ connection (minimum requirement)

---

## PHASE 3: VOICE CONTROL (WEEKS 4-6)

### 3.1 Wake Word ("Hey Ken" or "Ken")
**Picovoice Porcupine:**
- Always listening (low power, <5% CPU)
- Custom wake word: "Ken" (simpler than "Hey Ken")
- Visual feedback: gold glow around screen edge (500ms pulse)
- Audio confirmation: gentle chime (250ms, 440Hz)

**Wake word triggers:**
- Screen wakes from sleep
- Listening mode active (15-second window)
- Gold microphone icon appears (top-centre)

### 3.2 Voice Commands (Google Cloud Speech-to-Text)
**Core commands:**
- "Call [contact name]" → initiates video call
- "What time is it?" → speaks current time
- "Go to sleep" → screen dims, mic stays on
- "Wake up" → screen wakes

**Future commands:**
- "Read my messages" → TTS for unread messages
- "Turn the light on/off" → toggles nightlight
- "Louder" / "Quieter" → adjusts volume

**Implementation:**
- Picovoice detects wake word (on-device)
- 15-second audio buffer sent to Google Cloud STT
- Response parsed for intent matching
- Action executed (call, time check, etc.)

**Fallback:**
- If Google Cloud unavailable: Vosk (offline STT, lower accuracy)
- If both fail: visual prompt "I didn't catch that, try tapping [contact name]"

### 3.3 Text-to-Speech (for responses)
- Browser native: `window.speechSynthesis`
- Voice: British English, female, moderate pace
- Volume: 80% default (adjustable via admin portal)

---

## PHASE 4: MESSAGING (WEEKS 6-8)

### 4.1 Signal Integration (FREE)
**Setup:**
- Signal CLI installed on Pi
- Device linked to Signal network (QR code, one-time setup)
- Pi acts as linked device (not primary phone)

**Receive-only mode:**
- Ken receives messages from family
- NO reply function (simplifies UX massively)
- Messages stored locally (encrypted SQLite)

**UI:**
- Home screen shows unread message count (gold badge on phone icon)
- Tapping phone icon with messages → switches to message list
- Message list: sender photo, name, timestamp, preview (first 80 chars)
- Tapping message → full-screen display (large text, 32px font)
- Voice button: TTS reads message aloud

**Message display screen:**
- Sender photo (top, 200x200px square)
- Sender name (below photo, 40px font)
- Timestamp ("2 minutes ago", 24px font, mid grey)
- Message text (32px font, ink, line-height 1.5)
- Voice button (bottom, 200x80px, "Read aloud")
- Back button (bottom-left, 100x80px, "Home")

### 4.2 WhatsApp Integration (OPTIONAL +£2/month)
**WhatsApp Business API:**
- Requires business account (£2/month for API access)
- Same UX as Signal (receive-only)
- Toggle enabled/disabled via admin portal
- Family manages subscription via Stripe

**Implementation:**
- WhatsApp Cloud API (Meta)
- Webhook receives messages
- Stored in same SQLite database as Signal
- Unified message list (no separate "WhatsApp" section)

### 4.3 Message Notifications
**Visual:**
- Badge on phone icon (gold circle with number)
- No pop-ups (user may be on call)

**Audio:**
- Gentle chime (if screen awake)
- No sound if screen asleep or on call

**Voice:**
- "Ken" wake word → "You have 3 new messages" → lists senders

---

## PHASE 5: ADMIN PORTAL (WEEKS 8-10)

### 5.1 Web Dashboard (React SPA)
**Hosting:**
- Netlify (free tier, custom domain: admin.theken.uk)
- Passwordless auth (magic link via email)
- Per-device login (one portal per Ken device)

**Dashboard sections:**
1. **Status:** Device online/offline, battery level, last seen
2. **Contacts:** Add/edit/delete, upload photos, reorder
3. **Call History:** Who called, when, duration, accepted/rejected
4. **Messages:** View messages sent to Ken (read-only)
5. **Settings:** Volume, brightness, auto-answer hours
6. **Subscription:** Manage billing (Stripe portal link)

### 5.2 Contact Management
**Add contact form:**
- Name (text input, max 20 chars)
- Relationship (dropdown: Daughter, Son, GP, Friend, etc.)
- Photo upload (resize to 480x480px, compress to <100KB)
- Phone number (optional, for emergency pendant)
- Emergency contact flag (checkbox)

**Photo requirements:**
- Minimum 200x200px
- Maximum 5MB upload size
- Auto-crop to square if landscape/portrait
- Stored on Cloudflare R2 (£0.015/GB/month)

### 5.3 Remote Settings
**Auto-answer schedule:**
- Default: 8am-10pm daily
- Family can set custom hours per day
- "Do not disturb" mode (all calls to voicemail)

**Volume presets:**
- Ring tone: 50-100% (default 70%)
- Call volume: 50-100% (default 80%)
- Message chime: 30-80% (default 50%)

**Brightness:**
- Manual: 30-100% (default 70%)
- Auto: KY-018 sensor adjusts (30-100% range)

### 5.4 Family Notifications (Email)
**Daily summary (8pm):**
- Calls made/received (count)
- Messages received (count)
- Device online time
- Battery level

**Alerts (immediate):**
- Device offline >6 hours
- Battery <15%
- Missed call (if user rejected)
- Emergency pendant pressed

---

## PHASE 6: HARDWARE INTEGRATION (WEEKS 10-12)

### 6.1 Touchscreen (Waveshare 10.1" - ARRIVING ~3 DAYS)
**Setup:**
- Install drivers (Waveshare provides .sh script)
- Calibrate touch (xinput_calibrator)
- Test all touch targets (280x320px minimum)
- Verify single-tap accuracy with shaky hand simulation

**Touch accuracy requirements:**
- 95%+ accuracy within tile boundary
- No accidental taps on adjacent tiles
- 20px dead zone between tiles

### 6.2 Light Sensor (KY-018)
**GPIO connection:**
- Data: GPIO 17
- VCC: 3.3V
- GND: Ground

**Auto-brightness logic:**
```python
import RPi.GPIO as GPIO
import time

def read_light_level():
    # Returns 0-1023 (10-bit ADC)
    count = 0
    GPIO.setup(17, GPIO.OUT)
    GPIO.output(17, GPIO.LOW)
    time.sleep(0.1)
    GPIO.setup(17, GPIO.IN)
    while GPIO.input(17) == GPIO.LOW:
        count += 1
    return count

def calculate_brightness(light_level):
    # Map 0-1023 → 30-100% brightness
    brightness = 30 + (light_level / 1023) * 70
    return int(brightness)
```

**Nightlight mode:**
- After 9pm: dim to 20% (override auto-brightness)
- Before 7am: dim to 20%
- Manual override via "Ken, turn the light up" voice command

### 6.3 Physical Buttons (Chassis-mounted)
**Top button (power):**
- Press 1x: sleep/wake (same as screen tap)
- Hold 3 sec: power off (shutdown -h now)
- Hold 10 sec: factory reset (wipe data, reload OS)

**Side button (volume rocker - OPTIONAL):**
- Up: increase volume 10%
- Down: decrease volume 10%
- Works even if software frozen (hardware PWM)

**Reset pinhole (back panel):**
- Requires paperclip
- Immediate reboot (same as `sudo reboot`)
- Used by support team only

---

## PHASE 7: SECURITY (WEEKS 12-14)

### 7.1 OS Hardening
**Remove unnecessary packages:**
```bash
sudo apt-get remove --purge libreoffice* scratch* minecraft-pi
sudo apt-get autoremove
sudo apt-get autoclean
```

**Disable unused services:**
```bash
sudo systemctl disable bluetooth.service
sudo systemctl disable avahi-daemon.service
sudo systemctl disable cups.service
```

**SSH/VNC in production:**
- Disabled by default
- Enabled via physical button combo: Hold Reset + Power for 5 sec
- Auto-disables after 15 minutes
- Visual indicator: red LED on back panel

### 7.2 Data Encryption
**Encrypt SQLite database:**
```python
import sqlite3
from cryptography.fernet import Fernet

# Generate key (store in /boot/ken-secret.key)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt data before storing
encrypted_data = cipher.encrypt(b"Contact data...")
```

**Encrypt WiFi credentials:**
- WPA2 passphrase encrypted at rest
- Key stored in separate partition (/boot)
- Not accessible via SSH even if enabled

### 7.3 Firewall Rules (ufw)
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.0.0/16 to any port 22  # SSH (local network only)
sudo ufw allow from 192.168.0.0/16 to any port 5900  # VNC (local network only)
sudo ufw enable
```

**Whitelist domains (outbound only):**
- daily.co (video calling)
- signal.org (messaging)
- theken.uk (admin portal API)
- anthropic.com (future AI features)

### 7.4 Remote Support Access
**TeamViewer-style access:**
- Family initiates via admin portal
- Generates 6-digit PIN (displayed on Ken's screen)
- Family enters PIN in portal
- 15-minute time limit
- Full screen-share + control
- Visual indicator: "Remote support active" (gold banner)

**Implementation:**
- VNC server (temporarily enabled)
- Unique password per session
- Auto-disable after 15 min

---

## PHASE 8: SUBSCRIPTION & PROVISIONING (WEEKS 14-16)

### 8.1 Subscription Backend (Stripe)
**Pricing:**
- Base device: £275 (one-time)
- Subscription: £4.99/month or £49/year (17% discount)
- WhatsApp add-on: +£2/month

**Stripe products:**
- `prod_ken_base_subscription` (£4.99/month)
- `prod_ken_annual_subscription` (£49/year)
- `prod_ken_whatsapp_addon` (£2/month)

**Features unlocked by subscription:**
- Video voicemail (3 months storage, 100MB max)
- Call history export (CSV download)
- Premium support (phone line for family)
- WhatsApp integration (if addon enabled)

**Grace period:**
- 7 days if payment fails
- Visual warning on Ken's screen: "Subscription expired - call [family]"
- Video calling still works (critical safety feature)
- Messages disabled until payment resumes

### 8.2 Device Provisioning
**Factory setup script:**
```bash
#!/bin/bash
# /home/pi/factory-reset.sh

# Generate unique device ID (MAC address)
DEVICE_ID=$(cat /sys/class/net/wlan0/address | tr -d ':')

# Create device record in database
curl -X POST https://api.theken.uk/devices \
  -H "Content-Type: application/json" \
  -d "{\"deviceId\": \"$DEVICE_ID\", \"status\": \"provisioned\"}"

# Generate activation QR code
qrencode -o /boot/activation-qr.png "https://admin.theken.uk/activate/$DEVICE_ID"

echo "Device provisioned: $DEVICE_ID"
```

**Activation flow (family):**
1. Scan QR code on box
2. Lands on admin.theken.uk/activate/DEVICE_ID
3. Creates account (email + password)
4. Enters Stripe payment (£4.99/month subscription)
5. Device auto-connects to account
6. Family adds first contact (themselves)

### 8.3 Video Voicemail (Daily.co Recording API)
**When user rejects call:**
1. Daily.co call redirected to recording room
2. Caller sees "Leave a video message" prompt
3. 60-second max recording
4. Stored on Daily.co servers (3 months)
5. Notification sent to Ken: "Sarah left you a message"

**Playback UI:**
- Message list shows "Video message" badge
- Tapping plays full-screen video
- No pause/rewind (simplifies UX)
- Automatically deletes after 3 months (storage limit)

---

## PHASE 9: WIFI SETUP (WEEKS 16-17)

### 9.1 First-Boot Setup Wizard
**Hotspot mode:**
```bash
# /home/pi/create-hotspot.sh
sudo nmcli dev wifi hotspot ssid "Ken-Setup-$DEVICE_ID" password "Ken2026"
```

**Web interface (captive portal):**
- Pi broadcasts WiFi: "Ken-Setup-ABCD1234"
- Family connects phone to hotspot
- Auto-redirects to http://192.168.4.1
- Shows WiFi network list (scan via `nmcli dev wifi list`)
- Family selects home WiFi + enters password
- Ken connects, hotspot shuts down

**Implementation:**
- Lightweight HTTP server (Python Flask)
- QR code option (scan WiFi credentials from router)
- Falls back to manual entry if QR fails

### 9.2 WiFi Change UI (On-Device)
**Hidden settings menu:**
- Triple-tap Ken logo (top-centre) → reveals Settings button
- Settings screen: WiFi, Volume, Brightness, Factory Reset
- Current WiFi network displayed
- "Change Network" button → rescans networks
- Select new network, enter password (on-screen keyboard)
- Large keys (80x80px minimum)

**On-screen keyboard:**
- QWERTY layout (not ABC - most familiar)
- Large keys (80x80px)
- Auto-capitalise first letter
- Show/hide password toggle
- "Connect" button (200x80px, gold)

---

## HARDWARE ADD-ONS (OPTIONAL ACCESSORIES)

### 1. Emergency Pendant (£20 retail)
**Specs:**
- Bluetooth Low Energy (BLE)
- Waterproof (IP67)
- CR2032 battery (1-year life)
- Red LED (flashes when pressed)
- Wearable (lanyard or wristband)

**Functionality:**
- Single press → triggers SOS call to first emergency contact
- Pi receives BLE signal
- Auto-dials emergency contact via Daily.co
- Sends notification to all family members: "EMERGENCY: Pendant pressed at 14:23"

**Implementation:**
```python
import bluetooth

def scan_for_pendant():
    devices = bluetooth.discover_devices(lookup_names=True)
    for addr, name in devices:
        if name == "Ken-Pendant":
            # Pendant found, listen for button press
            listen_for_emergency(addr)
```

### 2. Wall Mount (£15 retail)
**Specs:**
- Adjustable angle (0-45°)
- VESA-compatible (75x75mm)
- Cable management clips
- Tool-free installation (adhesive + screws)

**Use case:**
- Kitchen wall (always visible)
- Bedroom (bedside calls)
- Care home (communal area)

### 3. Wireless Keyboard & Mouse (£15 retail)
**Specs:**
- Large keys (20mm)
- High-contrast labels (black on white)
- USB dongle (plug into Pi)
- AAA batteries (6-month life)

**Use case:**
- Admin access (family editing settings on Ken directly)
- Backup if touchscreen fails
- Not for elderly user (too complex)

### 4. Protective Case (£30 retail)
**Specs:**
- Waterproof (IP65)
- Drop-resistant (1.5m)
- Carry handles
- Transparent front (touchscreen still usable)

**Use case:**
- Transport (visits to family)
- Outdoor use (garden calls)
- Care home (prevents damage)

---

## IMMEDIATE PRIORITIES (NEXT 7 DAYS)

1. **Test touchscreen when it arrives** (~3 days)
   - Install drivers
   - Calibrate touch
   - Deploy ken-minimal code
   - Test all touch targets

2. **Build contact data structure**
   - Create contacts.json schema
   - Load 4 dummy contacts
   - Display on home screen

3. **Daily.co account setup**
   - Create free account
   - Generate test room URL
   - Test video call from laptop → Pi

4. **Admin portal wireframe**
   - Sketch contact management UI
   - Plan authentication flow
   - Define API endpoints

5. **Voice wake word test**
   - Install Picovoice Porcupine
   - Test "Ken" wake word accuracy
   - Measure CPU usage (<5% target)

---

## COST IMPLICATIONS (UPDATED BOM)

| Component | Cost |
|-----------|------|
| Raspberry Pi 4 (4GB) | £85.00 |
| **10.1" Touchscreen (ordered)** | £67.00 |
| 16GB SD Card | £3.50 |
| Camera (720p) | £6.59 |
| Microphone (USB) | £5.29 |
| Speakers (stereo) | £10.00 |
| KY-018 Light Sensor | £1.50 |
| Bluetooth Remote | £6.08 |
| Housing (charcoal) | £12.00 |
| Power Supply (USB-C) | £7.60 |
| Assembly | £15.00 |
| **TOTAL BOM** | **£219.56** |

**RRP:** £275 | **Margin:** £55.44 (20.2%)

**Margin warning:** Below 25% target. Options:
- Increase RRP to £299 (+£24 margin = 27.4%)
- Reduce component costs (cheaper speakers, housing)
- Accept lower margin for market entry

---

## RISKS & MITIGATIONS

**Risk 1: Touch accuracy with shaky hands**
- Mitigation: 20px dead zone between tiles, forgive imprecise taps
- Test with elderly users (Phil's parents)

**Risk 2: WiFi setup too complex**
- Mitigation: QR code option, family does setup remotely via hotspot
- Video tutorial (embed in admin portal)

**Risk 3: Voice recognition accuracy**
- Mitigation: Fall back to visual prompts if STT fails
- Train on British accents (elderly voice samples)

**Risk 4: Daily.co free tier limit (10,000 min/month)**
- Mitigation: Monitor usage, upgrade to paid tier (£39/month) at 50 devices
- 10,000 min = 166 hours = 3.3 hours/device/month (adequate for testing)

**Risk 5: Subscription churn**
- Mitigation: 7-day grace period, premium features justify cost
- Annual discount (17% off) encourages commitment

---

## SUCCESS METRICS (MVP)

**Technical:**
- 95%+ call success rate (connection established)
- <3 second call initiation (tap to video)
- <5% CPU usage (wake word detection)
- 99%+ uptime (device online)

**User experience:**
- <1 rejected call per week (high auto-answer acceptance)
- >3 calls per week per device (regular usage)
- <10% support tickets (low confusion)

**Business:**
- 25%+ gross margin (target)
- <5% monthly churn (subscription retention)
- 4.5+ star rating (family feedback)

---

## NOTES

- **No scrolling/swiping:** Applies to ALL screens, not just home screen
- **4 contact limit:** If user needs >4, solve via voice ("Call Michael") or admin portal priority system
- **Single-tap only:** Even in settings, message list, call controls
- **Physical buttons:** Only for critical functions (power, reset)
- **Mic always on:** Privacy concern - address in marketing ("mutes during calls, never records")
- **Deuteranopia:** User has this, no red/green/purple in any UI
