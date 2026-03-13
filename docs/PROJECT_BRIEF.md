# THE KEN - PROJECT BRIEF FOR CLAUDE CODE

## CRITICAL CONTEXT: READ THIS FIRST

You are working on **The Ken** - a voice-first, simplified video calling device for elderly users and those with limited dexterity, vision, or short-term memory. This document contains everything you need to understand the project, make decisions, and write code that aligns with our design principles.

**Primary buyer:** Adult children purchasing for elderly parents  
**Emotional hook:** Peace of mind and staying connected  
**Core philosophy:** Function-first design, extreme simplicity, single-tap interaction only

---

## PROJECT OWNER: H

**Background:**
- 155 IQ, turnaround CFO
- 90+ CAGR across 7 entities
- Has deuteranopia (red/green color blindness)
- Prefers concise, direct communication
- Values function over style ("function with style" acceptable)

**Team (reference only when directly relevant):**
- Phil (journalist, brother)
- Hannah (ex-colleague, product development & factory relationships)
- Pierce (nurse, care experience)

**Company:** Big Brain Company  
**Website:** theken.uk (Netlify hosted)  
**Email:** team@theken.uk, howard@bigbraincompany.co.uk (Google Workspace)

---

## CURRENT HARDWARE & COSTS

**Confirmed hardware:**
- Raspberry Pi 4 (4GB) - £85.00
- Waveshare 10.1" IPS Resistive Touchscreen - £67.00 (ORDERED, arriving ~3 days)
- 16GB SD Card - £3.50
- 720p Camera - £6.59
- USB Microphone - £5.29
- Stereo Speakers - £10.00
- KY-018 Light Sensor - £1.50
- Bluetooth Remote - £6.08
- Housing (charcoal) - £12.00
- USB-C Power Supply - £7.60
- Assembly - £15.00

**TOTAL BOM:** £219.56  
**RRP:** £275  
**MARGIN:** £55.44 (20.2%) - below 25% target, consider £299 RRP

**Subscription:** £4.99/month or £49/year

---

## RASPBERRY PI SETUP (CURRENT STATE)

**Hardware:** Raspberry Pi 4 (4GB)  
**OS:** Raspberry Pi OS Desktop (64-bit, Debian Trixie)  
**Hostname:** ken-prototype  
**Credentials:** username `pi`, password `Ken2026`  
**Home WiFi:** "Ton" (192.168.1.31)  
**Fallback WiFi:** "Howie" (iPhone hotspot, 172.20.10.2)

**Current software stack:**
- Location: `/home/pi/ken-minimal/`
- Electron ^28.0.0 running full-screen kiosk mode
- Autostart configured via `~/.config/autostart/ken.desktop`
- VNC enabled for headless development
- SSH enabled (local network only)

**Development workflow:**
- Code on laptop, deploy to Pi via SSH/SCP
- View/test via VNC (192.168.1.31 or 172.20.10.2)
- Touchscreen arrives in ~3 days for physical testing

---

## DESIGN CONSTRAINTS (CRITICAL - NEVER VIOLATE)

### INTERACTION MODEL (ABSOLUTE RULES):
- **Single-tap ONLY** - no double-tap, long-press, swipe, scroll, pagination
- **Large touch targets** - minimum 280x320px per tile
- **People shake** - forgive imprecise taps, 20px dead zones between tiles
- **4 contacts maximum** on home screen - if more needed, solve differently (voice commands)
- **Physical buttons only for critical functions:**
  - Top button: 1x tap = sleep/wake, 3 sec hold = power off, 10 sec hold = factory reset
  - Single tap on screen = sleep/wake
  - Mic always listening for voice commands

### VISUAL DESIGN (BRAND COLORS):
```css
--cream: #F5F0E8;
--warm-white: #FDFAF5;  /* background, H has deuteranopia */
--ink: #1A1714;          /* primary text */
--mid: #6B6459;          /* secondary text */
--gold: #C4A962;         /* accents, highlights */
--gold-light: #D9C48A;
```

**NEVER use:**
- Red/green/purple (deuteranopia conflict)
- Blue/green combinations
- Circular profile photos (use square with rounded corners)
- "Stylish" design - prioritize function

**Typography:**
- Headings: Cormorant Garamond (serif, italic for emphasis)
- Body: Jost (sans-serif, 300-400 weight)
- Minimum font size: 22px for body, 32px for headers

### SCREEN SPECS:
- **Portrait orientation:** 600x1024px (10.1" touchscreen)
- **No scrolling, swiping, or pagination**
- **Single screen per function** - no multi-step wizards

---

## CURRENT HOME SCREEN DESIGN

**Layout (600x1024px portrait):**

```
┌─────────────────────────┐
│    Clock: 10:23    Date │  ← Top-right (60px height)
│                         │
│     [Phone Icon]        │  ← Gold, 140x140px
│                         │
│ "Ask Ken who you'd     │  ← Prompt (28px italic)
│  like to call"         │
│                         │
│  ┌─────┐  ┌─────┐      │  ← Contact tiles
│  │Sarah│  │ Dr  │      │    160x160px photos
│  │     │  │Wilson│     │    Square with rounded corners
│  └─────┘  └─────┘      │    3px cream border
│                         │
│  ┌─────┐  ┌─────┐      │
│  │Mike │  │Emma │      │
│  │     │  │     │      │
│  └─────┘  └─────┘      │
└─────────────────────────┘
```

**Key features:**
- Clock/date small and unobtrusive (elderly users have clocks)
- NO weather information
- Traditional phone icon (not smartphone)
- 4 contact tiles max
- Square photos with rounded corners + borders
- Contact names below photos (22px font)

---

## FILE STRUCTURE

**Current structure on Pi:**
```
/home/pi/ken-minimal/
├── index.html          ← Home screen UI
├── main.js             ← Electron launcher (kiosk mode)
├── package.json        ← Electron dependency
├── contacts.json       ← Contact data (dynamic loading)
├── photos/             ← Contact photos (160x160px min)
│   ├── sarah.jpg
│   ├── drwilson.jpg
│   ├── michael.jpg
│   └── emma.jpg
└── node_modules/       ← 70 packages installed
```

**Recommended local structure (laptop):**
```
C:\Users\user\OneDrive\Documents\Big Brain Ltd\The Ken\Claude Code Folder\
├── pi-code/            ← Code that deploys to Pi
│   ├── index.html
│   ├── main.js
│   ├── package.json
│   ├── contacts.json
│   └── photos/
├── docs/               ← Documentation
│   ├── development-sequence.md
│   ├── deployment-instructions.md
│   └── session-notes/
├── design/             ← Design files, mockups
│   └── brand-guidelines.md
└── admin-portal/       ← Future web dashboard (React)
```

---

## CONTACT DATA STRUCTURE

**contacts.json schema:**
```json
{
  "contacts": [
    {
      "id": "1",
      "name": "Sarah",
      "relationship": "Daughter",
      "photo": "./photos/sarah.jpg",
      "dailyRoomUrl": "",
      "phoneNumber": "+447700900001",
      "emergencyContact": true,
      "position": 1
    }
  ]
}
```

**Rules:**
- Maximum 4 contacts displayed on home screen
- Sorted by `position` field (ascending)
- Photos must be square, minimum 160x160px
- Emergency contacts get priority in SOS scenarios

---

## TECHNICAL ARCHITECTURE

### CORE STACK:
- **OS:** Raspberry Pi OS Desktop (64-bit)
- **Runtime:** Electron ^28.0.0 (Node.js wrapper for Chromium)
- **UI:** Vanilla HTML/CSS/JS (NO React - keep it simple)
- **Display:** Chromium in kiosk mode (--kiosk flag)
- **Video calling:** Daily.co (free tier: 10,000 min/month)
- **Messaging:** Signal (free) + optional WhatsApp (+£2/month)
- **Voice wake word:** Picovoice Porcupine ("Ken")
- **Speech-to-text:** Google Cloud (£300 free credit) or Vosk (offline fallback)
- **Text-to-speech:** Browser native `window.speechSynthesis`
- **Virtual number:** Vonage (£5-8/year)
- **Storage:** SQLite (encrypted at rest)

### ELECTRON LAUNCHER (main.js):
```javascript
const { app, BrowserWindow } = require('electron');

app.whenReady().then(() => {
  const win = new BrowserWindow({
    fullscreen: true,
    kiosk: true,
    backgroundColor: '#FDFAF5',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });
  
  win.loadFile('index.html');
  win.setMenuBarVisibility(false);
});
```

### AUTOSTART (via systemd or autostart file):
```
~/.config/autostart/ken.desktop:
[Desktop Entry]
Type=Application
Name=The Ken
Exec=/bin/bash -c 'cd /home/pi/ken-minimal && npm start'
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
```

---

## DEVELOPMENT ROADMAP (9 PHASES)

### PHASE 1: CORE INTERFACE (WEEKS 1-2) ✓ IN PROGRESS
- [x] Home screen HTML mock
- [x] Dynamic contact loading from JSON
- [ ] Contact photos (real images)
- [ ] Clock/date display
- [ ] Phone icon + prompt

### PHASE 2: VIDEO CALLING (WEEKS 2-4)
- [ ] Daily.co account setup
- [ ] Generate unique room URLs per contact
- [ ] Call initiation UI (single tap → "Calling Sarah...")
- [ ] Full-screen video interface
- [ ] End call button (always visible, 200x80px)
- [ ] Auto-answer incoming calls (5-second countdown)

### PHASE 3: VOICE CONTROL (WEEKS 4-6)
- [ ] Picovoice wake word ("Ken")
- [ ] Voice commands: "Call [name]", "What time is it?", "Go to sleep"
- [ ] Google Cloud STT integration
- [ ] Vosk offline fallback
- [ ] TTS for responses

### PHASE 4: MESSAGING (WEEKS 6-8)
- [ ] Signal CLI integration (receive-only)
- [ ] Message display UI (large text, TTS button)
- [ ] WhatsApp Business API (optional, +£2/month)
- [ ] Unread message badge on home screen

### PHASE 5: ADMIN PORTAL (WEEKS 8-10)
- [ ] React SPA (Netlify hosted)
- [ ] Passwordless auth (magic link)
- [ ] Contact management (add/edit/delete remotely)
- [ ] Call history view
- [ ] Settings (volume, brightness, auto-answer hours)
- [ ] Stripe subscription management

### PHASE 6: HARDWARE INTEGRATION (WEEKS 10-12)
- [ ] Waveshare touchscreen drivers
- [ ] Touch calibration
- [ ] KY-018 light sensor (auto-brightness)
- [ ] Nightlight mode (dim after 9pm)
- [ ] Physical button GPIO setup

### PHASE 7: SECURITY (WEEKS 12-14)
- [ ] Disable SSH/VNC in production
- [ ] Encrypt SQLite database
- [ ] Encrypt WiFi credentials
- [ ] Firewall rules (ufw)
- [ ] Remote support access (TeamViewer-style)

### PHASE 8: SUBSCRIPTION & PROVISIONING (WEEKS 14-16)
- [ ] Stripe integration
- [ ] Device activation flow (QR code on box)
- [ ] Video voicemail (Daily.co recording API)
- [ ] Subscription grace period (7 days)

### PHASE 9: WIFI SETUP (WEEKS 16-17)
- [ ] First-boot hotspot mode
- [ ] Captive portal for WiFi config
- [ ] On-device WiFi change UI (hidden settings)

---

## KEY DECISIONS & CONSTRAINTS

### INTERACTION RULES:
1. **No scrolling, swiping, double-tap, long-press** - EVER
2. **Single-tap only** for all touchscreen interactions
3. **4 contacts max** - if more needed, use voice ("Call Michael")
4. **No pagination** - single screen per function
5. **Large touch targets** - minimum 280x320px
6. **Forgive imprecise taps** - 20px dead zones between tiles

### VISUAL RULES:
1. **Square photos** with rounded corners (12px radius), 3px cream border
2. **No circular photos** - function over style
3. **Warm neutrals + gold only** - no red/green/purple/blue
4. **Minimum font sizes:** 22px body, 32px headers
5. **High contrast:** ink (#1A1714) on warm-white (#FDFAF5)

### TECHNICAL RULES:
1. **Edge-first processing** - minimize cloud dependency
2. **Offline-capable** - core functions work without internet
3. **Privacy-first** - no cloud storage of personal data
4. **Encrypted at rest** - SQLite database, WiFi credentials
5. **Auto-updates** - security patches only (no feature changes without consent)

### BUSINESS RULES:
1. **Base RRP:** £275 (consider £299 for better margin)
2. **Subscription:** £4.99/month or £49/year (17% discount)
3. **WhatsApp addon:** +£2/month (optional)
4. **Target margin:** 25%+ (currently 20.2%)
5. **Buyer persona:** Adult children, not elderly users themselves

---

## COMPETITOR ANALYSIS

**GrandPad (US, $79.99/month):**
- Pros: Proven market, simple UI
- Cons: Expensive subscription, US-only, locked ecosystem
- Our advantage: Lower cost, UK market, open platform

**Komp (Norway, €30/month):**
- Pros: Photo sharing focus, family engagement
- Cons: No video calling, expensive
- Our advantage: Video calling primary, lower price

**Amazon Echo Show:**
- Pros: Voice-first, cheap hardware
- Cons: Complex UI, privacy concerns, ad-driven
- Our advantage: Privacy-first, elderly-optimized UI

**Key differentiators:**
- Function-first design (not "smart home in disguise")
- Single-tap only (no complex gestures)
- UK market focus
- Affordable subscription (£4.99 vs £30-80/month)
- Privacy-first (no Amazon/Google ecosystem lock-in)

---

## WEBSITES FOR CONTEXT

**Primary site:** https://theken.uk  
- Coming soon page
- Brand colors and typography
- Tagline: "Simple for them. The world to you."
- Email capture form (Netlify forms)

**Preview page:** https://theken.uk/friends  
- Private preview for early access
- Product configurator (React)
- Features section
- Subscription details
- Accessory tiles

**Key messaging:**
- NOT about features - about peace of mind
- NOT "smart home" - simplified video calling device
- NOT condescending - "simple for them" not "simple for dummies"

---

## IMMEDIATE PRIORITIES (NEXT 7 DAYS)

1. **Deploy new home screen to Pi** (via SSH)
   - Replace current index.html
   - Add contacts.json
   - Download placeholder photos
   - Test via VNC

2. **Create Daily.co account**
   - Free tier (10,000 min/month)
   - Generate 4 test room URLs
   - Update contacts.json with room URLs

3. **Build video call UI**
   - Full-screen iframe for Daily.co
   - "End Call" button overlay
   - Auto-answer logic for incoming calls

4. **Test voice wake word**
   - Install Picovoice Porcupine
   - Test "Ken" wake word accuracy
   - Measure CPU usage (<5% target)

---

## COMMUNICATION PREFERENCES (H'S STYLE)

**Do:**
- Be concise, no preamble
- Challenge weak thinking respectfully
- Point out patterns when repeating behaviors
- Use UK English (not American)
- Short paragraphs (1-3 sentences max)
- Get to the point immediately

**Don't:**
- Use motivational language or flattery
- Repeat points (once is enough)
- Use FULL CAPS unless necessary
- Use em dashes (—) - use regular dashes
- Explain obvious things
- Over-literalism - understand context
- Dwelling on what won't work

**Writing style:**
- Sharp, human, not robotic
- Use contractions naturally (don't, can't, won't)
- Numbers as digits
- Direct and precise
- No banned AI phrases ("delve", "dive into", "harness", "unlock", etc.)

---

## COMMON PITFALLS TO AVOID

1. **Don't suggest circular profile photos** - square with rounded corners only
2. **Don't add scrolling/swiping** - single screen, single tap only
3. **Don't use red/green/purple** - H has deuteranopia
4. **Don't over-complicate** - function first, style second
5. **Don't suggest "smart home" features** - this is a video calling device
6. **Don't use marketing-speak** - direct, honest communication
7. **Don't create multi-step wizards** - single screen per function
8. **Don't assume elderly = incompetent** - respectful, empowering language

---

## DEPLOYMENT WORKFLOW

**Current process:**
1. Code on laptop (Windows, OneDrive)
2. Transfer to Pi via SSH/SCP:
   ```bash
   scp file.html pi@192.168.1.31:/home/pi/ken-minimal/
   ```
3. SSH into Pi to test:
   ```bash
   ssh pi@192.168.1.31
   cd ~/ken-minimal
   npm start  # or sudo reboot to test autostart
   ```
4. View via VNC: 192.168.1.31 (or 172.20.10.2 on iPhone hotspot)

**Testing checklist:**
- [ ] Clock updates every second
- [ ] Contact tiles visible and clickable
- [ ] Photos load (or show fallback if missing)
- [ ] Single-tap triggers console log
- [ ] No errors in DevTools (F12)
- [ ] Electron window full-screen
- [ ] Background color correct (#FDFAF5)

---

## QUESTIONS TO ASK BEFORE CODING

Before implementing any feature, consider:
1. **Is this single-tap?** If not, redesign.
2. **Can an 80-year-old with shaky hands use this?** If not, simplify.
3. **Does this require scrolling?** If yes, eliminate it.
4. **Is the text large enough?** Minimum 22px.
5. **Are the colors deuteranopia-safe?** No red/green/purple.
6. **Is this function-first?** Style is secondary.
7. **Does this align with "simple for them"?** Not condescending, actually simple.

---

## SUCCESS METRICS (MVP)

**Technical:**
- 95%+ call success rate
- <3 second call initiation
- <5% CPU for wake word detection
- 99%+ uptime

**User experience:**
- <1 rejected call per week
- >3 calls per week per device
- <10% support tickets

**Business:**
- 25%+ gross margin
- <5% monthly churn
- 4.5+ star rating

---

## FINAL NOTES

This is 90% H's project. Team members (Phil, Hannah, Pierce) exist but should only be referenced when directly relevant.

The primary buyer is adult children managing a parent's care, NOT the elderly user themselves. Marketing and UX should reflect this dual audience:
- **Elderly user:** Needs simple, large, forgiving interface
- **Buyer (adult child):** Needs peace of mind, remote management, reliability

Tagline candidates:
- "Simple for them. The world to you." (current favorite)
- "Simple for them. Irreplaceable to you." (alternative)

When in doubt:
1. Prioritize simplicity over features
2. Function over style
3. Privacy over convenience
4. Offline-capable over cloud-dependent

---

**END OF PROJECT BRIEF**

For questions about specific technical details, refer to:
- https://theken.uk (brand & messaging)
- https://theken.uk/friends (product preview)
- Development sequence document (in this project)
- Session notes (in docs/ folder)
