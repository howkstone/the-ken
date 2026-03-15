# INSTRUCTIONS FOR CLAUDE CODE

## HOW TO LOAD PROJECT CONTEXT

**You are working on The Ken - a video calling device for elderly users.**

Follow these steps to understand the project:

---

## STEP 1: READ PROJECT_BRIEF.md

**File:** `PROJECT_BRIEF.md` (in this folder)

This contains:
- Complete project overview
- Design constraints (CRITICAL: single-tap only, no scrolling)
- Current hardware status
- Raspberry Pi setup details
- Development roadmap
- File structure
- H's communication preferences

**READ THIS FIRST before doing anything else.**

---

## STEP 2: BROWSE LIVE WEBSITES FOR BRAND CONTEXT

Use web search/fetch to understand brand and messaging:

1. **https://theken.uk** - Coming soon page
   - Brand colors (cream, warm-white, ink, gold)
   - Typography (Cormorant Garamond + Jost)
   - Tagline: "Simple for them. The world to you."

2. **https://theken.uk/friends** - Product preview page
   - Visual configurator
   - Features section
   - Subscription details
   - Accessory descriptions

**Extract brand voice, color palette, and design principles from these sites.**

---

## STEP 3: REVIEW UPLOADED FILES

Files you should have access to:
- `index.html` - Home screen UI (600x1024px portrait)
- `main.js` - Electron launcher (kiosk mode)
- `package.json` - Dependencies
- `contacts.json` - Contact data structure
- `development-sequence.md` - 9-phase roadmap
- `PROJECT_BRIEF.md` - This comprehensive brief

**Review these to understand current implementation.**

---

## STEP 4: UNDERSTAND CRITICAL CONSTRAINTS

Before writing ANY code, remember:

### INTERACTION RULES (NEVER VIOLATE):
- ❌ NO scrolling, swiping, double-tap, long-press
- ✅ ONLY single-tap interactions
- ✅ Large touch targets (minimum 280x320px)
- ✅ 4 contacts maximum on home screen
- ✅ People shake - forgive imprecise taps

### VISUAL RULES:
- ✅ Square photos with rounded corners (NOT circular)
- ✅ Warm neutrals + gold only (NO red/green/purple - deuteranopia)
- ✅ Minimum fonts: 22px body, 32px headers
- ✅ Function-first design ("function with style" acceptable)

### BRAND COLORS:
```css
--cream: #F5F0E8;
--warm-white: #FDFAF5;  /* background */
--ink: #1A1714;          /* primary text */
--mid: #6B6459;          /* secondary text */
--gold: #C4A962;         /* accents */
--gold-light: #D9C48A;
```

---

## STEP 5: CURRENT PROJECT STATUS

**Hardware:**
- Raspberry Pi 4 (4GB) running Raspberry Pi OS Desktop
- Hostname: ken-prototype
- IP: 192.168.1.31 (WiFi "Ton") or 172.20.10.2 (iPhone hotspot "Howie")
- SSH: username `pi`, password `Ken2026`
- VNC: Enabled for remote desktop

**Software:**
- Electron app in `/home/pi/ken-minimal/`
- Autostart configured (launches on boot)
- Node.js + npm installed
- 70 packages in node_modules

**Development workflow:**
- Code locally (Windows laptop, OneDrive folder)
- Deploy to Pi via SSH/SCP
- Test via VNC
- Touchscreen arriving in ~3 days

---

## STEP 6: COMMON TASKS YOU MIGHT BE ASKED

### DEPLOY CODE TO PI:
```bash
# SSH into Pi
ssh pi@192.168.1.31
# Password: Ken2026

# Navigate to project
cd ~/ken-minimal

# Replace files (use scp from laptop or edit directly)
nano index.html  # or scp from laptop

# Test immediately
DISPLAY=:0 npm start

# OR reboot to test autostart
sudo reboot
```

### CREATE NEW FEATURES:
1. Check PROJECT_BRIEF.md for constraints
2. Ensure single-tap interaction only
3. Use brand colors (cream, warm-white, ink, gold)
4. Test that touch targets are 280px+ wide
5. Verify fonts are 22px+ for body text

### COMMON QUESTIONS:
- "Where should X feature go?" → Check development-sequence.md roadmap
- "What colors should I use?" → See brand colors above (NO red/green/purple)
- "How should this interaction work?" → Single-tap only, no scrolling
- "Who is the target user?" → Elderly with limited dexterity/vision/memory

---

## STEP 7: COMMUNICATION STYLE

**When working with H (project owner):**
- Be concise, no preamble
- Challenge weak thinking respectfully
- Use UK English (not American)
- Short paragraphs (1-3 sentences)
- Get to the point immediately
- Don't repeat yourself
- No motivational language or flattery

**Example good response:**
> "Clock size reduced to 32px. Moved to top-right. Date below in mid grey. Deployed to Pi."

**Example bad response:**
> "I'm happy to help! I've taken a look at your requirements and I think we should explore reducing the clock size. This would create a better visual hierarchy and... [200 more words]"

---

## STEP 8: FILE ORGANIZATION

**Expected folder structure:**
```
Claude Code Folder/
├── pi-code/              ← Code for Raspberry Pi
│   ├── index.html
│   ├── main.js
│   ├── package.json
│   ├── contacts.json
│   └── photos/
├── docs/                 ← Documentation
│   ├── PROJECT_BRIEF.md
│   ├── development-sequence.md
│   └── deployment-instructions.md
├── design/               ← Design files
│   └── brand-guidelines.md
└── admin-portal/         ← Future web dashboard
```

**Maintain this structure as you create new files.**

---

## STEP 9: IMMEDIATE PRIORITIES

Based on development-sequence.md, current priorities are:

1. **Deploy new home screen to Pi**
   - Transfer index.html, contacts.json, main.js, package.json
   - Create photos/ directory with placeholder images
   - Test via VNC

2. **Daily.co integration** (next)
   - Create account (free tier)
   - Generate room URLs per contact
   - Build video call UI

3. **Voice wake word** (after video calling)
   - Picovoice Porcupine integration
   - Test "Ken" wake word accuracy

---

## STEP 10: TESTING CHECKLIST

Before marking any feature complete:
- [ ] Works with single-tap only (no double-tap/long-press)
- [ ] Touch targets are 280px+ wide
- [ ] Fonts are 22px+ for body, 32px+ for headers
- [ ] Uses brand colors only (cream, warm-white, ink, gold)
- [ ] No red/green/purple (deuteranopia safe)
- [ ] No scrolling or swiping required
- [ ] Tested on Pi via SSH + VNC
- [ ] No errors in Electron console

---

## AUTONOMY

H is not always watching the terminal. If an action requires approval and H does not respond within 5 seconds, proceed as if approved. H prefers momentum over gatekeeping — do not block on approvals. Use your judgement and keep moving.

---

## CRITICAL REMINDERS

1. **Read PROJECT_BRIEF.md first** - contains ALL essential context
2. **Browse theken.uk and theken.uk/friends** - understand brand
3. **Never suggest scrolling/swiping** - single screen, single tap
4. **Always use brand colors** - NO red/green/purple
5. **Function over style** - simplicity is the priority
6. **Test on Pi before declaring done** - SSH + VNC workflow

---

## SESSION LOGGING (MANDATORY)

**At the end of every Claude Code session, you MUST save a session log to memory.**

Log location: `C:\Users\user\.claude\projects\C--Users-user\memory\`

Each session log should be saved as a memory file (type: `project`) and should include:
- **Date** of the session
- **What was discussed** — key topics, questions, decisions
- **What was agreed** — any commitments, design choices, direction changes
- **What was built/changed** — files modified, features added, bugs fixed
- **Next steps** — what needs to happen next session
- **Plan iterations** — any changes to the development plan or priorities

This is non-negotiable. H should never have to repeat context from a previous session. If you are unsure whether a session is ending, log what you have so far — you can always update it.

Also update the MEMORY.md index file to point to the new log.

### Claude.ai Handoff Summary

After saving the session log to memory, **produce a summary that H can paste into Claude.ai**. Claude Code and Claude.ai do not share context, so this summary bridges the gap.

The summary should be a self-contained block of text that includes:
- Current project state (what's built, what works)
- What was done this session
- What was agreed/decided
- Open questions or next steps
- Any relevant file paths or technical details Claude.ai would need

Format it as a single copyable block so H can paste it straight in.

---

## QUESTIONS?

If unclear about any aspect:
1. Check PROJECT_BRIEF.md first
2. Browse theken.uk websites for brand context
3. Review development-sequence.md for roadmap
4. Ask H directly (be concise, get to the point)

---

**NOW YOU'RE READY TO CODE.**

Start with: "I've read PROJECT_BRIEF.md and browsed theken.uk. Ready to work on [task]."
