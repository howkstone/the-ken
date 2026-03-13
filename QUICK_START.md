# QUICK START - USING THESE FILES WITH CLAUDE CODE

## FILES YOU NOW HAVE:

**Core Pi code (deploy to Raspberry Pi):**
- `index.html` - Home screen UI
- `main.js` - Electron launcher
- `package.json` - Dependencies
- `contacts.json` - Contact data

**Documentation (for context):**
- `PROJECT_BRIEF.md` - Complete project overview (READ THIS FIRST)
- `development-sequence.md` - 9-phase roadmap
- `CLAUDE_CODE_INSTRUCTIONS.md` - How to bootstrap Claude Code
- `DEPLOYMENT_INSTRUCTIONS.md` - How to deploy to Pi

---

## SETUP IN 3 STEPS:

### 1. ORGANIZE FILES IN ONEDRIVE

Create this structure in:
`C:\Users\user\OneDrive\Documents\Big Brain Ltd\The Ken\Claude Code Folder\`

```
Claude Code Folder/
├── pi-code/
│   ├── index.html          ← From downloads
│   ├── main.js             ← From downloads
│   ├── package.json        ← From downloads
│   ├── contacts.json       ← From downloads
│   └── photos/             ← Create empty folder
│       (placeholder images will be added later)
├── docs/
│   ├── PROJECT_BRIEF.md          ← From downloads
│   ├── development-sequence.md   ← From downloads
│   └── DEPLOYMENT_INSTRUCTIONS.md ← From downloads (if you have it)
└── CLAUDE_CODE_INSTRUCTIONS.md   ← From downloads (root level)
```

---

### 2. OPEN IN CLAUDE CODE (TERMINAL OR DESKTOP)

**Option A: Terminal (if you fix PowerShell execution policy):**
```powershell
# Fix execution policy first:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then install Claude Code:
npm install -g @anthropic-ai/claude-code

# Navigate to project:
cd "C:\Users\user\OneDrive\Documents\Big Brain Ltd\The Ken\Claude Code Folder"

# Launch Claude Code:
claude
```

**Option B: Desktop app (easier):**
1. Open Claude Desktop app
2. Click "Code" tab
3. File → Open Folder
4. Navigate to: `C:\Users\user\OneDrive\Documents\Big Brain Ltd\The Ken\Claude Code Folder`

**Option C: Web browser:**
1. Go to https://claude.ai/code
2. Open folder or connect to GitHub (optional)

---

### 3. GIVE CLAUDE CODE THIS INITIAL PROMPT:

Copy-paste this into Claude Code:

```
I'm working on The Ken - a video calling device for elderly users.

First, read PROJECT_BRIEF.md (in this folder) - it contains all essential context.

Then, browse these websites for brand context:
- https://theken.uk (coming soon page)
- https://theken.uk/friends (product preview)

Finally, confirm you understand:
1. Design constraints (single-tap only, no scrolling/swiping)
2. Brand colors (cream, warm-white, ink, gold - NO red/green/purple)
3. Target user (elderly with limited dexterity/vision)
4. Current hardware (Raspberry Pi 4 at 192.168.1.31)

Once you've read PROJECT_BRIEF.md and browsed the websites, let me know you're ready to work.
```

**Claude Code will then:**
1. Read PROJECT_BRIEF.md
2. Browse theken.uk websites
3. Confirm understanding
4. Be ready to code with full context

---

## NEXT STEPS (ONCE CLAUDE CODE IS READY):

### Task 1: Deploy to Pi
```
SSH into my Pi at 192.168.1.31 (password: Ken2026) and deploy the files in pi-code/ folder to /home/pi/ken-minimal/. Create photos/ directory and download 4 placeholder images. Then reboot and verify it works via VNC.
```

### Task 2: Daily.co Integration
```
Create a Daily.co account (free tier), generate 4 test room URLs, update contacts.json with those URLs, and build the video call UI (full-screen iframe, End Call button overlay).
```

### Task 3: Voice Wake Word
```
Install Picovoice Porcupine on the Pi, test "Ken" wake word detection, and integrate with the home screen to trigger when user says "Ken".
```

---

## TROUBLESHOOTING:

**If Claude Code says "empty folder":**
- Make sure files are actually in the folder
- Try refreshing or reopening the folder
- Check OneDrive sync is complete

**If Claude Code doesn't have context:**
- Paste the initial prompt above
- Point it to PROJECT_BRIEF.md explicitly
- Tell it to browse theken.uk websites

**If PowerShell execution policy blocks npm:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then retry npm install.

**If you prefer staying in this chat:**
- That's fine - our current workflow works
- I can continue creating files as downloads
- You deploy to Pi via SSH manually
- No context loss, simpler workflow

---

## RECOMMENDED APPROACH:

**For now:** Stay in this chat (simpler, no context loss)

**Later:** Once project is more mature, migrate to Claude Code for:
- Faster iteration
- Autonomous deployment
- Multi-file editing
- Git integration

**Both approaches work - your call.**

---

## SUPPORT:

If Claude Code struggles with any task:
- Come back to this chat
- I have full context
- We can troubleshoot together
- Generate files as downloads if needed

**You're now set up to use either workflow.**
