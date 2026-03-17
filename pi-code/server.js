const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = 3000;
const CONTACTS_FILE = path.join(__dirname, 'contacts.json');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');
const PHOTOS_DIR = path.join(__dirname, 'photos');
const DEVICE_ID_FILE = path.join(__dirname, '.device-id');
const CONFIG_FILE = path.join(__dirname, 'config.json');
function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
  catch { return {}; }
}
const config = loadConfig();
const CLOUD_API = config.cloudApi || 'https://ken-api.the-ken.workers.dev';
const DEVICE_KEY_FILE = path.join(__dirname, '.device-key');
let DEVICE_API_KEY = '';
try { DEVICE_API_KEY = fs.readFileSync(DEVICE_KEY_FILE, 'utf8').trim(); } catch {}

// Rolling screenshot buffer — keeps last 5 screen captures for feedback context
const screenshotBuffer = [];
const MAX_SCREENSHOTS = 5;

// Authenticated fetch wrapper: adds device API key to all cloud requests
function cloudFetch(url, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  if (typeof opts.headers.set === 'function') {
    // Headers object
    if (DEVICE_API_KEY) opts.headers.set('X-Ken-Device-Key', DEVICE_API_KEY);
  } else {
    // Plain object
    if (DEVICE_API_KEY) opts.headers['X-Ken-Device-Key'] = DEVICE_API_KEY;
    if (!opts.headers['Content-Type'] && opts.body) opts.headers['Content-Type'] = 'application/json';
  }
  return fetch(url, opts);
}

// Helper: build headers with device API key for authenticated cloud requests
function deviceHeaders(extra) {
  const headers = { 'Content-Type': 'application/json' };
  if (DEVICE_API_KEY) headers['X-Ken-Device-Key'] = DEVICE_API_KEY;
  return Object.assign(headers, extra || {});
}

// Log events to cloud audit trail (fire-and-forget)
function logToAudit(action, details) {
  if (!DEVICE_API_KEY) return; // Can't log without auth
  cloudFetch(`${CLOUD_API}/api/audit/${DEVICE_ID}/log`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, details: typeof details === 'string' ? { info: details } : details })
  }).catch(() => {}); // Silent fail — never block main flow
}

async function captureBlurredScreenshot(screenName) {
  try {
    const win = global.kenWindow;
    if (!win || win.isDestroyed()) return;

    // Inject CSS to blur message content before capture
    await win.webContents.executeJavaScript(`
      (function() {
        const style = document.createElement('style');
        style.id = 'ken-blur-overlay';
        style.textContent = '.msg-text, .msg-body, .thread-msg-text, .message-text, .msg-item-text, .vm-text, [class*="message"] .text-content { filter: blur(8px) !important; -webkit-filter: blur(8px) !important; }';
        document.head.appendChild(style);
      })();
    `);

    // Small delay for CSS to apply
    await new Promise(r => setTimeout(r, 100));

    // Capture
    const image = await win.webContents.capturePage();
    const resized = image.resize({ width: 480, quality: 'good' });
    const jpegBuffer = resized.toJPEG(60);
    const base64 = 'data:image/jpeg;base64,' + jpegBuffer.toString('base64');

    // Remove blur CSS
    await win.webContents.executeJavaScript(`
      (function() {
        const s = document.getElementById('ken-blur-overlay');
        if (s) s.remove();
      })();
    `);

    // Add to circular buffer
    screenshotBuffer.push({
      screen: screenName,
      timestamp: new Date().toISOString(),
      frame: base64
    });
    if (screenshotBuffer.length > MAX_SCREENSHOTS) {
      screenshotBuffer.shift();
    }
  } catch (err) {
    console.error('Rolling screenshot capture failed:', err.message);
  }
}

const POLL_INTERVAL = 60000;       // Contacts, messages: every 60s (was 15s)
const CALL_POLL_INTERVAL = 10000;  // Calls: every 10s (was 3s)
const CALLS_FILE = path.join(__dirname, 'calls.json');
const CALL_HISTORY_FILE = path.join(__dirname, 'call-history.json');
const REMINDERS_FILE = path.join(__dirname, 'reminders.json');
const VOICEMAILS_FILE = path.join(__dirname, 'voicemails.json');
const PHOTOS_CAROUSEL_DIR = path.join(__dirname, 'photos-carousel');
const SETTINGS_FILE = path.join(__dirname, 'settings.json');

if (!fs.existsSync(PHOTOS_CAROUSEL_DIR)) fs.mkdirSync(PHOTOS_CAROUSEL_DIR);

function readSettings() {
  try { return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); }
  catch { return {}; }
}
function writeSettings(data) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2));
}

// Call history tracking
function readCallHistory() {
  try { return JSON.parse(fs.readFileSync(CALL_HISTORY_FILE, 'utf8')); }
  catch { return { calls: [] }; }
}

function logCall(type, contactName, roomUrl, status) {
  logToAudit('Call ' + status, { type, contact: contactName });
  const history = readCallHistory();
  history.calls.push({
    id: crypto.randomUUID(),
    type, // 'outbound', 'inbound'
    contactName,
    roomUrl: roomUrl || '',
    status, // 'connected', 'missed', 'rejected'
    timestamp: new Date().toISOString()
  });
  // Keep last 100 calls
  if (history.calls.length > 100) history.calls = history.calls.slice(-100);
  fs.writeFileSync(CALL_HISTORY_FILE, JSON.stringify(history, null, 2));
  // Sync to cloud
  syncCallHistory();
}

async function syncCallHistory() {
  try {
    const history = readCallHistory();
    await cloudFetch(`${CLOUD_API}/api/history/${DEVICE_ID}/calls`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(history)
    });
  } catch {}
}

if (!fs.existsSync(PHOTOS_DIR)) fs.mkdirSync(PHOTOS_DIR);

function getDeviceId() {
  try {
    return fs.readFileSync(DEVICE_ID_FILE, 'utf8').trim();
  } catch {
    const id = crypto.randomUUID();
    fs.writeFileSync(DEVICE_ID_FILE, id);
    console.log('Generated device ID:', id);
    return id;
  }
}

const DEVICE_ID = getDeviceId();

function readContacts() {
  try { return JSON.parse(fs.readFileSync(CONTACTS_FILE, 'utf8')); }
  catch { return { contacts: [] }; }
}

function writeContacts(data) {
  fs.writeFileSync(CONTACTS_FILE, JSON.stringify(data, null, 2));
}

function readMessages() {
  try { return JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8')); }
  catch { return { messages: [] }; }
}

function writeMessages(data) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(data, null, 2));
}

async function createDailyRoom(name) {
  const roomName = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/create-room`, {
      method: 'POST',
      body: JSON.stringify({ roomName })
    });
    const data = await resp.json();
    return data.roomUrl || 'https://theken.daily.co/' + roomName;
  } catch {
    return 'https://theken.daily.co/' + roomName;
  }
}

// Poll Cloudflare for pending contacts
async function pollForContacts() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/contacts/${DEVICE_ID}/pending`);
    const data = await resp.json();
    if (!data.contacts || data.contacts.length === 0) return;

    console.log(`Found ${data.contacts.length} pending contact(s)`);
    const contacts = readContacts();

    for (const pending of data.contacts) {
      const nextId = String(Math.max(0, ...contacts.contacts.map(c => parseInt(c.id))) + 1);
      const nextPos = contacts.contacts.length + 1;

      let photoPath = '';
      if (pending.photo) {
        const base64Data = pending.photo.replace(/^data:image\/\w+;base64,/, '');
        const fileName = pending.name.toLowerCase().replace(/[^a-z0-9]/g, '') + '_' + Date.now() + '.jpg';
        fs.writeFileSync(path.join(PHOTOS_DIR, fileName), base64Data, 'base64');
        photoPath = './photos/' + fileName;
      }

      const dailyRoomUrl = await createDailyRoom(pending.name);

      contacts.contacts.push({
        id: nextId, name: pending.name, relationship: pending.relationship || '',
        photo: photoPath, dailyRoomUrl, phoneNumber: pending.phoneNumber || '',
        emergencyContact: false, position: nextPos
      });

      console.log(`Added contact: ${pending.name}`);
    }

    writeContacts(contacts);
    await cloudFetch(`${CLOUD_API}/api/contacts/${DEVICE_ID}/ack`, { method: 'POST' });
    syncContactsToCloud();
    console.log('Contacts synced and acknowledged');
  } catch (err) {
    // Silent fail — will retry next interval
  }
}

// Poll Cloudflare for pending messages
async function pollForMessages() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/messages/${DEVICE_ID}/pending`);
    const data = await resp.json();
    if (!data.messages || data.messages.length === 0) return;

    console.log(`Found ${data.messages.length} pending message(s)`);
    const store = readMessages();

    for (const msg of data.messages) {
      store.messages.push({
        id: msg.id,
        from: msg.from,
        text: msg.text,
        sentAt: msg.sentAt,
        read: false
      });
      console.log(`New message from ${msg.from}: ${msg.text.substring(0, 40)}...`);
    }

    // Keep last 50 messages
    if (store.messages.length > 50) {
      store.messages = store.messages.slice(-50);
    }

    writeMessages(store);
    await cloudFetch(`${CLOUD_API}/api/messages/${DEVICE_ID}/ack`, { method: 'POST' });
    console.log('Messages synced and acknowledged');
  } catch (err) {
    // Silent fail — will retry next interval
  }
}

// Sync contacts to cloud (so family portal can see them)
async function syncContactsToCloud() {
  try {
    const contacts = readContacts();
    // Send name, relationship, and position only (not photos or API keys)
    const safeContacts = (contacts.contacts || []).map(c => ({
      name: c.name, relationship: c.relationship || '', position: c.position,
      phoneNumber: c.phoneNumber || ''
    }));
    await cloudFetch(`${CLOUD_API}/api/contacts/${DEVICE_ID}/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contacts: safeContacts })
    });
  } catch {}
}

// Register device room with cloud on startup
let deviceRoomUrl = '';
async function ensureDeviceRoom() {
  const roomName = 'ken-' + DEVICE_ID.substring(0, 8);
  try {
    // Create room via Worker (holds the Daily API key securely)
    const resp = await cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/create-room`, {
      method: 'POST',
      body: JSON.stringify({ roomName })
    });
    const data = await resp.json();
    deviceRoomUrl = data.roomUrl || 'https://theken.daily.co/' + roomName;
    console.log('Device room URL:', deviceRoomUrl);
    // Register with cloud
    await cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/room`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ roomUrl: deviceRoomUrl })
    });
    console.log('Room registered with cloud');
  } catch (err) {
    console.error('Room setup failed:', err.message);
    logToAudit('Error', { message: 'Room setup failed: ' + err.message });
    deviceRoomUrl = 'https://theken.daily.co/' + roomName;
  }
}

// Track current incoming call
let currentIncomingCall = null;

// Poll for incoming calls (faster interval — 3s)
async function pollForCalls() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/pending`);
    const data = await resp.json();
    if (data.call && (!currentIncomingCall || currentIncomingCall.id !== data.call.id)) {
      currentIncomingCall = data.call;
      console.log(`Incoming call from ${data.call.from}`);
      logToAudit('Incoming call', { from: data.call.from });
      // Write to calls.json so the Electron frontend can pick it up
      fs.writeFileSync(CALLS_FILE, JSON.stringify(data.call, null, 2));
    }
  } catch {
    // Silent fail
  }
}

// Heartbeat — tell cloud we're online every 60s
async function sendHeartbeat() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/heartbeat/${DEVICE_ID}`, {
      method: 'POST',
      headers: deviceHeaders(),
    });
    const data = await resp.json();
    // Store device API key on first heartbeat (used for authenticated cloud requests)
    if (data.deviceKey && !DEVICE_API_KEY) {
      DEVICE_API_KEY = data.deviceKey;
      fs.writeFileSync(DEVICE_KEY_FILE, data.deviceKey);
      console.log('Device API key stored');
    }
  } catch {}
}

// Register device info with cloud
async function registerDeviceInfo() {
  try {
    // Read localStorage isn't possible from Node, so we expose an API for the frontend
    await cloudFetch(`${CLOUD_API}/api/device/${DEVICE_ID}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userName: 'The Ken', deviceId: DEVICE_ID })
    });
  } catch {}
}

// ===== PHOTOS CAROUSEL POLLING =====
function readReminders() {
  try { return JSON.parse(fs.readFileSync(REMINDERS_FILE, 'utf8')); }
  catch { return { reminders: [] }; }
}

function writeReminders(data) {
  fs.writeFileSync(REMINDERS_FILE, JSON.stringify(data, null, 2));
}

function readVoicemails() {
  try { return JSON.parse(fs.readFileSync(VOICEMAILS_FILE, 'utf8')); }
  catch { return { voicemails: [] }; }
}

function writeVoicemails(data) {
  fs.writeFileSync(VOICEMAILS_FILE, JSON.stringify(data, null, 2));
}

async function pollForPhotos() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/photos/${DEVICE_ID}`);
    const data = await resp.json();
    const photos = data.photos || [];

    // Read existing cached photo IDs
    const existingFiles = fs.readdirSync(PHOTOS_CAROUSEL_DIR);
    const existingIds = new Set(existingFiles.map(f => f.replace(/\.\w+$/, '')));

    // Remove photos that are no longer in cloud
    const cloudIds = new Set(photos.map(p => p.id));
    for (const file of existingFiles) {
      const fileId = file.replace(/\.\w+$/, '');
      if (!cloudIds.has(fileId)) {
        try { fs.unlinkSync(path.join(PHOTOS_CAROUSEL_DIR, file)); } catch {}
      }
    }

    // Download new photos
    for (const photo of photos) {
      if (!existingIds.has(photo.id) && photo.photo) {
        const base64Data = photo.photo.replace(/^data:image\/\w+;base64,/, '');
        const ext = photo.photo.startsWith('data:image/png') ? 'png' : 'jpg';
        fs.writeFileSync(path.join(PHOTOS_CAROUSEL_DIR, photo.id + '.' + ext), base64Data, 'base64');
      }
    }

    // Write metadata
    const meta = photos.map(p => ({
      id: p.id,
      caption: p.caption || '',
      uploadedAt: p.uploadedAt
    }));
    fs.writeFileSync(path.join(PHOTOS_CAROUSEL_DIR, '_meta.json'), JSON.stringify(meta, null, 2));
  } catch (err) {
    // Silent fail
  }
}

async function pollForReminders() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/reminders/${DEVICE_ID}`);
    const data = await resp.json();
    writeReminders({ reminders: data.reminders || [] });
  } catch {
    // Silent fail
  }
}

// Track which voicemails we've already notified about
let notifiedVoicemailIds = new Set();
let pendingVoicemailNotifications = [];

async function pollForVoicemails() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/voicemail/${DEVICE_ID}`);
    const data = await resp.json();
    const cloudVms = data.voicemails || [];
    const localData = readVoicemails();
    const localIds = new Set((localData.voicemails || []).map(v => v.id));

    // Find new voicemails (not yet on device)
    for (const vm of cloudVms) {
      if (!localIds.has(vm.id)) {
        // Mark as delivered in cloud
        try {
          await cloudFetch(`${CLOUD_API}/api/voicemail/${DEVICE_ID}/${vm.id}/delivered`, { method: 'POST' });
          console.log(`Voicemail delivered: ${vm.from} (${vm.type})`);
        } catch {}
      }
      // Queue notification for unplayed voicemails we haven't notified about
      if (!vm.played && !notifiedVoicemailIds.has(vm.id)) {
        notifiedVoicemailIds.add(vm.id);
        pendingVoicemailNotifications.push({
          id: vm.id,
          from: vm.from || 'Someone',
          type: vm.type || 'video',
          duration: vm.duration || 0,
          timestamp: vm.timestamp
        });
      }
    }

    writeVoicemails({ voicemails: cloudVms });
  } catch {
    // Silent fail
  }
}

// Poll cloud for settings changes (from portal)
async function pollForSettings() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/settings/${DEVICE_ID}`);
    const data = await resp.json();
    const current = readSettings();
    // Only write if something actually changed
    if (JSON.stringify(data) !== JSON.stringify(current)) {
      writeSettings(data);
      console.log('Settings updated from cloud');
    }
  } catch {}
}

// Check for queued settings changes (applied when device comes back online)
async function pollForSettingsQueue() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/settings/${DEVICE_ID}/queue`);
    const data = await resp.json();
    if (data.queue && data.queue.length > 0) {
      const settings = readSettings();
      for (const item of data.queue) {
        if (item.setting && item.value !== undefined) {
          settings[item.setting] = item.value;
          console.log(`Applied queued setting: ${item.setting} = ${item.value}`);
        }
      }
      writeSettings(settings);
      // Push merged settings back to cloud
      await cloudFetch(`${CLOUD_API}/api/settings/${DEVICE_ID}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });
      // ACK the queue
      await cloudFetch(`${CLOUD_API}/api/settings/${DEVICE_ID}/queue/ack`, { method: 'POST' });
      console.log(`Applied ${data.queue.length} queued settings`);
    }
  } catch {}
}

// Poll cloud for offline alert settings
async function pollForOfflineAlertSettings() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/settings/${DEVICE_ID}/offline-alerts`);
    const data = await resp.json();
    // Store locally so frontend can use it
    const settings = readSettings();
    settings.offlineAlerts = data;
    writeSettings(settings);
  } catch {}
}

// ===== SCREEN VIEWING (HQ Remote View) =====
let screenStreamingActive = false;
let screenStreamTimer = null;

async function pollScreenViewStatus() {
  try {
    const resp = await cloudFetch(`${CLOUD_API}/api/screen/${DEVICE_ID}/status`);
    const data = await resp.json();
    if (data.active && !screenStreamingActive) {
      console.log('HQ screen viewing requested by', data.requestedBy);
      startScreenStreaming();
    } else if (!data.active && screenStreamingActive) {
      console.log('HQ screen viewing stopped');
      stopScreenStreaming();
    }
  } catch {}
}

function startScreenStreaming() {
  screenStreamingActive = true;
  // Capture and upload a frame every 2 seconds
  screenStreamTimer = setInterval(captureAndUploadFrame, 2000);
  captureAndUploadFrame();
}

function stopScreenStreaming() {
  screenStreamingActive = false;
  if (screenStreamTimer) { clearInterval(screenStreamTimer); screenStreamTimer = null; }
}

async function captureAndUploadFrame() {
  if (!screenStreamingActive) return;
  try {
    const win = global.kenWindow;
    if (!win || win.isDestroyed()) return;
    const image = await win.webContents.capturePage();
    // Resize to reduce bandwidth (half size) and convert to JPEG
    const resized = image.resize({ width: 300, quality: 'good' });
    const jpegBuffer = resized.toJPEG(60);
    const base64 = 'data:image/jpeg;base64,' + jpegBuffer.toString('base64');
    await cloudFetch(`${CLOUD_API}/api/screen/${DEVICE_ID}/frame`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ frame: base64 }),
    });
  } catch (err) {
    console.error('Screen capture failed:', err.message);
    logToAudit('Error', { message: 'Screen capture failed: ' + err.message });
  }
}

// Start polling
setInterval(pollForContacts, POLL_INTERVAL);        // 60s
setInterval(pollForMessages, POLL_INTERVAL);        // 60s
setInterval(pollForCalls, CALL_POLL_INTERVAL);      // 10s
setInterval(sendHeartbeat, 300000);                 // 5 min (was 60s)
setInterval(pollForPhotos, 300000);                 // 5 min (was 60s)
setInterval(pollForReminders, 300000);              // 5 min (was 60s)
setInterval(pollForVoicemails, 120000);             // 2 min (was 30s)
setInterval(pollForSettings, 120000);               // 2 min (was 30s)
setInterval(pollForSettingsQueue, 300000);           // 5 min (was 60s)
setInterval(pollForOfflineAlertSettings, 300000);   // 5 min (was 60s)
setInterval(pollScreenViewStatus, 10000);           // 10s — check for HQ screen view requests
pollForContacts();
pollForMessages();
pollForPhotos();
pollForReminders();
pollForVoicemails();
pollForSettings();
pollForSettingsQueue();
sendHeartbeat();
ensureDeviceRoom();
syncContactsToCloud();

const server = http.createServer(async (req, res) => {
  // Restrict CORS to Electron app only (file:// sends 'null' origin)
  const origin = req.headers.origin || '';
  if (origin === 'null' || origin.startsWith('file://') || origin === 'http://localhost:3000') {
    res.setHeader('Access-Control-Allow-Origin', origin || 'null');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // Return device ID
  if (req.method === 'GET' && req.url === '/api/device-id') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ deviceId: DEVICE_ID, cloudUrl: CLOUD_API }));
    return;
  }

  // Return current settings (for Electron frontend)
  if (req.method === 'GET' && req.url === '/api/settings') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(readSettings()));
    return;
  }

  // Get pending voicemail notifications (Electron polls this when coming off idle)
  if (req.method === 'GET' && req.url === '/api/voicemails/notifications') {
    const notifications = pendingVoicemailNotifications.slice();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ notifications }));
    return;
  }

  // Dismiss a voicemail notification ("Later" pressed)
  if (req.method === 'POST' && req.url === '/api/voicemails/dismiss') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { id } = JSON.parse(body);
        pendingVoicemailNotifications = pendingVoicemailNotifications.filter(n => n.id !== id);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // Mark voicemail as watched (user played it)
  if (req.method === 'POST' && req.url === '/api/voicemails/watched') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { id } = JSON.parse(body);
        // Remove from pending notifications
        pendingVoicemailNotifications = pendingVoicemailNotifications.filter(n => n.id !== id);
        // Mark as played locally
        const data = readVoicemails();
        const vm = (data.voicemails || []).find(v => v.id === id);
        if (vm) {
          vm.played = true;
          vm.playedAt = new Date().toISOString();
          writeVoicemails(data);
        }
        // Notify cloud
        try {
          await cloudFetch(`${CLOUD_API}/api/voicemail/${DEVICE_ID}/${id}/watched`, { method: 'POST' });
        } catch {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // Get all voicemails (for contact card view)
  if (req.method === 'GET' && req.url === '/api/voicemails') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(readVoicemails()));
    return;
  }

  // Call history
  if (req.method === 'GET' && req.url === '/api/calls/history') {
    const history = readCallHistory();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(history));
    return;
  }

  // Log a call (from Electron frontend)
  if (req.method === 'POST' && req.url === '/api/calls/log') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { type, contactName, roomUrl, status } = JSON.parse(body);
        logCall(type, contactName, roomUrl || '', status || 'connected');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    });
    return;
  }

  // Screen brightness control (for nightlight mode)
  if (req.method === 'POST' && req.url === '/api/brightness') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { brightness } = JSON.parse(body);
        // Set backlight brightness on Pi (0-255)
        const val = Math.max(10, Math.min(255, Math.round(brightness * 2.55)));
        const blPath = '/sys/class/backlight/rpi_backlight/brightness';
        if (fs.existsSync(blPath)) {
          fs.writeFileSync(blPath, String(val));
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, brightness: val }));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    });
    return;
  }

  // Return messages (for Electron frontend)
  if (req.method === 'GET' && req.url === '/api/messages') {
    const store = readMessages();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(store));
    return;
  }

  // Return pending incoming call (for Electron frontend)
  if (req.method === 'GET' && req.url === '/api/calls/pending') {
    try {
      const callData = fs.existsSync(CALLS_FILE) ? JSON.parse(fs.readFileSync(CALLS_FILE, 'utf8')) : null;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ call: callData, roomUrl: deviceRoomUrl }));
    } catch {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ call: null, roomUrl: deviceRoomUrl }));
    }
    return;
  }

  // Acknowledge/clear the incoming call (with optional voicemail signal)
  if (req.method === 'POST' && (req.url === '/api/calls/ack' || req.url.startsWith('/api/calls/ack?'))) {
    const urlObj = new URL(req.url, 'http://localhost:3000');
    const sendVoicemail = urlObj.searchParams.get('voicemail') === 'true';
    currentIncomingCall = null;
    try { fs.unlinkSync(CALLS_FILE); } catch {}
    // Also clear cloud signal
    cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/ack`, { method: 'POST' }).catch(() => {});
    // If voicemail=true, also signal voicemail to cloud
    if (sendVoicemail) {
      cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/voicemail`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: '' })
      }).catch(() => {});
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Return device room URL
  if (req.method === 'GET' && req.url === '/api/calls/room') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ roomUrl: deviceRoomUrl }));
    return;
  }

  // Signal outbound call (Ken is calling someone — notify family portal)
  if (req.method === 'POST' && req.url === '/api/calls/outbound') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { contactName, roomUrl } = JSON.parse(body);
        logToAudit('Initiated call', { contact: contactName });
        await cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/outbound`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contactName, roomUrl })
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    });
    return;
  }

  // Clear outbound call signal (call ended)
  if (req.method === 'POST' && req.url === '/api/calls/outbound/clear') {
    logToAudit('Call ended', {});
    cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/outbound/clear`, { method: 'POST' }).catch(() => {});
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Update device info in cloud (called by Electron frontend)
  if (req.method === 'POST' && req.url === '/api/device/info') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const info = JSON.parse(body);
        await cloudFetch(`${CLOUD_API}/api/device/${DEVICE_ID}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(info)
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    });
    return;
  }

  // Mark message as read
  if (req.method === 'POST' && req.url.match(/^\/api\/messages\/[\w-]+\/read$/)) {
    const msgId = req.url.split('/')[3];
    const store = readMessages();
    const msg = store.messages.find(m => m.id === msgId);
    if (msg) {
      logToAudit('Viewed message', { from: msg.from, messageId: msgId });
      msg.read = true;
      writeMessages(store);
      // Notify cloud so portal shows ✓✓✓ Read (fire-and-forget)
      cloudFetch(`${CLOUD_API}/api/messages/${DEVICE_ID}/read`, {
        method: 'POST',
        headers: deviceHeaders(),
        body: JSON.stringify({ messageId: msgId })
      }).catch(() => {});
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Delete message (locally + mark as deleted-by-recipient in cloud)
  if (req.method === 'DELETE' && req.url.match(/^\/api\/messages\/[\w-]+$/)) {
    const msgId = req.url.split('/')[3];
    const store = readMessages();
    const before = store.messages.length;
    store.messages = store.messages.filter(m => m.id !== msgId);
    if (store.messages.length < before) writeMessages(store);
    // Mark as deleted-by-recipient in cloud (sender can still see it)
    cloudFetch(`${CLOUD_API}/api/messages/${DEVICE_ID}/${msgId}/delete`, {
      method: 'POST',
      headers: deviceHeaders(),
      body: JSON.stringify({ mode: 'for-me' })
    }).catch(() => {});
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Proxy: medication reminder response (frontend → cloud via server, no key exposed)
  if (req.method === 'POST' && req.url.match(/^\/api\/reminders\/[\w-]+\/response$/)) {
    const reminderId = req.url.split('/')[3];
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        await cloudFetch(`${CLOUD_API}/api/reminders/${DEVICE_ID}/${reminderId}/response`, {
          method: 'POST', body
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    });
    return;
  }

  // Proxy: emoji reaction (frontend → cloud via server, no key exposed)
  if (req.method === 'POST' && req.url.match(/^\/api\/messages\/[\w-]+\/react$/)) {
    const msgId = req.url.split('/')[3];
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        await cloudFetch(`${CLOUD_API}/api/messages/${DEVICE_ID}/${msgId}/react`, {
          method: 'POST', body
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    });
    return;
  }

  // Get medical info (proxy to cloud, with local cache)
  if (req.method === 'GET' && req.url === '/api/medical') {
    try {
      const resp = await cloudFetch(`${CLOUD_API}/api/medical/${DEVICE_ID}`);
      const data = await resp.json();
      // Cache locally
      fs.writeFileSync(path.join(__dirname, 'medical-cache.json'), JSON.stringify(data));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch {
      // Serve from cache
      try {
        const cached = fs.readFileSync(path.join(__dirname, 'medical-cache.json'), 'utf8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(cached);
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ gp: {}, medications: [], allergies: [], conditions: [], careNotes: '' }));
      }
    }
    return;
  }

  // Get emergency contacts (proxy to cloud, with local cache for offline)
  if (req.method === 'GET' && req.url === '/api/contacts/emergency') {
    try {
      const resp = await cloudFetch(`${CLOUD_API}/api/contacts/${DEVICE_ID}/emergency`);
      const data = await resp.json();
      fs.writeFileSync(path.join(__dirname, 'emergency-cache.json'), JSON.stringify(data));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch {
      try {
        const cached = fs.readFileSync(path.join(__dirname, 'emergency-cache.json'), 'utf8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(cached);
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ contacts: [] }));
      }
    }
    return;
  }

  // Serve add-contact form (local fallback)
  if (req.method === 'GET' && (req.url === '/' || req.url === '/add-contact')) {
    fs.readFile(path.join(__dirname, 'add-contact.html'), (err, data) => {
      if (err) { res.writeHead(500); res.end('Error'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  // Add new contact (local)
  if (req.method === 'POST' && req.url === '/api/contacts') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { name, relationship, phoneNumber, photo } = JSON.parse(body);
        if (!name) { res.writeHead(400); res.end(JSON.stringify({ error: 'Name required' })); return; }

        const contacts = readContacts();
        const nextId = String(Math.max(0, ...contacts.contacts.map(c => parseInt(c.id))) + 1);
        const nextPos = contacts.contacts.length + 1;

        let photoPath = '';
        if (photo) {
          const base64Data = photo.replace(/^data:image\/\w+;base64,/, '');
          const fileName = name.toLowerCase().replace(/[^a-z0-9]/g, '') + '_' + Date.now() + '.jpg';
          fs.writeFileSync(path.join(PHOTOS_DIR, fileName), base64Data, 'base64');
          photoPath = './photos/' + fileName;
        }

        const dailyRoomUrl = await createDailyRoom(name);

        const newContact = {
          id: nextId, name, relationship: relationship || '',
          photo: photoPath, dailyRoomUrl, phoneNumber: phoneNumber || '',
          emergencyContact: false, position: nextPos
        };

        contacts.contacts.push(newContact);
        writeContacts(contacts);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, contact: newContact }));
      } catch (err) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: 'Failed to add contact' }));
      }
    });
    return;
  }

  // Return cached carousel photos
  if (req.method === 'GET' && req.url === '/api/photos') {
    try {
      const metaPath = path.join(PHOTOS_CAROUSEL_DIR, '_meta.json');
      const meta = fs.existsSync(metaPath) ? JSON.parse(fs.readFileSync(metaPath, 'utf8')) : [];
      const photos = [];
      for (const item of meta) {
        // Find the file for this photo
        const files = fs.readdirSync(PHOTOS_CAROUSEL_DIR).filter(f => f.startsWith(item.id) && !f.endsWith('.json'));
        if (files.length > 0) {
          photos.push({
            id: item.id,
            caption: item.caption || '',
            url: '/api/photos/file/' + files[0]
          });
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ photos }));
    } catch {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ photos: [] }));
    }
    return;
  }

  // Serve a carousel photo file
  if (req.method === 'GET' && req.url.startsWith('/api/photos/file/')) {
    const fileName = req.url.split('/').pop();
    const filePath = path.join(PHOTOS_CAROUSEL_DIR, fileName);
    if (fs.existsSync(filePath)) {
      const ext = path.extname(fileName).toLowerCase();
      const mime = ext === '.png' ? 'image/png' : 'image/jpeg';
      res.writeHead(200, { 'Content-Type': mime });
      res.end(fs.readFileSync(filePath));
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
    return;
  }

  // Return reminders
  if (req.method === 'GET' && req.url === '/api/reminders') {
    const data = readReminders();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
    return;
  }

  // Signal voicemail to cloud
  if (req.method === 'POST' && req.url === '/api/calls/voicemail') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { from } = JSON.parse(body);
        await cloudFetch(`${CLOUD_API}/api/calls/${DEVICE_ID}/voicemail`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ from: from || '' })
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false }));
      }
    });
    return;
  }

  // Return cached voicemails for frontend
  if (req.method === 'GET' && req.url === '/api/voicemails') {
    const data = readVoicemails();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
    return;
  }

  // WiFi info
  if (req.method === 'GET' && req.url === '/api/wifi') {
    const { execSync } = require('child_process');
    try {
      const iwconfig = execSync('iwconfig wlan0 2>/dev/null || echo ""', { encoding: 'utf8' });
      const ssidMatch = iwconfig.match(/ESSID:"([^"]+)"/);
      const qualityMatch = iwconfig.match(/Link Quality=(\d+)\/(\d+)/);
      const ssid = ssidMatch ? ssidMatch[1] : '';
      let strength = '';
      if (qualityMatch) {
        const pct = Math.round((parseInt(qualityMatch[1]) / parseInt(qualityMatch[2])) * 100);
        strength = pct >= 70 ? 'Strong' : pct >= 40 ? 'Fair' : 'Weak';
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ssid, strength }));
    } catch {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ssid: '', strength: '' }));
    }
    return;
  }

  // WiFi scan
  if (req.method === 'GET' && req.url === '/api/wifi/scan') {
    const { execSync } = require('child_process');
    try {
      const scan = execSync('nmcli -t -f SSID,SIGNAL dev wifi list 2>/dev/null || echo ""', { encoding: 'utf8' });
      const networks = scan.split('\n').filter(l => l.trim()).map(l => {
        const [ssid, signal] = l.split(':');
        return { ssid: ssid || '', signal: signal ? signal + '%' : '' };
      }).filter(n => n.ssid);
      // Deduplicate by SSID, keep strongest
      const seen = {};
      for (const n of networks) {
        if (!seen[n.ssid] || parseInt(n.signal) > parseInt(seen[n.ssid].signal)) {
          seen[n.ssid] = n;
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ networks: Object.values(seen) }));
    } catch {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ networks: [] }));
    }
    return;
  }

  // WiFi connect (uses execFile with args array to prevent shell injection)
  if (req.method === 'POST' && req.url === '/api/wifi/connect') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const { execFileSync } = require('child_process');
      try {
        const { ssid, password } = JSON.parse(body);
        if (!ssid || typeof ssid !== 'string') throw new Error('SSID required');
        if (!password || typeof password !== 'string') throw new Error('Password required');
        execFileSync('nmcli', ['dev', 'wifi', 'connect', ssid, 'password', password], { encoding: 'utf8', timeout: 15000 });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message || 'Connection failed' }));
      }
    });
    return;
  }

  if (req.method === 'POST' && req.url === '/api/capture-frame') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { screen } = JSON.parse(body);
        await captureBlurredScreenshot(screen || 'unknown');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, buffered: screenshotBuffer.length }));
      } catch {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Capture failed' }));
      }
    });
    return;
  }

  // Submit feedback (captures screenshot and forwards to cloud)
  if (req.method === 'POST' && req.url === '/api/feedback') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const feedbackBody = JSON.parse(body);
        // Attach rolling screenshot buffer (last 5 screens, messages blurred)
        feedbackBody.recentScreens = screenshotBuffer.slice();
        // Also capture current screen (with blur)
        try {
          const win = global.kenWindow;
          if (win && !win.isDestroyed()) {
            await win.webContents.executeJavaScript(`
              (function() {
                const style = document.createElement('style');
                style.id = 'ken-blur-overlay';
                style.textContent = '.msg-text, .msg-body, .thread-msg-text, .message-text, .msg-item-text, .vm-text, [class*="message"] .text-content { filter: blur(8px) !important; -webkit-filter: blur(8px) !important; }';
                document.head.appendChild(style);
              })();
            `);
            await new Promise(r => setTimeout(r, 100));
            const image = await win.webContents.capturePage();
            const resized = image.resize({ width: 480, quality: 'good' });
            const jpegBuffer = resized.toJPEG(70);
            feedbackBody.screenshot = 'data:image/jpeg;base64,' + jpegBuffer.toString('base64');
            await win.webContents.executeJavaScript(`
              (function() {
                const s = document.getElementById('ken-blur-overlay');
                if (s) s.remove();
              })();
            `);
          }
        } catch (err) {
          console.error('Feedback screenshot capture failed:', err.message);
        }
        // Forward to cloud
        await cloudFetch(`${CLOUD_API}/api/feedback/${DEVICE_ID}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(feedbackBody)
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to submit feedback' }));
      }
    });
    return;
  }

  // Network info (IP address)
  if (req.method === 'GET' && req.url === '/api/network-info') {
    const os = require('os');
    const interfaces = os.networkInterfaces();
    let ip = '—';
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          ip = iface.address;
          break;
        }
      }
      if (ip !== '—') break;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ip }));
    return;
  }

  // Audit log relay — frontend posts events here, server forwards to cloud
  if (req.method === 'POST' && req.url === '/api/audit/log') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { action, details } = JSON.parse(body);
        if (action) logToAudit(action, details || {});
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('Contact server running on port ' + PORT);
  console.log('Device ID:', DEVICE_ID);
  console.log('Cloud API:', CLOUD_API);
  console.log('Polling every ' + (POLL_INTERVAL / 1000) + 's for contacts and messages');
  // Log device startup to audit trail (delayed to allow heartbeat to set device key)
  setTimeout(() => logToAudit('Device started', { deviceId: DEVICE_ID }), 10000);
});

module.exports = server;
