// The Ken — Cloudflare Worker API
// Handles contacts, messaging, family interface, auth, permissions & audit

const ALLOWED_ORIGINS = ['https://theken.uk', 'https://www.theken.uk', 'https://ken-api.the-ken.workers.dev', 'https://api.theken.uk'];
let _currentCorsHeaders = null;

// ===== SECURITY: RATE LIMITING =====
// IP-based rate limiting using KV with TTL
async function checkRateLimit(env, request, action, maxAttempts, windowSeconds) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const key = `ratelimit:${action}:${ip}`;
  const current = await env.KEN_KV.get(key, 'json');
  const now = Date.now();
  if (current && current.count >= maxAttempts && (now - current.start) < windowSeconds * 1000) {
    return { limited: true, retryAfter: Math.ceil((current.start + windowSeconds * 1000 - now) / 1000) };
  }
  if (!current || (now - current.start) >= windowSeconds * 1000) {
    await env.KEN_KV.put(key, JSON.stringify({ count: 1, start: now }), { expirationTtl: windowSeconds });
  } else {
    current.count++;
    await env.KEN_KV.put(key, JSON.stringify(current), { expirationTtl: windowSeconds });
  }
  return { limited: false };
}

// ===== SECURITY: INPUT SANITISATION =====
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str
    .slice(0, 10000)
    .replace(/<[^>]*>/g, '')
    .replace(/javascript\s*:/gi, '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .trim();
}

// ===== SECURITY: HTML ESCAPING (for template output) =====
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ===== SECURITY: REQUEST SIZE LIMIT =====
const MAX_REQUEST_BODY = 5 * 1024 * 1024; // 5MB global max
const MAX_PHOTO_BASE64 = 500 * 1024; // 500KB decoded for contact/user photos
const MAX_VOICEMAIL_BASE64 = 5 * 1024 * 1024; // 5MB for voicemails
const MAX_SCREENSHOT_BASE64 = 200 * 1024; // 200KB for screenshots

// ===== SECURITY: FIELD-LEVEL ENCRYPTION (AES-GCM) =====
// Encrypts sensitive fields (medical, care notes, patient details) before KV storage
const SENSITIVE_FIELDS = ['gp', 'medications', 'allergies', 'conditions', 'careNotes', 'nhsNumber', 'keySafeCode', 'nextOfKin', 'dob'];

async function getEncryptionKey(env) {
  const keyMaterial = env.ENCRYPTION_KEY;
  if (!keyMaterial) throw new Error('ENCRYPTION_KEY secret not configured — set via `wrangler secret put ENCRYPTION_KEY`');
  const encoder = new TextEncoder();
  const rawKey = await crypto.subtle.digest('SHA-256', encoder.encode(keyMaterial));
  return crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptField(env, plaintext) {
  if (!plaintext || typeof plaintext !== 'string') return plaintext;
  const key = await getEncryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  // Store as base64: iv:ciphertext
  const ivB64 = btoa(String.fromCharCode(...iv));
  const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  return 'ENC:' + ivB64 + ':' + ctB64;
}

async function decryptField(env, encrypted) {
  if (!encrypted || typeof encrypted !== 'string' || !encrypted.startsWith('ENC:')) return encrypted;
  try {
    const key = await getEncryptionKey(env);
    const parts = encrypted.slice(4).split(':');
    const iv = Uint8Array.from(atob(parts[0]), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch {
    return encrypted; // Return as-is if decryption fails (legacy unencrypted data)
  }
}

async function encryptObject(env, obj, fields) {
  const result = { ...obj };
  for (const field of fields) {
    if (result[field] !== undefined && result[field] !== null) {
      if (typeof result[field] === 'string') {
        result[field] = await encryptField(env, result[field]);
      } else if (typeof result[field] === 'object') {
        result[field] = await encryptField(env, JSON.stringify(result[field]));
      }
    }
  }
  return result;
}

async function decryptObject(env, obj, fields) {
  const result = { ...obj };
  for (const field of fields) {
    if (result[field] !== undefined && typeof result[field] === 'string' && result[field].startsWith('ENC:')) {
      const decrypted = await decryptField(env, result[field]);
      // Try parsing as JSON (for arrays/objects that were stringified)
      try { result[field] = JSON.parse(decrypted); } catch { result[field] = decrypted; }
    }
  }
  return result;
}

// ===== DEVICE KEY HASHING (at-rest protection) =====
// Device keys are high-entropy UUIDs — SHA-256 is sufficient (no need for PBKDF2)
async function hashDeviceKey(rawKey) {
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode('ken-dk-salt:' + rawKey));
  return 'DK:' + btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function storeDeviceKey(env, deviceId, rawKey) {
  const hashed = await hashDeviceKey(rawKey);
  await env.KEN_KV.put(`device-key:${deviceId}`, hashed);
}

async function verifyDeviceKey(env, deviceId, providedKey) {
  if (!providedKey) return false;
  const stored = await env.KEN_KV.get(`device-key:${deviceId}`);
  if (!stored) return false;
  if (stored.startsWith('DK:')) {
    // Hashed key — compare hashes
    const providedHash = await hashDeviceKey(providedKey);
    return timingSafeEqual(stored, providedHash);
  }
  // Legacy plaintext key — compare directly, then migrate to hashed
  if (timingSafeEqual(stored, providedKey)) {
    // Migrate to hashed storage
    try { await storeDeviceKey(env, deviceId, providedKey); } catch {}
    return true;
  }
  return false;
}

// ===== D1 DATABASE HELPERS (Phase 1: Users, Devices) =====
// These read from D1 with KV fallback during migration

async function d1GetUser(env, email) {
  if (!env.KEN_DB) return null;
  try {
    const row = await env.KEN_DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
    if (!row) return null;
    // Reconstruct KV-compatible user object
    const devices = {};
    const deviceRows = await env.KEN_DB.prepare('SELECT device_id, role FROM user_devices WHERE email = ?').bind(email.toLowerCase()).all();
    for (const d of deviceRows.results) {
      devices[d.device_id] = { role: d.role };
    }
    return {
      email: row.email, name: row.name, phone: row.phone,
      passwordHash: row.password_hash, passwordSalt: row.password_salt,
      photo: row.photo, globalRole: row.global_role, poa: !!row.poa,
      mfaEnabled: !!row.mfa_enabled, mfaSecret: row.mfa_secret,
      mfaBackupCodes: row.mfa_backup_codes ? JSON.parse(row.mfa_backup_codes) : [],
      consent: !!row.consent_accepted, consentPolicyVersion: row.consent_policy_version, consentAt: row.consent_at,
      subscriptions: row.subscriptions ? JSON.parse(row.subscriptions) : {},
      lastLogin: row.last_login, createdAt: row.created_at,
      devices
    };
  } catch (e) { console.error('D1 getUser error:', e.message); return null; }
}

async function d1SaveUser(env, user) {
  if (!env.KEN_DB) return;
  try {
    await env.KEN_DB.prepare(`
      INSERT INTO users (email, name, phone, password_hash, password_salt, photo, global_role, poa,
        mfa_enabled, mfa_secret, mfa_backup_codes, consent_accepted, consent_policy_version, consent_at,
        subscriptions, last_login, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(email) DO UPDATE SET
        name=excluded.name, phone=excluded.phone, password_hash=excluded.password_hash,
        password_salt=excluded.password_salt, photo=excluded.photo, global_role=excluded.global_role,
        poa=excluded.poa, mfa_enabled=excluded.mfa_enabled, mfa_secret=excluded.mfa_secret,
        mfa_backup_codes=excluded.mfa_backup_codes, consent_accepted=excluded.consent_accepted,
        consent_policy_version=excluded.consent_policy_version, consent_at=excluded.consent_at,
        subscriptions=excluded.subscriptions, last_login=excluded.last_login
    `).bind(
      user.email.toLowerCase(), user.name || '', user.phone || '',
      user.passwordHash || '', user.passwordSalt || '', user.photo || '',
      user.globalRole || null, user.poa ? 1 : 0,
      user.mfaEnabled ? 1 : 0, user.mfaSecret || null,
      user.mfaBackupCodes ? JSON.stringify(user.mfaBackupCodes) : null,
      user.consent ? 1 : 0, user.consentPolicyVersion || null, user.consentAt || null,
      user.subscriptions ? JSON.stringify(user.subscriptions) : '{}',
      user.lastLogin || null, user.createdAt || new Date().toISOString()
    ).run();
    // Sync user_devices
    if (user.devices) {
      for (const [deviceId, data] of Object.entries(user.devices)) {
        const role = typeof data === 'object' ? (data.role || 'standard') : 'standard';
        await env.KEN_DB.prepare(
          'INSERT INTO user_devices (email, device_id, role) VALUES (?, ?, ?) ON CONFLICT(email, device_id) DO UPDATE SET role=excluded.role'
        ).bind(user.email.toLowerCase(), deviceId, role).run();
      }
    }
  } catch (e) { console.error('D1 saveUser error:', e.message); }
}

async function d1GetDeviceUsers(env, deviceId) {
  if (!env.KEN_DB) return [];
  try {
    const rows = await env.KEN_DB.prepare(
      'SELECT u.email, u.name, u.phone, u.photo, u.last_login, u.global_role, ud.role FROM users u JOIN user_devices ud ON u.email = ud.email WHERE ud.device_id = ?'
    ).bind(deviceId).all();
    return rows.results.map(r => ({
      email: r.email, name: r.name, phone: r.phone, photo: r.photo,
      lastLogin: r.last_login, globalRole: r.global_role, role: r.role
    }));
  } catch (e) { console.error('D1 getDeviceUsers error:', e.message); return []; }
}

async function d1GetAllDevices(env) {
  if (!env.KEN_DB) return [];
  try {
    const rows = await env.KEN_DB.prepare('SELECT device_id FROM devices').all();
    return rows.results.map(r => r.device_id);
  } catch (e) { console.error('D1 getAllDevices error:', e.message); return []; }
}

// Dual-write helper: saves user to both KV and D1
async function saveUserDual(env, email, user) {
  await env.KEN_KV.put(`user:${email.toLowerCase()}`, JSON.stringify(user));
  try { await d1SaveUser(env, user); } catch (e) { console.error('D1 dual-write error (non-fatal):', e.message); }
}

// ===== PII TOKENISATION & ENCRYPTED STORAGE =====
// Separate encryption key for PII token mappings (stored in KEN_PII namespace)
// Even if KEN_KV is compromised, PII mappings remain encrypted without PII_KEY

const RETENTION_PERIODS = {
  medical: 3 * 365 * 24 * 60 * 60 * 1000,   // 3 years — UK safeguarding
  audit: 6 * 365 * 24 * 60 * 60 * 1000,     // 6 years — legal/regulatory
  messages: 1 * 365 * 24 * 60 * 60 * 1000,  // 1 year — dispute resolution
  general: 90 * 24 * 60 * 60 * 1000,        // 90 days — everything else
};

async function getPiiKey(env) {
  const keyMaterial = env.PII_KEY;
  if (!keyMaterial) throw new Error('PII_KEY secret not configured — set via `wrangler secret put PII_KEY`');
  const encoder = new TextEncoder();
  const rawKey = await crypto.subtle.digest('SHA-256', encoder.encode(keyMaterial));
  return crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptPii(env, plaintext) {
  if (!plaintext || typeof plaintext !== 'string') return plaintext;
  const key = await getPiiKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const ivB64 = btoa(String.fromCharCode(...iv));
  const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
  return 'PII:' + ivB64 + ':' + ctB64;
}

async function decryptPii(env, encrypted) {
  if (!encrypted || typeof encrypted !== 'string' || !encrypted.startsWith('PII:')) return encrypted;
  const key = await getPiiKey(env);
  const parts = encrypted.slice(4).split(':');
  const iv = Uint8Array.from(atob(parts[0]), c => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(parts[1]), c => c.charCodeAt(0));
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

// Generate a PII token and store encrypted PII mapping in KEN_PII
async function tokenisePii(env, piiData, retentionCategory) {
  const token = 'TOK_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12);
  const encryptedPii = await encryptPii(env, JSON.stringify(piiData));
  const retentionMs = RETENTION_PERIODS[retentionCategory] || RETENTION_PERIODS.general;
  await env.KEN_PII.put(`pii:${token}`, JSON.stringify({
    data: encryptedPii,
    createdAt: new Date().toISOString(),
    retentionExpiry: new Date(Date.now() + retentionMs).toISOString(),
    category: retentionCategory,
  }));
  return token;
}

// Resolve a PII token — returns decrypted PII data (HQ use only)
async function resolvePiiToken(env, token) {
  const record = await env.KEN_PII.get(`pii:${token}`, 'json');
  if (!record) return null;
  const decrypted = await decryptPii(env, record.data);
  try { return JSON.parse(decrypted); } catch { return decrypted; }
}

// Replace PII fields in a message/record with a token
function tokeniseRecord(record, emailToToken) {
  if (!record) return record;
  const r = { ...record };
  if (r.fromEmail && emailToToken[r.fromEmail]) {
    r.from = emailToToken[r.fromEmail];
    r.fromEmail = emailToToken[r.fromEmail];
  }
  if (r.toEmail && emailToToken[r.toEmail]) {
    r.to = emailToToken[r.toEmail];
    r.toEmail = emailToToken[r.toEmail];
  }
  if (r.userId && emailToToken[r.userId]) {
    r.userId = emailToToken[r.userId];
  }
  if (r.email && emailToToken[r.email]) {
    r.email = emailToToken[r.email];
  }
  if (r.invitedBy && emailToToken[r.invitedBy]) {
    r.invitedBy = emailToToken[r.invitedBy];
  }
  if (r.carerId && emailToToken[r.carerId]) {
    r.carerId = emailToToken[r.carerId];
    r.carerName = emailToToken[r.carerId] || r.carerName;
  }
  return r;
}

// ===== ROLE & PERMISSIONS SYSTEM =====
// Roles (ascending access): user, standard, admin, carer, hq
const VALID_ROLES = ['user', 'standard', 'admin', 'carer', 'hq'];

const PERMISSIONS = {
  'view:contacts':           ['user', 'standard', 'admin', 'carer', 'hq'],
  'edit:contacts':           ['admin', 'carer'],
  'view:messages':           ['user', 'standard', 'admin', 'carer'],
  'send:messages':           ['standard', 'admin', 'carer'],
  'view:voicemail':          ['user', 'standard', 'admin', 'carer'],
  'send:voicemail':          ['standard', 'admin', 'carer'],
  'view:medical':            ['user', 'admin', 'carer'],
  'edit:medical':            ['user', 'admin', 'carer'],
  'view:care_notes':         ['user', 'admin', 'carer', 'hq'],
  'edit:care_notes':         ['carer'],
  'edit:settings':           ['admin', 'carer'],
  'edit:reminders':          ['admin', 'carer'],
  'view:audit':              ['admin', 'hq'],
  'manage:multiple_devices': ['carer', 'hq'],
  'manage:invites':          ['admin'],
  'view:all_devices':        ['hq'],
  'remote:view_pi':          ['hq'],
  'set:poa':                 ['hq'],
  'view:hq_messages':        [], // requires explicit permission grant
  'view:hq_voicemail':       [], // requires explicit permission grant
};

function hasPermission(role, action) {
  return (PERMISSIONS[action] || []).includes(role);
}

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Ken-CSRF, X-Ken-Device-Key',
    'Access-Control-Allow-Credentials': 'true',
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const CORS_HEADERS = getCorsHeaders(request);
    _currentCorsHeaders = CORS_HEADERS;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // ===== SECURITY: REQUEST SIZE LIMIT =====
    const contentLength = parseInt(request.headers.get('Content-Length') || '0');
    if (contentLength > MAX_REQUEST_BODY) {
      return json({ error: 'Request too large' }, 413);
    }

    // ===== SECURITY: CSRF PROTECTION =====
    // Require X-Ken-CSRF header on all POST/DELETE from browsers.
    // Device-key authenticated requests (Pi) are exempt.
    if ((request.method === 'POST' || request.method === 'DELETE') && !path.startsWith('/api/auth/')) {
      const hasCSRF = request.headers.get('X-Ken-CSRF');
      const hasDeviceKey = request.headers.get('X-Ken-Device-Key');
      // Public endpoints exempt: add-contact, feedback submit (these are also rate-limited)
      const csrfExempt = (
        path.match(/^\/api\/contacts\/[\w-]+$/) && request.method === 'POST' ||
        path.match(/^\/api\/feedback\/[\w-]+$/) && request.method === 'POST' ||
        path.match(/^\/api\/heartbeat\/[\w-]+/) && request.method === 'POST'
      );
      if (!hasCSRF && !hasDeviceKey && !csrfExempt) {
        return json({ error: 'CSRF token required' }, 403);
      }
    }

    // ===== DEVICE AUTHENTICATION MIDDLEWARE =====
    // All device-scoped endpoints require either a valid device API key or user session
    const deviceScopeMatch = path.match(/^\/api\/(?:contacts|messages|calls|medical|voicemail|settings|heartbeat|history|screen|reminders|device|check-offline|offline-alert|audit|feedback|notifications|med-alerts|export|groups|escalation)\/([A-Za-z0-9-]+)/);
    if (deviceScopeMatch) {
      const scopedDeviceId = deviceScopeMatch[1];
      // Public endpoints exempt from auth (QR code contact form, feedback, heartbeat)
      // Heartbeat does its own device-key validation internally
      const isPublicEndpoint = (
        (request.method === 'POST' && path === `/api/contacts/${scopedDeviceId}`) ||
        (request.method === 'GET' && path === `/api/contacts/${scopedDeviceId}/pending`) ||
        (request.method === 'POST' && path === `/api/feedback/${scopedDeviceId}`) ||
        (request.method === 'POST' && path.startsWith(`/api/heartbeat/${scopedDeviceId}`)) ||
        (request.method === 'GET' && path.startsWith(`/api/heartbeat/${scopedDeviceId}`)) ||
        (request.method === 'GET' && path.startsWith(`/api/check-offline/${scopedDeviceId}`)) ||
        (request.method === 'POST' && path === '/api/device/migrate-id')
      );
      if (!isPublicEndpoint) {
        const deviceKey = request.headers.get('X-Ken-Device-Key');
        const isDeviceAuthed = deviceKey ? await verifyDeviceKey(env, scopedDeviceId, deviceKey) : false;
        const session = await getSession(request, env);
        if (!isDeviceAuthed && !session) {
          return json({ error: 'Authentication required' }, 401);
        }
      }
    }

    // ===== AUTH ENDPOINTS =====
    if (request.method === 'POST' && path === '/api/auth/register') {
      const rl = await checkRateLimit(env, request, 'register', 5, 300);
      if (rl.limited) return json({ error: 'Too many attempts. Please wait a few minutes and try again.' }, 429);
      try {
        const body = await request.json();
        const { email, password, name, phone, deviceId, consent, policyVersion } = body;
        if (!email || !password || !name) return json({ error: 'Please fill in your name, email address, and password.' }, 400);
        if (!consent) return json({ error: 'You must agree to the Privacy Policy and Terms to create an account.' }, 400);
        if (password.length < 8) return json({ error: 'Password must be at least 8 characters long.' }, 400);
        const existing = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (existing) return json({ error: 'An account with this email address already exists. Try signing in instead.' }, 400);
        const { hash: passwordHash, salt: passwordSalt } = await hashPassword(password);
        const devices = {};
        if (deviceId) {
          // Check for invite
          const invite = await env.KEN_KV.get(`invite:${deviceId}:${email.toLowerCase()}`, 'json');
          devices[deviceId] = { role: invite ? invite.role : 'standard' };
          if (invite) await env.KEN_KV.delete(`invite:${deviceId}:${email.toLowerCase()}`);
        }
        const user = {
          email: email.toLowerCase(),
          name: sanitize(name),
          phone: sanitize(phone || ''),
          passwordHash,
          passwordSalt,
          photo: '',
          devices,
          createdAt: new Date().toISOString(),
          consent: {
            accepted: true,
            policyVersion: policyVersion || '2.0',
            consentedAt: new Date().toISOString(),
          },
          subscriptions: {
            emailNotifications: { enabled: true, updatedAt: new Date().toISOString() },
            birthdayReminders: { enabled: true, updatedAt: new Date().toISOString() },
            productUpdates: { enabled: false, updatedAt: new Date().toISOString() },
          },
        };
        await saveUserDual(env, email, user);
        // Create session
        const token = crypto.randomUUID();
        await env.KEN_KV.put(`session:${token}`, JSON.stringify({ email: user.email, token, createdAt: new Date().toISOString() }), { expirationTtl: 2592000 });
        if (deviceId) await logAudit(env, deviceId, user.email, 'Account created', { role: devices[deviceId]?.role || 'standard' });
        const headers = { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Set-Cookie': `ken_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000` };
        return new Response(JSON.stringify({ success: true }), { headers });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    if (request.method === 'POST' && path === '/api/auth/login') {
      const rl = await checkRateLimit(env, request, 'login', 5, 60);
      if (rl.limited) return json({ error: 'Too many login attempts. Try again in a minute.' }, 429);
      try {
        const body = await request.json();
        const { email, password, totpCode } = body;
        if (!email || !password) return json({ error: 'Please enter your email address and password.' }, 400);
        const user = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (!user) return json({ error: 'That email and password combination doesn\'t match our records. Please check and try again.' }, 401);
        // Account lockout: 5 failed attempts in 15 minutes
        const lockoutKey = `lockout:${email.toLowerCase()}`;
        const lockout = await env.KEN_KV.get(lockoutKey, 'json');
        if (lockout && lockout.count >= 5) {
          return json({ error: 'This account has been temporarily locked after too many failed attempts. Please try again in 15 minutes.' }, 429);
        }
        const pwResult = await verifyPassword(password, user.passwordHash, user.passwordSalt || 'ken-salt-2026');
        if (!pwResult.valid) {
          const newCount = (lockout ? lockout.count : 0) + 1;
          await env.KEN_KV.put(lockoutKey, JSON.stringify({ count: newCount }), { expirationTtl: 900 });
          if (newCount >= 5) {
            return json({ error: 'This account has been temporarily locked after too many failed attempts. Please try again in 15 minutes.' }, 429);
          }
          return json({ error: 'That email and password combination doesn\'t match our records. Please check and try again.' }, 401);
        }
        // Successful login — clear lockout counter
        await env.KEN_KV.delete(lockoutKey);
        // Rehash with PBKDF2 if still using legacy SHA-256
        if (pwResult.needsRehash) {
          const { hash: newHash, salt: newSalt } = await hashPassword(password, user.passwordSalt || 'ken-salt-2026');
          user.passwordHash = newHash;
          user.passwordSalt = newSalt;
          await saveUserDual(env, email, user);
        }
        // Check MFA
        if (user.mfaEnabled && user.mfaSecret) {
          if (!totpCode) {
            return json({ mfaRequired: true, error: 'Please enter your authenticator code to sign in.' }, 403);
          }
          // Try TOTP first, then backup codes
          const validTotp = await verifyTOTP(user.mfaSecret, totpCode);
          if (!validTotp) {
            // Check backup codes (stored as hashes — try PBKDF2 then legacy)
            let backupIdx = -1;
            const { hash: codeHash } = await hashPassword(totpCode, 'mfa-backup-salt');
            const { hash: legacyCodeHash } = await hashPasswordLegacy(totpCode, 'mfa-backup-salt');
            for (let i = 0; i < (user.mfaBackupCodes || []).length; i++) {
              if (timingSafeEqual(user.mfaBackupCodes[i], codeHash) || timingSafeEqual(user.mfaBackupCodes[i], legacyCodeHash)) { backupIdx = i; break; }
            }
            if (backupIdx === -1) return json({ error: 'That authenticator code isn\'t right. Check your app for the latest code, or use a backup code.' }, 401);
            // Consume the backup code
            user.mfaBackupCodes.splice(backupIdx, 1);
            await saveUserDual(env, email, user);
          }
        }
        const token = crypto.randomUUID();
        await env.KEN_KV.put(`session:${token}`, JSON.stringify({ email: user.email, token, createdAt: new Date().toISOString() }), { expirationTtl: 2592000 });
        // Track last login
        user.lastLogin = new Date().toISOString();
        await saveUserDual(env, email, user);
        const headers = { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Set-Cookie': `ken_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000` };
        return new Response(JSON.stringify({ success: true }), { headers });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== MFA SETUP =====
    // Setup uses a temporary token instead of cookies to avoid third-party cookie blocking
    if (request.method === 'POST' && path === '/api/auth/mfa/setup') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const secret = generateTOTPSecret();
      // Store pending setup with a temporary token (avoids cookie issues on confirm)
      const setupToken = crypto.randomUUID();
      await env.KEN_KV.put(`mfa-setup:${setupToken}`, JSON.stringify({ email: auth.user.email, secret }), { expirationTtl: 600 });
      const otpauth = `otpauth://totp/TheKen:${encodeURIComponent(auth.user.email)}?secret=${secret}&issuer=TheKen&digits=6&period=30`;
      return json({ secret, otpauth, setupToken });
    }

    // Confirm uses the setupToken from setup (no cookie needed)
    if (request.method === 'POST' && path === '/api/auth/mfa/confirm') {
      const rl = await checkRateLimit(env, request, 'mfa-confirm', 5, 60);
      if (rl.limited) return json({ error: 'Too many attempts. Try again in a minute.' }, 429);
      try {
        const body = await request.json();
        const { code, setupToken } = body;
        if (!code || !setupToken) return json({ error: 'Code and setup token are required' }, 400);
        const setup = await env.KEN_KV.get(`mfa-setup:${setupToken}`, 'json');
        if (!setup) return json({ error: 'Setup expired. Please start MFA setup again.' }, 400);
        const valid = await verifyTOTP(setup.secret, code);
        if (!valid) return json({ error: 'Invalid code. Check your authenticator app and try again.' }, 400);
        // Activate MFA on the user
        const user = await env.KEN_KV.get(`user:${setup.email}`, 'json');
        if (!user) return json({ error: 'User not found' }, 400);
        user.mfaEnabled = true;
        user.mfaSecret = setup.secret;
        const backupCodes = Array.from({ length: 8 }, () => crypto.randomUUID().slice(0, 8));
        // Store hashed backup codes for security; return plaintext to user once
        const hashedBackupCodes = [];
        for (const code of backupCodes) {
          const { hash } = await hashPassword(code, 'mfa-backup-salt');
          hashedBackupCodes.push(hash);
        }
        user.mfaBackupCodes = hashedBackupCodes;
        await saveUserDual(env, setup.email, user);
        await env.KEN_KV.delete(`mfa-setup:${setupToken}`);
        const deviceIds = Object.keys(user.devices || {});
        if (deviceIds[0]) await logAudit(env, deviceIds[0], setup.email, 'Enabled MFA', {});
        return json({ success: true, backupCodes });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // Disable also uses email+password directly (no cookie needed)
    if (request.method === 'POST' && path === '/api/auth/mfa/disable') {
      try {
        const body = await request.json();
        const { email, password } = body;
        if (!email || !password) return json({ error: 'Email and password required' }, 400);
        const user = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (!user) return json({ error: 'Invalid credentials' }, 401);
        const pwResult = await verifyPassword(password, user.passwordHash, user.passwordSalt || 'ken-salt-2026');
        if (!pwResult.valid) return json({ error: 'Invalid password' }, 401);
        if (pwResult.needsRehash) {
          const { hash: newHash, salt: newSalt } = await hashPassword(password, user.passwordSalt || 'ken-salt-2026');
          user.passwordHash = newHash;
          user.passwordSalt = newSalt;
        }
        user.mfaEnabled = false;
        delete user.mfaSecret;
        delete user.mfaPendingSecret;
        delete user.mfaBackupCodes;
        await saveUserDual(env, email, user);
        const deviceIds = Object.keys(user.devices || {});
        if (deviceIds[0]) await logAudit(env, deviceIds[0], email, 'Disabled MFA', {});
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    if (request.method === 'GET' && path === '/api/auth/mfa/status') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      return json({ mfaEnabled: !!auth.user.mfaEnabled });
    }

    // ===== FORGOT PASSWORD =====
    if (request.method === 'POST' && path === '/api/auth/forgot-password') {
      const rl = await checkRateLimit(env, request, 'forgot-pw', 3, 300);
      if (rl.limited) return json({ error: 'Too many requests. Try again later.' }, 429);
      try {
        const body = await request.json();
        const { email } = body;
        if (!email) return json({ error: 'Please enter your email address.' }, 400);
        const user = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        // Always return success (don't reveal if account exists)
        if (!user) return json({ success: true });
        const resetToken = crypto.randomUUID();
        await env.KEN_KV.put(`reset:${resetToken}`, JSON.stringify({ email: email.toLowerCase(), createdAt: new Date().toISOString() }), { expirationTtl: 900 });
        // Store token on user for reference
        user.resetToken = resetToken;
        await saveUserDual(env, email, user);
        // Try to send password reset email, but don't fail if email service is down
        let emailSent = false;
        try {
          await sendEmail(env, email.toLowerCase(),
            'Reset your password \u2014 The Ken',
            'Reset your password',
            '<p style="color:#6B6459;line-height:1.7;">Click the button below to set a new password. This link expires in 15 minutes.</p>' +
            '<a href="https://theken.uk/portal/?reset=' + resetToken + '" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Reset Password</a>' +
            '<p style="color:#6B6459;font-size:13px;margin-top:24px;">If you didn\'t request this, you can safely ignore this email.</p>'
          );
          emailSent = true;
        } catch { /* email service unavailable — fall back to direct token */ }
        if (emailSent) {
          return json({ success: true });
        }
        // Email failed — return token directly so user can still reset
        return json({ success: true, resetToken });
      } catch (e) { return json({ error: e.message || 'Invalid request' }, 400); }
    }

    if (request.method === 'POST' && path === '/api/auth/reset-password') {
      const rl = await checkRateLimit(env, request, 'reset-pw', 5, 300);
      if (rl.limited) return json({ error: 'Too many attempts. Try again later.' }, 429);
      try {
        const body = await request.json();
        const { token, password } = body;
        if (!token || !password) return json({ error: 'Please enter your new password.' }, 400);
        if (password.length < 8) return json({ error: 'Password must be at least 8 characters long.' }, 400);
        const reset = await env.KEN_KV.get(`reset:${token}`, 'json');
        if (!reset) return json({ error: 'This reset link has expired. Reset links last 15 minutes. Please go back and request a new one.' }, 400);
        const user = await env.KEN_KV.get(`user:${reset.email}`, 'json');
        if (!user) return json({ error: 'We couldn\'t find the account linked to this reset link. Please try creating a new account.' }, 400);
        const { hash: newHash, salt: newSalt } = await hashPassword(password);
        user.passwordHash = newHash;
        user.passwordSalt = newSalt;
        delete user.resetToken;
        await saveUserDual(env, reset.email, user);
        await env.KEN_KV.delete(`reset:${token}`);
        // Invalidate all existing sessions for this user
        try {
          const sessionList = await env.KEN_KV.list({ prefix: 'session:' });
          for (const key of sessionList.keys) {
            const sess = await env.KEN_KV.get(key.name, 'json');
            if (sess && sess.email && sess.email.toLowerCase() === reset.email.toLowerCase()) {
              await env.KEN_KV.delete(key.name);
            }
          }
        } catch { /* best-effort session cleanup */ }
        const deviceIds = Object.keys(user.devices || {});
        if (deviceIds[0]) await logAudit(env, deviceIds[0], reset.email, 'Password reset', {});
        return json({ success: true });
      } catch (e) { return json({ error: 'Something went wrong while resetting your password. Please try again or request a new reset link.' }, 400); }
    }

    // Reset password using MFA code (no email link needed)
    if (request.method === 'POST' && path === '/api/auth/reset-with-mfa') {
      const rl = await checkRateLimit(env, request, 'mfa-reset', 5, 300);
      if (rl.limited) return json({ error: 'Too many attempts. Please wait a few minutes and try again.' }, 429);
      try {
        const body = await request.json();
        const { email, totpCode, newPassword } = body;
        if (!email || !totpCode || !newPassword) return json({ error: 'Please fill in your email, authenticator code, and new password.' }, 400);
        if (newPassword.length < 8) return json({ error: 'Password must be at least 8 characters long.' }, 400);
        const user = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (!user) return json({ error: 'We couldn\'t find an account with that email address.' }, 404);
        if (!user.mfaEnabled || !user.mfaSecret) return json({ error: 'Two-factor authentication isn\'t set up on this account. Please use the email reset link instead.' }, 400);
        const validTotp = await verifyTOTP(user.mfaSecret, totpCode);
        if (!validTotp) return json({ error: 'That authenticator code isn\'t right. Check your authenticator app and try the latest code.' }, 401);
        const { hash: newHash, salt: newSalt } = await hashPassword(newPassword);
        user.passwordHash = newHash;
        user.passwordSalt = newSalt;
        delete user.resetToken;
        await saveUserDual(env, email, user);
        // Invalidate all existing sessions
        try {
          const sessionList = await env.KEN_KV.list({ prefix: 'session:' });
          for (const key of sessionList.keys) {
            const sess = await env.KEN_KV.get(key.name, 'json');
            if (sess && sess.email && sess.email.toLowerCase() === email.toLowerCase()) {
              await env.KEN_KV.delete(key.name);
            }
          }
        } catch {}
        const deviceIds = Object.keys(user.devices || {});
        if (deviceIds[0]) await logAudit(env, deviceIds[0], email.toLowerCase(), 'Password reset via MFA', {});
        return json({ success: true });
      } catch (e) { return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== FEEDBACK (all devices — for head office) =====
    if (request.method === 'GET' && path === '/api/admin/feedback/all') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      // Check if user has admin on any device (head office access)
      const isAnyAdmin = Object.values(auth.user.devices || {}).some(d => d.role === 'admin');
      if (!isAnyAdmin) return json({ error: 'Admin access required' }, 403);
      const devices = await env.KEN_KV.get('devices:all', 'json') || [];
      const allFeedback = [];
      for (const deviceId of devices) {
        const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
        feedback.forEach(f => { f.deviceId = deviceId; });
        allFeedback.push(...feedback);
      }
      // Sort by timestamp, newest first
      allFeedback.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
      return json({ feedback: allFeedback });
    }

    if (request.method === 'POST' && path === '/api/auth/logout') {
      const cookie = request.headers.get('Cookie') || '';
      const match = cookie.match(/ken_session=([^;]+)/);
      if (match) await env.KEN_KV.delete(`session:${match[1]}`);
      const headers = { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Set-Cookie': 'ken_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' };
      return new Response(JSON.stringify({ success: true }), { headers });
    }

    if (request.method === 'GET' && path === '/api/auth/me') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const user = auth.user;
      const deviceIds = Object.keys(user.devices || {});
      const firstDevice = deviceIds[0] || null;
      const role = user.globalRole || (firstDevice && user.devices[firstDevice] ? user.devices[firstDevice].role : 'standard');
      return json({ user: {
        email: user.email, name: user.name, phone: user.phone, photo: user.photo,
        role, globalRole: user.globalRole || null,
        devices: user.devices, deviceId: firstDevice,
        carerDevices: user.carerDevices || [],
        carerProfile: user.carerProfile || null,
        mfaEnabled: !!user.mfaEnabled,
        poa: user.poa || false,
        consent: user.consent || null,
        subscriptions: user.subscriptions || {},
      }});
    }

    // Check specific permission for a device
    if (request.method === 'GET' && path.match(/^\/api\/auth\/can\/[\w-]+\/[\w:.-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[4];
      const action = parts[5];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const perm = requirePermission(auth.user, deviceId, action);
      return json({ allowed: perm.allowed, role: perm.role });
    }

    if (request.method === 'GET' && path.match(/^\/api\/auth\/permissions\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = auth.user.devices && auth.user.devices[deviceId] ? auth.user.devices[deviceId].role : null;
      if (!role) return json({ error: 'No access to this device' }, 403);
      return json({ role });
    }

    if (request.method === 'POST' && path === '/api/auth/invite') {
      try {
        const body = await request.json();
        const { email, deviceId, role } = body;
        if (!email || !deviceId || !role) return json({ error: 'email, deviceId and role are required' }, 400);
        if (!VALID_ROLES.includes(role)) return json({ error: 'role must be one of: ' + VALID_ROLES.join(', ') }, 400);
        const auth = await requireAdmin(request, env, deviceId);
        if (auth.error) return auth.response;
        await env.KEN_KV.put(`invite:${deviceId}:${email.toLowerCase()}`, JSON.stringify({ role, invitedBy: auth.user.email, createdAt: new Date().toISOString() }), { expirationTtl: 604800 });
        await logAudit(env, deviceId, auth.user.email, 'Invited user', { email: email.toLowerCase(), role });
        // Send invitation email
        const inviterName = auth.user.name || auth.user.email;
        const registerUrl = 'https://theken.uk/portal/?invite=' + deviceId;
        await sendEmail(env, email.toLowerCase(),
          inviterName + ' invited you to The Ken',
          'You\'ve been invited',
          '<p style="color:#6B6459;line-height:1.7;">' + inviterName + ' has invited you to join The Ken as <strong>' + role + '</strong>.</p>' +
          '<p style="color:#6B6459;line-height:1.7;">The Ken is a simplified video calling device that keeps families connected. Create your account to get started.</p>' +
          '<a href="' + registerUrl + '" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Create Account</a>'
        );
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== AUDIT LOG ENDPOINTS =====
    if (request.method === 'GET' && path.match(/^\/api\/audit\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const perm = requirePermission(auth.user, deviceId, 'view:audit');
      if (!perm.allowed) return json({ error: 'Insufficient permissions' }, 403);
      const audit = await env.KEN_KV.get(`audit:${deviceId}`, 'json') || [];
      return json({ audit });
    }

    // List audit archives
    if (request.method === 'GET' && path.match(/^\/api\/audit\/[\w-]+\/archives$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const perm = requirePermission(auth.user, deviceId, 'view:audit');
      if (!perm.allowed) return json({ error: 'Insufficient permissions' }, 403);
      const archiveList = await env.KEN_KV.list({ prefix: `audit-archive:${deviceId}:` });
      const archives = [];
      for (const key of archiveList.keys) {
        const data = await env.KEN_KV.get(key.name, 'json');
        if (data) archives.push({ key: key.name, count: data.length, entries: data });
      }
      return json({ archives });
    }

    // Device audit log — POST from Pi device (requires device key auth)
    if (request.method === 'POST' && path.match(/^\/api\/audit\/[\w-]+\/log$/)) {
      const deviceId = path.split('/')[3];
      const deviceKey = request.headers.get('X-Ken-Device-Key');
      const deviceKeyVerified = deviceKey ? await verifyDeviceKey(env, deviceId, deviceKey) : false;
      if (!deviceKeyVerified) {
        return json({ error: 'Device authentication required' }, 401);
      }
      try {
        const body = await request.json();
        const { action, details } = body;
        if (!action) return json({ error: 'Action required' }, 400);
        await logAudit(env, deviceId, 'device', action, details || {});
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== SETTINGS QUEUE (offline changes) =====
    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/queue$/)) {
      const deviceId = path.split('/')[3];
      // Require auth — settings queue can change device behaviour
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'edit:settings')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        // Whitelist allowed settings to prevent arbitrary injection
        const ALLOWED_SETTINGS = ['dndEnabled', 'dndStart', 'dndEnd', 'nightlightEnabled', 'nightlightStart', 'nightlightEnd', 'nightlightBrightness', 'userName', 'fontSize', 'language', 'clockFormat', 'autoAnswer', 'ringVolume', 'callVolume', 'readVolume', 'autoRead', 'readDelay', 'quietEnabled', 'quietStart', 'quietEnd', 'urgentRing', 'urgentAnswer', 'clearPasscode'];
        if (body.setting && !ALLOWED_SETTINGS.includes(body.setting)) {
          return json({ error: 'Setting not allowed: ' + body.setting }, 400);
        }
        const queue = await env.KEN_KV.get(`queue:${deviceId}`, 'json') || [];
        queue.push({ id: crypto.randomUUID(), ...body, queuedAt: new Date().toISOString() });
        await env.KEN_KV.put(`queue:${deviceId}`, JSON.stringify(queue));
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    if (request.method === 'GET' && path.match(/^\/api\/settings\/[\w-]+\/queue$/)) {
      const deviceId = path.split('/')[3];
      // Require device key or session auth
      const qDevKey = request.headers.get('X-Ken-Device-Key');
      const qDevAuthed = qDevKey ? await verifyDeviceKey(env, deviceId, qDevKey) : false;
      const qSession = await getSession(request, env);
      if (!qDevAuthed && !qSession) return json({ error: 'Authentication required' }, 401);
      const queue = await env.KEN_KV.get(`queue:${deviceId}`, 'json') || [];
      return json({ queue });
    }

    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/queue\/ack$/)) {
      const deviceId = path.split('/')[3];
      // SECURITY: require device key auth (only the Pi should ack its own queue)
      const ackDevKey = request.headers.get('X-Ken-Device-Key');
      if (!(await verifyDeviceKey(env, deviceId, ackDevKey))) {
        return json({ error: 'Device authentication required' }, 401);
      }
      await env.KEN_KV.delete(`queue:${deviceId}`);
      return json({ success: true });
    }

    // ===== ADD CONTACT FORM =====
    if (request.method === 'GET' && path.match(/^\/add\/[\w-]+$/)) {
      const deviceId = path.split('/')[2];
      return html(addContactHTML(deviceId));
    }

    // ===== ADMIN FEEDBACK VIEWER =====
    if (request.method === 'GET' && path.match(/^\/admin\/feedback\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return new Response('Unauthorized — please log in via the portal first.', { status: 401, headers: { 'Content-Type': 'text/plain' } });
      const userRole = getUserRole(auth.user, deviceId);
      if (!['admin', 'hq'].includes(userRole)) return new Response('Forbidden — admin or HQ access required.', { status: 403, headers: { 'Content-Type': 'text/plain' } });
      return html(feedbackViewerHTML(deviceId));
    }

    // ===== FAMILY INTERFACE =====
    if (request.method === 'GET' && path.match(/^\/family\/[\w-]+$/)) {
      const deviceId = path.split('/')[2];
      return html(familyHTML(deviceId));
    }

    // ===== CONTACT ENDPOINTS =====
    if (request.method === 'POST' && path.match(/^\/api\/contacts\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const rl = await checkRateLimit(env, request, 'add-contact', 10, 60);
      if (rl.limited) return json({ error: 'Too many requests. Try again later.' }, 429);
      return handleAddContact(request, env, deviceId);
    }

    if (request.method === 'GET' && path.match(/^\/api\/contacts\/[\w-]+\/pending$/)) {
      const deviceId = path.split('/')[3];
      const pending = await env.KEN_KV.get(`pending:${deviceId}`, 'json') || [];
      return json({ contacts: pending });
    }

    if (request.method === 'POST' && path.match(/^\/api\/contacts\/[\w-]+\/ack$/)) {
      const deviceId = path.split('/')[3];
      await env.KEN_KV.delete(`pending:${deviceId}`);
      return json({ success: true });
    }

    // ===== MESSAGE ENDPOINTS =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      return handleSendMessage(request, env, deviceId);
    }

    if (request.method === 'GET' && path.match(/^\/api\/messages\/[\w-]+\/pending$/)) {
      const deviceId = path.split('/')[3];
      const pending = await env.KEN_KV.get(`messages:${deviceId}`, 'json') || [];
      return json({ messages: pending });
    }

    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/ack$/)) {
      const deviceId = path.split('/')[3];
      // When Pi acks pending messages, mark them as delivered in history
      const pending = await env.KEN_KV.get(`messages:${deviceId}`, 'json') || [];
      if (pending.length > 0) {
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        const now = new Date().toISOString();
        const pendingIds = pending.map(p => p.id);
        let updated = 0;
        for (const msg of history) {
          if (pendingIds.includes(msg.id) && !msg.deliveredAt) {
            msg.deliveredAt = now;
            updated++;
          }
        }
        if (updated > 0) await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
      }
      await env.KEN_KV.delete(`messages:${deviceId}`);
      return json({ success: true });
    }

    // ===== MESSAGE STATUS: DELIVERED (Pi calls when it downloads messages) =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/delivered$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { messageIds } = body; // Array of message IDs that were delivered
        if (!messageIds || !Array.isArray(messageIds)) return json({ error: 'messageIds array required' }, 400);
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        const now = new Date().toISOString();
        let updated = 0;
        for (const msg of history) {
          if (messageIds.includes(msg.id) && !msg.deliveredAt) {
            msg.deliveredAt = now;
            updated++;
          }
        }
        if (updated > 0) await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        return json({ success: true, updated });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== MESSAGE STATUS: READ (Pi calls when User views a message) =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/read$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { messageId } = body;
        if (!messageId) return json({ error: 'messageId required' }, 400);
        // Check if read receipts are enabled for this device
        const readReceiptsPref = await env.KEN_KV.get(`read-receipts:${deviceId}`, 'json');
        if (readReceiptsPref && readReceiptsPref.enabled === false) {
          return json({ success: true, suppressed: true });
        }
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        const msg = history.find(m => m.id === messageId);
        if (msg && !msg.readAt) {
          msg.readAt = new Date().toISOString();
          await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        }
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== READ RECEIPTS TOGGLE (Admin/Carer only) =====
    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/read-receipts$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'edit:settings')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        await env.KEN_KV.put(`read-receipts:${deviceId}`, JSON.stringify({ enabled: body.enabled !== false }));
        await logAudit(env, deviceId, auth.user.email, 'Updated read receipts setting', { enabled: body.enabled !== false });
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    if (request.method === 'GET' && path.match(/^\/api\/settings\/[\w-]+\/read-receipts$/)) {
      const deviceId = path.split('/')[3];
      const pref = await env.KEN_KV.get(`read-receipts:${deviceId}`, 'json');
      return json(pref || { enabled: true });
    }

    // ===== MESSAGE DELETE (for-me / for-everyone) =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/[\w-]+\/delete$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const messageId = parts[4];
      try {
        const body = await request.json();
        const { mode } = body; // 'for-me' or 'for-everyone'
        if (!mode || !['for-me', 'for-everyone'].includes(mode)) {
          return json({ error: 'mode must be for-me or for-everyone' }, 400);
        }
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        const msg = history.find(m => m.id === messageId);
        if (!msg) return json({ error: 'Message not found' }, 404);

        // Determine who is deleting
        const deviceKey = request.headers.get('X-Ken-Device-Key');
        const isDevice = deviceKey ? await verifyDeviceKey(env, deviceId, deviceKey) : false;
        const session = await getSession(request, env);

        if (mode === 'for-everyone') {
          // Admin only
          if (!session) return json({ error: 'Authentication required' }, 401);
          const user = await env.KEN_KV.get(`user:${session.email}`, 'json');
          if (!user) return json({ error: 'User not found' }, 401);
          const role = getUserRole(user, deviceId);
          if (role !== 'admin' && role !== 'hq') return json({ error: 'Admin access required for delete-for-everyone' }, 403);
          msg.deletedForEveryone = true;
          msg.deletedForEveryoneBy = session.email;
          msg.deletedForEveryoneAt = new Date().toISOString();
          await logAudit(env, deviceId, session.email, 'Deleted message for everyone', { messageId, preview: (msg.text || '').slice(0, 50) });
        } else {
          // for-me
          if (isDevice) {
            msg.deletedByRecipient = true;
            msg.deletedByRecipientAt = new Date().toISOString();
          } else if (session) {
            msg.deletedBySender = true;
            msg.deletedBySenderAt = new Date().toISOString();
            await logAudit(env, deviceId, session.email, 'Deleted message for self', { messageId });
          } else {
            return json({ error: 'Authentication required' }, 401);
          }
        }
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== REPLY (from device — goes to history only, not pending) =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/reply$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { from, text, to } = body;
        if (!from || !text || !text.trim()) {
          return json({ error: 'From and text are required' }, 400);
        }
        const message = {
          id: crypto.randomUUID(),
          from: sanitize(from),
          text: sanitize(text),
          sentAt: new Date().toISOString(),
          deliveredAt: new Date().toISOString(), // Replies from device are already on the device
          readAt: null,
          isReply: true,
          to: sanitize(to || '') || undefined,
          deletedBySender: false,
          deletedByRecipient: false,
          deletedForEveryone: false,
          emailNotificationSent: false,
        };
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        history.push(message);
        if (history.length > 100) history.splice(0, history.length - 100);
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // ===== MESSAGE HISTORY (for family interface) =====
    if (request.method === 'GET' && path.match(/^\/api\/messages\/[\w-]+\/history$/)) {
      const deviceId = path.split('/')[3];
      const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
      // Filter deleted messages based on viewer
      const deviceKey = request.headers.get('X-Ken-Device-Key');
      const isDevice = deviceKey ? await verifyDeviceKey(env, deviceId, deviceKey) : false;
      const session = await getSession(request, env);
      const filtered = history.filter(m => {
        if (m.deletedForEveryone) return false;
        if (isDevice && m.deletedByRecipient) return false;
        if (session && m.deletedBySender && m.fromEmail === session.email) return false;
        return true;
      });
      // Include read receipt setting so portal knows whether to show third tick
      const readReceiptsPref = await env.KEN_KV.get(`read-receipts:${deviceId}`, 'json');
      return json({ messages: filtered, readReceiptsEnabled: readReceiptsPref ? readReceiptsPref.enabled : true });
    }

    // ===== TYPING INDICATOR: POST (someone is typing) =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/typing$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const name = sanitize(body.name || 'Someone');
        // Determine who is typing
        const session = await getSession(request, env);
        const email = session ? session.email : 'device';
        await env.KEN_KV.put(`typing:${deviceId}`, JSON.stringify({
          name,
          email,
          timestamp: new Date().toISOString()
        }), { expirationTtl: 15 });
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== TYPING INDICATOR: GET (check if someone is typing) =====
    if (request.method === 'GET' && path.match(/^\/api\/messages\/[\w-]+\/typing$/)) {
      const deviceId = path.split('/')[3];
      const typing = await env.KEN_KV.get(`typing:${deviceId}`, 'json');
      if (typing && typing.timestamp) {
        const age = Date.now() - new Date(typing.timestamp).getTime();
        if (age < 15000) {
          return json({ typing: true, name: typing.name });
        }
      }
      return json({ typing: false });
    }

    // ===== DELETE MESSAGE (from history) =====
    if (request.method === 'DELETE' && path.match(/^\/api\/messages\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const messageId = parts[4];
      const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
      const filtered = history.filter(m => m.id !== messageId);
      if (filtered.length === history.length) {
        return json({ error: 'Message not found' }, 404);
      }
      await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(filtered));
      return json({ success: true });
    }

    // ===== CALL ENDPOINTS =====
    // Create a Daily.co room (Pi calls this instead of holding the API key)
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/create-room$/)) {
      const deviceId = path.split('/')[3];
      if (!env.DAILY_API_KEY) return json({ error: 'Daily API key not configured' }, 500);
      try {
        const body = await request.json();
        const roomName = sanitize(body.roomName || ('ken-' + deviceId));
        // Create or get existing room
        const dailyResp = await fetch('https://api.daily.co/v1/rooms', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.DAILY_API_KEY },
          body: JSON.stringify({
            name: roomName,
            privacy: 'public',
            properties: { max_participants: 10, enable_chat: false, exp: Math.floor(Date.now() / 1000) + 86400 }
          })
        });
        if (dailyResp.status === 400) {
          // Room likely already exists, return it
          const roomUrl = 'https://theken.daily.co/' + roomName;
          await env.KEN_KV.put(`room:${deviceId}`, roomUrl);
          return json({ success: true, roomUrl });
        }
        const room = await dailyResp.json();
        const roomUrl = room.url || ('https://theken.daily.co/' + roomName);
        await env.KEN_KV.put(`room:${deviceId}`, roomUrl);
        return json({ success: true, roomUrl });
      } catch (e) {
        return json({ error: 'Could not create room' }, 500);
      }
    }

    // Pi registers its Daily room URL
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/room$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        if (body.roomUrl) {
          await env.KEN_KV.put(`room:${deviceId}`, body.roomUrl);
          return json({ success: true });
        }
        return json({ error: 'roomUrl required' }, 400);
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Family portal gets room URL
    if (request.method === 'GET' && path.match(/^\/api\/calls\/[\w-]+\/room$/)) {
      const deviceId = path.split('/')[3];
      const roomUrl = await env.KEN_KV.get(`room:${deviceId}`);
      return json({ roomUrl: roomUrl || null });
    }

    // Family member initiates a call (signals the Ken)
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      // SECURITY: require device key or authenticated session
      const callDevKey = request.headers.get('X-Ken-Device-Key');
      if (!(await verifyDeviceKey(env, deviceId, callDevKey))) {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.response;
      }
      try {
        const body = await request.json();
        const { from } = body;
        if (!from) return json({ error: 'from is required' }, 400);
        const roomUrl = await env.KEN_KV.get(`room:${deviceId}`);
        const call = {
          id: crypto.randomUUID(),
          from: from.trim(),
          roomUrl: roomUrl || '',
          startedAt: new Date().toISOString(),
        };
        await env.KEN_KV.put(`call:${deviceId}`, JSON.stringify(call), { expirationTtl: 120 });
        return json({ success: true, call: { id: call.id, roomUrl: call.roomUrl } });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Pi polls for incoming call
    if (request.method === 'GET' && path.match(/^\/api\/calls\/[\w-]+\/pending$/)) {
      const deviceId = path.split('/')[3];
      const call = await env.KEN_KV.get(`call:${deviceId}`, 'json');
      return json({ call: call || null });
    }

    // Pi acknowledges (clears) the call signal
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/ack$/)) {
      const deviceId = path.split('/')[3];
      await env.KEN_KV.delete(`call:${deviceId}`);
      return json({ success: true });
    }

    // Family member ends call (clears signal so Ken knows)
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/end$/)) {
      const deviceId = path.split('/')[3];
      await env.KEN_KV.delete(`call:${deviceId}`);
      await env.KEN_KV.delete(`outbound:${deviceId}`);
      return json({ success: true });
    }

    // ===== OUTBOUND CALL (Ken calling out — notify family) =====
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/outbound$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { contactName, roomUrl } = body;
        if (!contactName) return json({ error: 'contactName required' }, 400);
        const outbound = {
          id: crypto.randomUUID(),
          contactName: contactName.trim(),
          roomUrl: roomUrl || '',
          startedAt: new Date().toISOString(),
        };
        await env.KEN_KV.put(`outbound:${deviceId}`, JSON.stringify(outbound), { expirationTtl: 120 });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Family portal polls for outbound calls
    if (request.method === 'GET' && path.match(/^\/api\/calls\/[\w-]+\/outbound$/)) {
      const deviceId = path.split('/')[3];
      const outbound = await env.KEN_KV.get(`outbound:${deviceId}`, 'json');
      return json({ outbound: outbound || null });
    }

    // Clear outbound signal (call ended from Ken side)
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/outbound\/clear$/)) {
      const deviceId = path.split('/')[3];
      await env.KEN_KV.delete(`outbound:${deviceId}`);
      return json({ success: true });
    }

    // ===== CONTACT LIST (synced from device) =====
    if (request.method === 'POST' && path.match(/^\/api\/contacts\/[\w-]+\/sync$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        await env.KEN_KV.put(`contactlist:${deviceId}`, JSON.stringify(body.contacts || []));
        const session = await getSession(request, env);
        await logAudit(env, deviceId, session ? session.email : 'device', 'Synced contacts', { count: (body.contacts || []).length });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/contacts\/[\w-]+\/list$/)) {
      const deviceId = path.split('/')[3];
      const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
      return json({ contacts });
    }

    // Update a contact
    if (request.method === 'POST' && path.match(/^\/api\/contacts\/[\w-]+\/update$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'edit:contacts')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const { id, name, relationship, phoneNumber } = body;
        if (!id) return json({ error: 'Contact id required' }, 400);
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        const contact = contacts.find(c => c.id === id);
        if (!contact) return json({ error: 'Contact not found' }, 404);
        if (name !== undefined) contact.name = name;
        if (relationship !== undefined) contact.relationship = relationship;
        if (phoneNumber !== undefined) contact.phoneNumber = phoneNumber;
        if (body.birthday !== undefined) contact.birthday = body.birthday; // YYYY-MM-DD format
        await env.KEN_KV.put(`contactlist:${deviceId}`, JSON.stringify(contacts));
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Delete a contact
    if (request.method === 'POST' && path.match(/^\/api\/contacts\/[\w-]+\/delete$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'edit:contacts')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const { id } = body;
        if (!id) return json({ error: 'Contact id required' }, 400);
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        const filtered = contacts.filter(c => c.id !== id);
        if (filtered.length === contacts.length) return json({ error: 'Contact not found' }, 404);
        // Re-number positions
        filtered.forEach((c, i) => c.position = i + 1);
        await env.KEN_KV.put(`contactlist:${deviceId}`, JSON.stringify(filtered));
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Toggle emergency contact flag
    if (request.method === 'POST' && path.match(/^\/api\/contacts\/[\w-]+\/emergency$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'edit:contacts')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const { id, isEmergencyContact } = body;
        if (!id) return json({ error: 'Contact id required' }, 400);
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        const contact = contacts.find(c => c.id === id);
        if (!contact) return json({ error: 'Contact not found' }, 404);
        contact.isEmergencyContact = !!isEmergencyContact;
        await env.KEN_KV.put(`contactlist:${deviceId}`, JSON.stringify(contacts));
        const session = await getSession(request, env);
        await logAudit(env, deviceId, session ? session.email : 'unknown', isEmergencyContact ? 'Marked emergency contact' : 'Unmarked emergency contact', { contactName: contact.name });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Toggle POA flag on contact (HQ only)
    if (request.method === 'POST' && path.match(/^\/api\/contacts\/[\w-]+\/poa$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (role !== 'hq') return json({ error: 'Only HQ can set POA status' }, 403);
      try {
        const body = await request.json();
        const { id, hasPOA } = body;
        if (!id) return json({ error: 'Contact id required' }, 400);
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        const contact = contacts.find(c => c.id === id);
        if (!contact) return json({ error: 'Contact not found' }, 404);
        contact.hasPOA = !!hasPOA;
        await env.KEN_KV.put(`contactlist:${deviceId}`, JSON.stringify(contacts));
        await logAudit(env, deviceId, auth.user.email, hasPOA ? 'Set POA on contact' : 'Removed POA from contact', { contactName: contact.name });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Set POA on a user login profile (HQ only)
    // ===== PROFILE EDIT =====
    if (request.method === 'POST' && path === '/api/auth/profile') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        if (body.name !== undefined) auth.user.name = sanitize(body.name);
        if (body.phone !== undefined) auth.user.phone = sanitize(body.phone);
        if (body.photo !== undefined) {
          if (body.photo && body.photo.length > MAX_PHOTO_BASE64 * 1.4) return json({ error: 'Photo too large' }, 400);
          auth.user.photo = body.photo;
        }
        await saveUserDual(env, auth.user.email, auth.user);
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== ADD DEVICE TO EXISTING ACCOUNT =====
    if (request.method === 'POST' && path === '/api/auth/add-device') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const { deviceId } = body;
        if (!deviceId) return json({ error: 'deviceId required' }, 400);
        // Check device exists
        const device = await env.KEN_KV.get(`device:${deviceId}`, 'json');
        if (!device) {
          // Register the device if it doesn't exist yet
          await env.KEN_KV.put(`device:${deviceId}`, JSON.stringify({ deviceId, createdAt: new Date().toISOString() }));
          const devices = await env.KEN_KV.get('devices:all', 'json') || [];
          if (!devices.includes(deviceId)) { devices.push(deviceId); await env.KEN_KV.put('devices:all', JSON.stringify(devices)); }
        }
        // Check for invite
        const invite = await env.KEN_KV.get(`invite:${deviceId}:${auth.user.email}`, 'json');
        const role = invite ? invite.role : 'standard';
        if (invite) await env.KEN_KV.delete(`invite:${deviceId}:${auth.user.email}`);
        // Add device to user
        if (!auth.user.devices) auth.user.devices = {};
        if (auth.user.devices[deviceId]) return json({ error: 'Device already linked to your account' }, 400);
        auth.user.devices[deviceId] = { role };
        await saveUserDual(env, auth.user.email, auth.user);
        await logAudit(env, deviceId, auth.user.email, 'Device added to account', { role });
        return json({ success: true, deviceId, role });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== SUBSCRIPTION PREFERENCES =====
    if (request.method === 'POST' && path === '/api/auth/subscriptions') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const { key, enabled } = body;
        const validKeys = ['emailNotifications', 'birthdayReminders', 'productUpdates'];
        if (!validKeys.includes(key)) return json({ error: 'Invalid subscription key' }, 400);
        if (!auth.user.subscriptions) auth.user.subscriptions = {};
        auth.user.subscriptions[key] = { enabled: !!enabled, updatedAt: new Date().toISOString() };
        await saveUserDual(env, auth.user.email, auth.user);
        return json({ success: true, subscriptions: auth.user.subscriptions });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    if (request.method === 'POST' && path === '/api/auth/poa') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'Only HQ can set POA status' }, 403);
      try {
        const body = await request.json();
        const { email, hasPOA, deviceId } = body;
        if (!email) return json({ error: 'Email required' }, 400);
        const targetUser = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (!targetUser) return json({ error: 'User not found' }, 404);
        targetUser.poa = !!hasPOA;
        await saveUserDual(env, email, targetUser);
        if (deviceId) await logAudit(env, deviceId, auth.user.email, hasPOA ? 'Granted POA to user' : 'Revoked POA from user', { targetEmail: email });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Get emergency contacts for a device (requires device key — Pi has it for offline cache)
    if (request.method === 'GET' && path.match(/^\/api\/contacts\/[\w-]+\/emergency$/)) {
      const deviceId = path.split('/')[3];
      const emDeviceKey = request.headers.get('X-Ken-Device-Key');
      const emIsDeviceAuthed = await verifyDeviceKey(env, deviceId, emDeviceKey);
      if (!emIsDeviceAuthed) {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.response;
      }
      const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
      const emergency = contacts.filter(c => c.isEmergencyContact);
      return json({ contacts: emergency });
    }

    // ===== MEDICAL INFO =====
    if (request.method === 'GET' && path.match(/^\/api\/medical\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      // Check if device-key authenticated (Pi has full access)
      const medDeviceKey = request.headers.get('X-Ken-Device-Key');
      const medIsDeviceAuthed = await verifyDeviceKey(env, deviceId, medDeviceKey);
      if (!medIsDeviceAuthed) {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.response;
        const userRole = getUserRole(auth.user, deviceId);
        if (!hasPermission(userRole, 'view:medical')) return json({ error: 'Insufficient permissions' }, 403);
      }
      const raw = await env.KEN_KV.get(`medical:${deviceId}`, 'json') || { gp: {}, medications: [], allergies: [], conditions: [], careNotes: '' };
      const medical = await decryptObject(env, raw, SENSITIVE_FIELDS);
      return json(medical);
    }

    if (request.method === 'POST' && path.match(/^\/api\/medical\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (!hasPermission(role, 'edit:medical')) return json({ error: 'No permission to edit medical info' }, 403);
      try {
        const body = await request.json();
        const existing = await env.KEN_KV.get(`medical:${deviceId}`, 'json') || { gp: {}, medications: [], allergies: [], conditions: [], careNotes: '' };
        if (body.gp !== undefined) existing.gp = body.gp;
        if (body.medications !== undefined) existing.medications = body.medications;
        if (body.allergies !== undefined) existing.allergies = body.allergies;
        if (body.conditions !== undefined) existing.conditions = body.conditions;
        existing.updatedAt = new Date().toISOString();
        existing.updatedBy = auth.user.email;
        const encrypted = await encryptObject(env, existing, SENSITIVE_FIELDS);
        await env.KEN_KV.put(`medical:${deviceId}`, JSON.stringify(encrypted));
        await logAudit(env, deviceId, auth.user.email, 'Updated medical info', { fields: Object.keys(body).filter(k => body[k] !== undefined) });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Care notes diary (append-only log — carers add entries, others view)
    if (request.method === 'POST' && path.match(/^\/api\/medical\/[\w-]+\/care-notes$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (!hasPermission(role, 'edit:care_notes')) return json({ error: 'Only carers can edit care notes' }, 403);
      try {
        const body = await request.json();
        const existing = await env.KEN_KV.get(`medical:${deviceId}`, 'json') || { gp: {}, medications: [], allergies: [], conditions: [], careNotes: '', careNotesLog: [] };
        // Migrate legacy string careNotes to diary array
        if (!existing.careNotesLog) existing.careNotesLog = [];
        if (typeof existing.careNotes === 'string' && existing.careNotes.trim()) {
          existing.careNotesLog.unshift({ text: existing.careNotes, author: existing.careNotesUpdatedBy || 'Unknown', timestamp: existing.careNotesUpdatedAt || new Date().toISOString() });
        }
        // Append new entry
        const newNote = sanitize(body.careNotes || body.text || '');
        if (newNote) {
          existing.careNotesLog.unshift({ id: crypto.randomUUID(), text: newNote, author: auth.user.name || auth.user.email, authorEmail: auth.user.email, timestamp: new Date().toISOString() });
          // Keep last 200 entries
          if (existing.careNotesLog.length > 200) existing.careNotesLog = existing.careNotesLog.slice(0, 200);
        }
        existing.careNotes = newNote; // Keep latest for backward compat
        existing.careNotesUpdatedAt = new Date().toISOString();
        existing.careNotesUpdatedBy = auth.user.email;
        const encMedical = await encryptObject(env, existing, SENSITIVE_FIELDS);
        await env.KEN_KV.put(`medical:${deviceId}`, JSON.stringify(encMedical));
        await logAudit(env, deviceId, auth.user.email, 'Added care note', { preview: newNote.slice(0, 50) });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // ===== CARER ENDPOINTS =====
    if (request.method === 'GET' && path === '/api/carer/devices') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'carer') return json({ error: 'Carer role required' }, 403);
      const deviceIds = auth.user.carerDevices || [];
      const devices = [];
      for (const did of deviceIds) {
        const info = await env.KEN_KV.get(`device:${did}`, 'json') || {};
        const heartbeat = await env.KEN_KV.get(`heartbeat:${did}`, 'json');
        const contacts = await env.KEN_KV.get(`contactlist:${did}`, 'json') || [];
        devices.push({
          deviceId: did,
          userName: info.userName || 'Unknown',
          lastActive: heartbeat ? heartbeat.timestamp : null,
          online: heartbeat ? (Date.now() - new Date(heartbeat.timestamp).getTime() < 360000) : false,
          contactCount: contacts.length,
        });
      }
      return json({ devices });
    }

    if (request.method === 'POST' && path === '/api/carer/profile') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'carer') return json({ error: 'Carer role required' }, 403);
      try {
        const body = await request.json();
        auth.user.carerProfile = {
          professionalTitle: (body.professionalTitle || '').trim(),
          organisation: (body.organisation || '').trim(),
          registrationNumber: (body.registrationNumber || '').trim(),
        };
        await saveUserDual(env, auth.user.email, auth.user);
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Patient details (carer-specific per device)
    if (request.method === 'POST' && path.match(/^\/api\/carer\/patient\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (role !== 'carer' && role !== 'admin') return json({ error: 'Carer or admin access required' }, 403);
      try {
        const body = await request.json();
        const key = `patient:${deviceId}`;
        const existing = await env.KEN_KV.get(key, 'json') || {};
        const patient = {
          ...existing,
          patientNumber: body.patientNumber !== undefined ? sanitize(body.patientNumber) : existing.patientNumber,
          fullName: body.fullName !== undefined ? sanitize(body.fullName) : existing.fullName,
          location: body.location !== undefined ? sanitize(body.location) : existing.location,
          dob: body.dob !== undefined ? sanitize(body.dob) : existing.dob,
          nextOfKin: body.nextOfKin !== undefined ? sanitize(body.nextOfKin) : existing.nextOfKin,
          preferredHospital: body.preferredHospital !== undefined ? sanitize(body.preferredHospital) : existing.preferredHospital,
          nhsNumber: body.nhsNumber !== undefined ? sanitize(body.nhsNumber) : existing.nhsNumber,
          communicationNotes: body.communicationNotes !== undefined ? sanitize(body.communicationNotes) : existing.communicationNotes,
          mobilityLevel: body.mobilityLevel !== undefined ? sanitize(body.mobilityLevel) : existing.mobilityLevel,
          keySafeCode: body.keySafeCode !== undefined ? sanitize(body.keySafeCode) : existing.keySafeCode,
          updatedAt: new Date().toISOString(),
          updatedBy: auth.user.email,
        };
        const encPatient = await encryptObject(env, patient, SENSITIVE_FIELDS);
        await env.KEN_KV.put(key, JSON.stringify(encPatient));
        await logAudit(env, deviceId, auth.user.email, 'Updated patient details', {});
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/carer\/patient\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (userRole !== 'carer' && userRole !== 'admin') return json({ error: 'Carer or admin access required' }, 403);
      const rawPatient = await env.KEN_KV.get(`patient:${deviceId}`, 'json') || {};
      const patient = await decryptObject(env, rawPatient, SENSITIVE_FIELDS);
      return json(patient);
    }

    // Carer inactivity alert settings per device
    if (request.method === 'POST' && path.match(/^\/api\/carer\/alerts\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (role !== 'carer' && role !== 'admin') return json({ error: 'Carer or admin access required' }, 403);
      try {
        const body = await request.json();
        const alerts = {
          enabled: body.enabled !== undefined ? !!body.enabled : true,
          thresholdMinutes: body.thresholdMinutes || 60,
          outsideNightlightOnly: body.outsideNightlightOnly !== undefined ? !!body.outsideNightlightOnly : true,
          method: body.method || ['email'],
          updatedAt: new Date().toISOString(),
          updatedBy: auth.user.email,
        };
        await env.KEN_KV.put(`carer-alerts:${deviceId}:${auth.user.email}`, JSON.stringify(alerts));
        await logAudit(env, deviceId, auth.user.email, 'Updated inactivity alert settings', { enabled: alerts.enabled, threshold: alerts.thresholdMinutes });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/carer\/alerts\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (userRole !== 'carer' && userRole !== 'admin') return json({ error: 'Carer or admin access required' }, 403);
      const alerts = await env.KEN_KV.get(`carer-alerts:${deviceId}:${auth.user.email}`, 'json') || { enabled: true, thresholdMinutes: 60, outsideNightlightOnly: true, method: ['email'] };
      return json(alerts);
    }

    // ===== HQ ENDPOINTS =====
    if (request.method === 'GET' && path === '/api/hq/devices') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ role required' }, 403);
      const allDevices = await env.KEN_KV.get('devices:all', 'json') || [];
      const devices = [];
      for (const did of allDevices) {
        const info = await env.KEN_KV.get(`device:${did}`, 'json') || {};
        const heartbeat = await env.KEN_KV.get(`heartbeat:${did}`, 'json');
        const online = heartbeat ? (Date.now() - new Date(heartbeat.lastSeen || heartbeat.timestamp).getTime() < 360000) : false;
        // Fetch alert counts for traffic light status
        const medAlerts = await env.KEN_KV.get(`med-alerts:${did}`, 'json') || [];
        const unresolvedAlerts = medAlerts.filter(a => !a.resolved).length;
        const history = await env.KEN_KV.get(`history:${did}`, 'json') || [];
        const unreadMessages = history.filter(m => m.isReply && !m.readAt && !m.deletedForEveryone).length;
        // Determine status: green (ok), amber (offline or minor), gold (needs attention)
        let status = 'green';
        if (!online) status = 'amber';
        if (unresolvedAlerts > 0) status = 'gold';
        devices.push({
          deviceId: did, userName: info.userName || 'Unknown',
          lastActive: heartbeat ? (heartbeat.lastSeen || heartbeat.timestamp) : null,
          online, status, unresolvedAlerts, unreadMessages,
        });
      }
      const totalOnline = devices.filter(d => d.online).length;
      const totalAlerts = devices.reduce((sum, d) => sum + d.unresolvedAlerts, 0);
      return json({ devices, summary: { total: devices.length, online: totalOnline, alerts: totalAlerts } });
    }

    // HQ: Get users with access to a specific device
    if (request.method === 'GET' && path.match(/^\/api\/hq\/device\/[\w-]+\/users$/)) {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ role required' }, 403);
      const deviceId = path.split('/')[4];
      const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
      const users = [];
      for (const key of allUsers.keys) {
        try {
          const u = await env.KEN_KV.get(key.name, 'json');
          if (!u || !u.devices || !u.devices[deviceId]) continue;
          users.push({
            name: u.name || '',
            email: u.email || '',
            role: u.devices[deviceId].role || u.globalRole || 'user',
            lastLogin: u.lastLogin || null,
          });
        } catch {}
      }
      users.sort((a, b) => {
        const order = { admin: 0, carer: 1, hq: 2, standard: 3, user: 4 };
        return (order[a.role] ?? 5) - (order[b.role] ?? 5);
      });
      return json({ users, deviceId });
    }

    // HQ broadcast message to all devices
    if (request.method === 'POST' && path === '/api/hq/broadcast') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ role required' }, 403);
      try {
        const body = await request.json();
        const { text } = body;
        if (!text || !text.trim()) return json({ error: 'Message text required' }, 400);
        const allDevices = await env.KEN_KV.get('devices:all', 'json') || [];
        let sent = 0;
        for (const did of allDevices) {
          const message = {
            id: crypto.randomUUID(),
            from: auth.user.name || 'The Ken HQ',
            fromEmail: auth.user.email,
            text: sanitize(text),
            sentAt: new Date().toISOString(),
            deliveredAt: null, readAt: null,
            isSystemBroadcast: true,
            deletedBySender: false, deletedByRecipient: false, deletedForEveryone: false,
            emailNotificationSent: false,
          };
          const pending = await env.KEN_KV.get(`messages:${did}`, 'json') || [];
          pending.push(message);
          await env.KEN_KV.put(`messages:${did}`, JSON.stringify(pending));
          const history = await env.KEN_KV.get(`history:${did}`, 'json') || [];
          history.push(message);
          if (history.length > 100) history.splice(0, history.length - 100);
          await env.KEN_KV.put(`history:${did}`, JSON.stringify(history));
          sent++;
        }
        await logAudit(env, allDevices[0] || 'system', auth.user.email, 'HQ broadcast sent', { text: text.slice(0, 50), deviceCount: sent });
        return json({ success: true, deviceCount: sent });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // HQ request access to private content
    if (request.method === 'POST' && path.match(/^\/api\/hq\/request-access\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ role required' }, 403);
      try {
        const body = await request.json();
        const { contentType, reason } = body;
        if (!contentType || !reason) return json({ error: 'contentType and reason required' }, 400);
        if (!['messages', 'voicemail'].includes(contentType)) return json({ error: 'contentType must be messages or voicemail' }, 400);
        const rid = crypto.randomUUID();
        const accessRequest = {
          id: rid, hqEmail: auth.user.email, hqName: auth.user.name,
          deviceId, contentType, reason: reason.trim(),
          status: 'pending', requestedAt: new Date().toISOString(),
        };
        const requests = await env.KEN_KV.get(`hq-access-requests:${deviceId}`, 'json') || [];
        requests.push(accessRequest);
        await env.KEN_KV.put(`hq-access-requests:${deviceId}`, JSON.stringify(requests));
        await logAudit(env, deviceId, auth.user.email, 'HQ requested access', { contentType, reason: reason.trim() });
        // Email admin/carer users for this device so they can approve
        const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
        for (const key of allUsers.keys) {
          try {
            const u = await env.KEN_KV.get(key.name, 'json');
            if (!u || !u.devices || !u.devices[deviceId]) continue;
            const uRole = u.devices[deviceId].role;
            if (uRole === 'admin' || uRole === 'carer' || u.poa) {
              await sendEmail(env, u.email,
                'Access request from HQ \u2014 The Ken',
                'HQ access request',
                '<p style="color:#6B6459;line-height:1.7;"><strong>' + (auth.user.name || auth.user.email) + '</strong> (HQ) is requesting access to <strong>' + contentType + '</strong>.</p>' +
                '<p style="color:#6B6459;line-height:1.7;">Reason: ' + reason.trim() + '</p>' +
                '<a href="https://theken.uk/portal/" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Review Request</a>' +
                '<p style="color:#6B6459;font-size:13px;margin-top:16px;">Once approved, HQ will have time-limited access to the requested content.</p>'
              );
            }
          } catch {}
        }
        return json({ success: true, requestId: rid });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Approve HQ access request
    if (request.method === 'POST' && path.match(/^\/api\/hq\/approve-access\/[\w-]+$/)) {
      const requestId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const { deviceId, approved, durationHours } = body;
        if (!deviceId) return json({ error: 'deviceId required' }, 400);
        const role = getUserRole(auth.user, deviceId);
        if (role !== 'admin' && role !== 'carer' && !auth.user.poa) {
          return json({ error: 'Admin, carer or POA holder required to approve' }, 403);
        }
        const requests = await env.KEN_KV.get(`hq-access-requests:${deviceId}`, 'json') || [];
        const req_item = requests.find(r => r.id === requestId);
        if (!req_item) return json({ error: 'Request not found' }, 404);
        req_item.status = approved ? 'approved' : 'denied';
        req_item.approvedBy = auth.user.email;
        req_item.approvedAt = new Date().toISOString();
        if (approved) {
          const hours = durationHours || 1;
          req_item.expiresAt = new Date(Date.now() + hours * 3600000).toISOString();
          await env.KEN_KV.put(`hq-access:${deviceId}:${req_item.hqEmail}:${req_item.contentType}`, JSON.stringify({
            grantedAt: req_item.approvedAt, expiresAt: req_item.expiresAt, approvedBy: auth.user.email,
          }), { expirationTtl: hours * 3600 });
        }
        await env.KEN_KV.put(`hq-access-requests:${deviceId}`, JSON.stringify(requests));
        await logAudit(env, deviceId, auth.user.email, approved ? 'Approved HQ access' : 'Denied HQ access', { requestId, contentType: req_item.contentType, hqEmail: req_item.hqEmail });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Check HQ access status
    if (request.method === 'GET' && path.match(/^\/api\/hq\/access-status\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (userRole !== 'hq') return json({ error: 'HQ role required' }, 403);
      const msgAccess = await env.KEN_KV.get(`hq-access:${deviceId}:${auth.user.email}:messages`, 'json');
      const vmAccess = await env.KEN_KV.get(`hq-access:${deviceId}:${auth.user.email}:voicemail`, 'json');
      return json({
        messages: msgAccess ? { granted: true, expiresAt: msgAccess.expiresAt } : { granted: false },
        voicemail: vmAccess ? { granted: true, expiresAt: vmAccess.expiresAt } : { granted: false },
      });
    }

    // Get pending HQ access requests (for admin/carer)
    if (request.method === 'GET' && path.match(/^\/api\/hq\/pending-requests\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (role !== 'admin' && role !== 'carer') return json({ error: 'Admin or carer required' }, 403);
      const requests = await env.KEN_KV.get(`hq-access-requests:${deviceId}`, 'json') || [];
      const pending = requests.filter(r => r.status === 'pending');
      return json({ requests: pending });
    }

    // ===== SCREEN VIEWING (HQ Remote View) =====

    // HQ starts screen viewing session
    if (request.method === 'POST' && path.match(/^\/api\/screen\/[\w-]+\/start$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const perm = requirePermission(auth.user, deviceId, 'remote:view_pi');
      if (!perm.allowed) return json({ error: 'HQ role required for screen viewing' }, 403);
      await env.KEN_KV.put(`screen:active:${deviceId}`, JSON.stringify({
        requestedBy: auth.user.email,
        requestedByName: auth.user.name,
        startedAt: new Date().toISOString(),
      }), { expirationTtl: 3600 });
      await logAudit(env, deviceId, auth.user.email, 'Screen viewing started', {});
      return json({ success: true });
    }

    // HQ stops screen viewing session
    if (request.method === 'POST' && path.match(/^\/api\/screen\/[\w-]+\/stop$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'remote:view_pi')) return json({ error: 'HQ role required for screen viewing' }, 403);
      await env.KEN_KV.delete(`screen:active:${deviceId}`);
      await env.KEN_KV.delete(`screen:frame:${deviceId}`);
      await logAudit(env, deviceId, auth.user.email, 'Screen viewing stopped', {});
      return json({ success: true });
    }

    // Pi checks if screen viewing is requested (polls this)
    if (request.method === 'GET' && path.match(/^\/api\/screen\/[\w-]+\/status$/)) {
      const deviceId = path.split('/')[3];
      // Check if device-key authenticated (Pi has full access)
      const screenDeviceKey = request.headers.get('X-Ken-Device-Key');
      const screenIsDeviceAuthed = await verifyDeviceKey(env, deviceId, screenDeviceKey);
      if (!screenIsDeviceAuthed) {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.response;
      }
      const active = await env.KEN_KV.get(`screen:active:${deviceId}`, 'json');
      return json({ active: !!active, ...(active || {}) });
    }

    // Pi uploads a screen frame (JPEG base64)
    if (request.method === 'POST' && path.match(/^\/api\/screen\/[\w-]+\/frame$/)) {
      const deviceId = path.split('/')[3];
      const active = await env.KEN_KV.get(`screen:active:${deviceId}`);
      if (!active) return json({ error: 'Streaming not active' }, 400);
      try {
        const body = await request.json();
        if (!body.frame) return json({ error: 'frame required' }, 400);
        if (body.frame.length > MAX_SCREENSHOT_BASE64 * 1.4) return json({ error: 'Frame too large (max 200KB)' }, 400);
        await env.KEN_KV.put(`screen:frame:${deviceId}`, body.frame, { expirationTtl: 30 });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Portal gets latest screen frame
    if (request.method === 'GET' && path.match(/^\/api\/screen\/[\w-]+\/frame$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const perm = requirePermission(auth.user, deviceId, 'remote:view_pi');
      if (!perm.allowed) return json({ error: 'HQ role required' }, 403);
      const frame = await env.KEN_KV.get(`screen:frame:${deviceId}`);
      if (!frame) return json({ frame: null, status: 'waiting' });
      return json({ frame, status: 'streaming' });
    }

    // ===== SCHEDULED VOICEMAIL =====
    if (request.method === 'POST' && path.match(/^\/api\/voicemail\/[\w-]+\/schedule$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const { voicemailId, scheduledFor } = body;
        if (!voicemailId || !scheduledFor) return json({ error: 'voicemailId and scheduledFor required' }, 400);
        const scheduled = await env.KEN_KV.get(`scheduled-vm:${deviceId}`, 'json') || [];
        scheduled.push({
          id: crypto.randomUUID(), voicemailId,
          from: auth.user.name || auth.user.email, fromEmail: auth.user.email,
          scheduledFor, status: 'scheduled', createdAt: new Date().toISOString(),
        });
        await env.KEN_KV.put(`scheduled-vm:${deviceId}`, JSON.stringify(scheduled));
        await logAudit(env, deviceId, auth.user.email, 'Scheduled voicemail', { scheduledFor });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/voicemail\/[\w-]+\/scheduled$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const scheduled = await env.KEN_KV.get(`scheduled-vm:${deviceId}`, 'json') || [];
      const mine = scheduled.filter(s => s.fromEmail === auth.user.email);
      return json({ scheduled: mine });
    }

    if (request.method === 'DELETE' && path.match(/^\/api\/voicemail\/[\w-]+\/scheduled\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const schedId = parts[5];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const scheduled = await env.KEN_KV.get(`scheduled-vm:${deviceId}`, 'json') || [];
      const filtered = scheduled.filter(s => !(s.id === schedId && s.fromEmail === auth.user.email));
      await env.KEN_KV.put(`scheduled-vm:${deviceId}`, JSON.stringify(filtered));
      await logAudit(env, deviceId, auth.user.email, 'Deleted scheduled voicemail', { schedId });
      return json({ success: true });
    }

    // ===== REMOTE MEDICATION REMINDERS =====
    if (request.method === 'POST' && path.match(/^\/api\/reminders\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (!hasPermission(role, 'edit:reminders')) return json({ error: 'Admin or carer access required' }, 403);
      try {
        const body = await request.json();
        const reminders = await env.KEN_KV.get(`reminders:${deviceId}`, 'json') || [];
        const reminder = {
          id: crypto.randomUUID(),
          label: sanitize(body.label || body.medicationName || ''),
          medicationName: sanitize(body.medicationName || body.label || ''),
          dosage: sanitize(body.dosage || ''),
          instructions: sanitize(body.instructions || ''),
          photo: body.photo || '',
          time: body.time,
          days: body.days || ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'],
          frequency: body.frequency || 'daily',
          startDate: body.startDate || null,
          endDate: body.endDate || null,
          enabled: true,
          createdBy: auth.user.email,
          createdAt: new Date().toISOString(),
        };
        reminders.push(reminder);
        await env.KEN_KV.put(`reminders:${deviceId}`, JSON.stringify(reminders));
        await logAudit(env, deviceId, auth.user.email, 'Added reminder', { label: reminder.label, time: reminder.time });
        return json({ success: true, reminder });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/reminders\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const reminders = await env.KEN_KV.get(`reminders:${deviceId}`, 'json') || [];
      return json({ reminders });
    }

    if (request.method === 'DELETE' && path.match(/^\/api\/reminders\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const reminderId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (!hasPermission(role, 'edit:reminders')) return json({ error: 'Admin or carer access required' }, 403);
      const reminders = await env.KEN_KV.get(`reminders:${deviceId}`, 'json') || [];
      const filtered = reminders.filter(r => r.id !== reminderId);
      await env.KEN_KV.put(`reminders:${deviceId}`, JSON.stringify(filtered));
      await logAudit(env, deviceId, auth.user.email, 'Deleted reminder', { reminderId });
      return json({ success: true });
    }

    // ===== DEVICE INFO =====
    if (request.method === 'POST' && path.match(/^\/api\/device\/[\w-]+$/) && path !== '/api/device/migrate-id') {
      const deviceId = path.split('/')[3];
      // SECURITY: require device key or admin/carer/hq session
      const devInfoKey = request.headers.get('X-Ken-Device-Key');
      if (!(await verifyDeviceKey(env, deviceId, devInfoKey))) {
        const auth = await requireAdmin(request, env, deviceId);
        if (auth.error) return auth.response;
      }
      try {
        const body = await request.json();
        await env.KEN_KV.put(`device:${deviceId}`, JSON.stringify(body));
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/device\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const info = await env.KEN_KV.get(`device:${deviceId}`, 'json');
      return json(info || { userName: 'The Ken' });
    }

    // ===== DEVICE ID MIGRATION (UUID → short format) =====
    if (request.method === 'POST' && path === '/api/device/migrate-id') {
      try {
        const body = await request.json();
        const { oldId, newId } = body;
        if (!oldId || !newId) return json({ error: 'oldId and newId required' }, 400);
        if (!/^[A-Z]\d{5}$/.test(newId)) return json({ error: 'newId must be format A12345' }, 400);
        // Require device key auth
        const hasKey = await env.KEN_KV.get(`device-key:${oldId}`);
        if (!hasKey) return json({ error: 'Unknown device' }, 404);
        const providedKey = request.headers.get('X-Ken-Device-Key');
        const verified = await verifyDeviceKey(env, oldId, providedKey);
        if (!verified) return json({ error: 'Device authentication required' }, 401);
        // Check new ID isn't taken
        const existingNew = await env.KEN_KV.get(`device:${newId}`, 'json');
        if (existingNew) return json({ error: 'New device ID already in use' }, 409);
        // Migrate all KV keys
        const prefixes = [
          'device:', 'device-key:', 'heartbeat:', 'heartbeat-time:',
          'messages:', 'history:', 'contacts:', 'settings:',
          'med-alerts:', 'medical:', 'reminders:', 'voicemails:',
          'offline-alerts:', 'screen:', 'hq-access-requests:',
          'feedback:', 'notifications:', 'call-history:', 'export:',
          'groups:', 'birthday-config:', 'group-call:',
        ];
        for (const prefix of prefixes) {
          const val = await env.KEN_KV.get(`${prefix}${oldId}`);
          if (val !== null) {
            await env.KEN_KV.put(`${prefix}${newId}`, val);
            await env.KEN_KV.delete(`${prefix}${oldId}`);
          }
        }
        // Update devices:all list
        const devices = await env.KEN_KV.get('devices:all', 'json') || [];
        const idx = devices.indexOf(oldId);
        if (idx !== -1) { devices[idx] = newId; } else { devices.push(newId); }
        await env.KEN_KV.put('devices:all', JSON.stringify(devices));
        // Update all users who had this device
        const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
        for (const key of allUsers.keys) {
          try {
            const u = await env.KEN_KV.get(key.name, 'json');
            if (!u || !u.devices || !u.devices[oldId]) continue;
            u.devices[newId] = u.devices[oldId];
            delete u.devices[oldId];
            await env.KEN_KV.put(key.name, JSON.stringify(u));
          } catch {}
        }
        await logAudit(env, newId, 'system', 'Device ID migrated', { oldId, newId });
        return json({ success: true, oldId, newId });
      } catch (e) { return json({ error: 'Migration failed: ' + e.message }, 500); }
    }

    // ===== HEARTBEAT =====
    // Secured: if device already has a key, require it. First heartbeat generates key.
    if (request.method === 'POST' && path.match(/^\/api\/heartbeat\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const now = new Date().toISOString();
      const hasStoredKey = await env.KEN_KV.get(`device-key:${deviceId}`);
      // If device key exists, require it in the request (prevents impersonation)
      if (hasStoredKey) {
        const providedKey = request.headers.get('X-Ken-Device-Key');
        const verified = await verifyDeviceKey(env, deviceId, providedKey);
        if (!verified) {
          return json({ error: 'Device authentication required' }, 401);
        }
      } else {
        // First heartbeat — require a valid one-time provision token
        const provisionToken = request.headers.get('X-Ken-Provision-Token');
        if (!provisionToken) {
          return json({ error: 'Provision token required for new device registration. Generate one via POST /api/admin/provision-token (HQ role).' }, 403);
        }
        const tokenData = await env.KEN_KV.get(`provision-token:${provisionToken}`, 'json');
        if (!tokenData) {
          return json({ error: 'Invalid or expired provision token' }, 403);
        }
        // Consume the token (one-time use)
        await env.KEN_KV.delete(`provision-token:${provisionToken}`);
      }
      // Generate key for new devices (first heartbeat)
      let returnKey = null;
      if (!hasStoredKey) {
        const newKey = crypto.randomUUID() + '-' + crypto.randomUUID();
        await storeDeviceKey(env, deviceId, newKey);
        await logAudit(env, deviceId, 'system', 'Device provisioned via token', {});
        returnKey = newKey;
      }
      // Heartbeat with lastSeen (TTL 600s = 10 min window with 5 min poll)
      await env.KEN_KV.put(`heartbeat:${deviceId}`, JSON.stringify({ online: true, lastSeen: now }), { expirationTtl: 600 });
      await env.KEN_KV.put(`heartbeat-time:${deviceId}`, now);
      // Register device only if not already known
      const devices = await env.KEN_KV.get('devices:all', 'json') || [];
      if (!devices.includes(deviceId)) {
        devices.push(deviceId);
        await env.KEN_KV.put('devices:all', JSON.stringify(devices));
      }
      return json({ success: true, deviceKey: returnKey });
    }

    // Separate endpoint for queue/alert processing (Pi calls this less frequently)
    if (request.method === 'POST' && path.match(/^\/api\/heartbeat\/[\w-]+\/sync$/)) {
      const deviceId = path.split('/')[3];
      // Clear offline alerts
      const alertSettings = await env.KEN_KV.get(`offline-alerts:${deviceId}`, 'json');
      if (alertSettings && alertSettings.lastAlertSent) {
        alertSettings.lastAlertSent = null;
        await env.KEN_KV.put(`offline-alerts:${deviceId}`, JSON.stringify(alertSettings));
      }
      // Process settings queue
      const queue = await env.KEN_KV.get(`queue:${deviceId}`, 'json') || [];
      if (queue.length > 0) {
        for (const item of queue) {
          if (item.setting && item.value !== undefined) {
            const settings = await env.KEN_KV.get(`settings:${deviceId}`, 'json') || {};
            settings[item.setting] = item.value;
            await env.KEN_KV.put(`settings:${deviceId}`, JSON.stringify(settings));
          }
        }
        await env.KEN_KV.delete(`queue:${deviceId}`);
      }
      return json({ success: true, queueApplied: queue.length > 0, queueCount: queue.length });
    }

    if (request.method === 'GET' && path.match(/^\/api\/heartbeat\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const hb = await env.KEN_KV.get(`heartbeat:${deviceId}`, 'json');
      return json({ online: !!hb, lastSeen: hb ? hb.lastSeen : null });
    }

    // ===== OFFLINE ALERT SETTINGS =====
    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/offline-alerts$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'edit:settings')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const settings = {
          enabled: !!body.enabled,
          delayMinutes: body.delayMinutes || 10,
          contactNames: body.contactNames || [],
          lastAlertSent: body.lastAlertSent || null
        };
        await env.KEN_KV.put(`offline-alerts:${deviceId}`, JSON.stringify(settings));
        const session = await getSession(request, env);
        await logAudit(env, deviceId, session ? session.email : 'device', 'Updated offline alert settings', settings);
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/settings\/[\w-]+\/offline-alerts$/)) {
      const deviceId = path.split('/')[3];
      const settings = await env.KEN_KV.get(`offline-alerts:${deviceId}`, 'json');
      return json(settings || { enabled: false, delayMinutes: 10, contactNames: [], lastAlertSent: null });
    }

    // ===== CHECK OFFLINE STATUS =====
    if (request.method === 'GET' && path.match(/^\/api\/check-offline\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const hb = await env.KEN_KV.get(`heartbeat:${deviceId}`, 'json');
      if (hb) {
        return json({ offline: false, shouldAlert: false });
      }
      const lastTime = await env.KEN_KV.get(`heartbeat-time:${deviceId}`);
      if (!lastTime) {
        return json({ offline: true, shouldAlert: false, reason: 'no heartbeat recorded' });
      }
      const offlineMs = Date.now() - new Date(lastTime).getTime();
      const offlineMinutes = Math.floor(offlineMs / 60000);
      const alertSettings = await env.KEN_KV.get(`offline-alerts:${deviceId}`, 'json');
      if (!alertSettings || !alertSettings.enabled) {
        return json({ offline: true, offlineMinutes, shouldAlert: false, reason: 'alerts disabled' });
      }
      if (offlineMinutes < alertSettings.delayMinutes) {
        return json({ offline: true, offlineMinutes, shouldAlert: false, reason: 'delay not reached' });
      }
      if (alertSettings.lastAlertSent) {
        return json({ offline: true, offlineMinutes, shouldAlert: false, reason: 'alert already sent' });
      }
      alertSettings.lastAlertSent = new Date().toISOString();
      await env.KEN_KV.put(`offline-alerts:${deviceId}`, JSON.stringify(alertSettings));
      return json({ offline: true, offlineMinutes, shouldAlert: true, contacts: alertSettings.contactNames });
    }

    // ===== SEND OFFLINE ALERT MESSAGES =====
    if (request.method === 'POST' && path.match(/^\/api\/offline-alert\/[\w-]+\/send$/)) {
      const deviceId = path.split('/')[3];
      try {
        const alertSettings = await env.KEN_KV.get(`offline-alerts:${deviceId}`, 'json');
        if (!alertSettings || !alertSettings.enabled || !alertSettings.contactNames.length) {
          return json({ error: 'No alert settings or contacts configured' }, 400);
        }
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || { userName: 'The Ken' };
        const deviceName = deviceInfo.userName || 'The Ken';
        const lastTime = await env.KEN_KV.get(`heartbeat-time:${deviceId}`);
        const offlineMinutes = lastTime ? Math.floor((Date.now() - new Date(lastTime).getTime()) / 60000) : 0;
        const alertText = deviceName + ' has been offline for ' + offlineMinutes + ' minutes. Please check the internet connection.';
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        let alertsSent = 0;
        for (const contactName of alertSettings.contactNames) {
          const contact = contacts.find(c => c.name === contactName);
          if (contact) {
            history.push({
              id: crypto.randomUUID(),
              from: 'System',
              text: alertText,
              sentAt: new Date().toISOString(),
              isSystemAlert: true,
              alertTo: contactName
            });
            alertsSent++;
          }
        }
        if (history.length > 100) history.splice(0, history.length - 100);
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        return json({ success: true, alertsSent });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // ===== CALL HISTORY =====
    if (request.method === 'POST' && path.match(/^\/api\/history\/[\w-]+\/calls$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        await env.KEN_KV.put(`callhistory:${deviceId}`, JSON.stringify(body));
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/history\/[\w-]+\/calls$/)) {
      const deviceId = path.split('/')[3];
      const history = await env.KEN_KV.get(`callhistory:${deviceId}`, 'json');
      return json(history || { calls: [] });
    }

    // ===== DO NOT DISTURB / SCHEDULE =====
    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      // Check if device-key authenticated (Pi has full access)
      const settingsDeviceKey = request.headers.get('X-Ken-Device-Key');
      const settingsIsDeviceAuthed = await verifyDeviceKey(env, deviceId, settingsDeviceKey);
      if (!settingsIsDeviceAuthed) {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.response;
        const userRole = getUserRole(auth.user, deviceId);
        if (!hasPermission(userRole, 'edit:settings')) return json({ error: 'Insufficient permissions' }, 403);
      }
      try {
        const body = await request.json();
        await env.KEN_KV.put(`settings:${deviceId}`, JSON.stringify(body));
        const session = await getSession(request, env);
        await logAudit(env, deviceId, session ? session.email : 'device', 'Updated device settings', body);
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/settings\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const settings = await env.KEN_KV.get(`settings:${deviceId}`, 'json');
      return json(settings || {
        dndEnabled: false,
        dndStart: '22:00',
        dndEnd: '08:00',
        nightlightEnabled: true,
        nightlightStart: '21:00',
        nightlightEnd: '07:00',
        nightlightBrightness: 20
      });
    }

    // (Duplicate reminder endpoints removed — handled by REMOTE MEDICATION REMINDERS section above)

    // Photos carousel feature removed — Ken is a connectivity device, not a picture frame.
    // Contact/user profile photos remain via the contacts and user profile endpoints.

    // ===== FEEDBACK =====
    if (request.method === 'POST' && path.match(/^\/api\/feedback\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const rl = await checkRateLimit(env, request, 'feedback', 5, 60);
      if (rl.limited) return json({ error: 'Too many submissions. Try again later.' }, 429);
      try {
        const body = await request.json();
        // Attach authenticated user identity if available
        const session = await getSession(request, env);
        if (session) {
          const user = await env.KEN_KV.get(`user:${session.email}`, 'json');
          if (user) {
            body.submittedBy = { email: user.email, name: user.name };
          }
        }
        if (body.text) body.text = sanitize(body.text);
        if (body.from) body.from = sanitize(body.from);
        if (body.category) body.category = sanitize(body.category);
        if (!body.timestamp) body.timestamp = new Date().toISOString();
        // Ticket system: assign id, status, and empty replies array
        body.id = crypto.randomUUID();
        body.status = 'open';
        body.replies = [];
        const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
        feedback.push(body);
        if (feedback.length > 100) feedback.splice(0, feedback.length - 100);
        await env.KEN_KV.put(`feedback:${deviceId}`, JSON.stringify(feedback));
        await logAudit(env, deviceId, session ? session.email : (body.from || 'device'), 'Submitted feedback', { type: body.type || 'text' });
        return json({ success: true, ticketId: body.id });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // ===== FEEDBACK TICKET ENDPOINTS =====
    // GET single ticket with replies
    if (request.method === 'GET' && path.match(/^\/api\/feedback\/[\w-]+\/[a-f0-9-]{36}$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const ticketId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
      const ticket = feedback.find(f => f.id === ticketId);
      if (!ticket) return json({ error: 'Ticket not found' }, 404);
      // HQ/admin see any ticket; others only their own
      if (!['admin', 'hq'].includes(userRole) && ticket.fromEmail !== auth.user.email) {
        return json({ error: 'Access denied' }, 403);
      }
      return json({ ticket });
    }

    // POST reply to a ticket
    if (request.method === 'POST' && path.match(/^\/api\/feedback\/[\w-]+\/[a-f0-9-]{36}\/reply$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const ticketId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
      const ticket = feedback.find(f => f.id === ticketId);
      if (!ticket) return json({ error: 'Ticket not found' }, 404);
      // HQ/admin can reply to any; others only their own
      if (!['admin', 'hq'].includes(userRole) && ticket.fromEmail !== auth.user.email) {
        return json({ error: 'Access denied' }, 403);
      }
      try {
        const body = await request.json();
        if (!body.text) return json({ error: 'Reply text is required' }, 400);
        const reply = {
          id: crypto.randomUUID(),
          from: auth.user.name || auth.user.email,
          fromEmail: auth.user.email,
          role: userRole || 'user',
          text: sanitize(body.text),
          image: body.image || null,
          timestamp: new Date().toISOString()
        };
        if (!ticket.replies) ticket.replies = [];
        ticket.replies.push(reply);
        await env.KEN_KV.put(`feedback:${deviceId}`, JSON.stringify(feedback));
        await logAudit(env, deviceId, auth.user.email, 'Replied to feedback ticket', { ticketId });
        return json({ success: true, reply });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // POST update ticket status (HQ/admin only)
    if (request.method === 'POST' && path.match(/^\/api\/feedback\/[\w-]+\/[a-f0-9-]{36}\/status$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const ticketId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!['admin', 'hq'].includes(userRole)) return json({ error: 'Admin or HQ access required' }, 403);
      const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
      const ticket = feedback.find(f => f.id === ticketId);
      if (!ticket) return json({ error: 'Ticket not found' }, 404);
      try {
        const body = await request.json();
        const validStatuses = ['open', 'in-progress', 'resolved', 'closed'];
        if (!body.status || !validStatuses.includes(body.status)) {
          return json({ error: 'Invalid status. Must be: ' + validStatuses.join(', ') }, 400);
        }
        ticket.status = body.status;
        await env.KEN_KV.put(`feedback:${deviceId}`, JSON.stringify(feedback));
        await logAudit(env, deviceId, auth.user.email, 'Updated feedback ticket status', { ticketId, status: body.status });
        return json({ success: true, status: ticket.status });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/feedback\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
      // HQ and admin see all; others see only their own
      if (!['admin', 'hq'].includes(userRole)) {
        const userFeedback = feedback.filter(f => f.fromEmail === auth.user.email);
        return json({ feedback: userFeedback });
      }
      return json({ feedback });
    }

    // ===== VOICEMAIL ENDPOINTS =====
    // Ken signals "send to voicemail"
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/voicemail$/)) {
      const deviceId = path.split('/')[3];
      // SECURITY: require device key or authenticated session
      const vmReqKey = request.headers.get('X-Ken-Device-Key');
      if (!(await verifyDeviceKey(env, deviceId, vmReqKey))) {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.response;
      }
      try {
        const body = await request.json();
        const { from } = body;
        await env.KEN_KV.put(`voicemail-req:${deviceId}`, JSON.stringify({ voicemailRequested: true, from: from || '' }), { expirationTtl: 120 });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Family portal polls for voicemail signal
    if (request.method === 'GET' && path.match(/^\/api\/calls\/[\w-]+\/voicemail$/)) {
      const deviceId = path.split('/')[3];
      const req = await env.KEN_KV.get(`voicemail-req:${deviceId}`, 'json');
      return json(req || { voicemailRequested: false });
    }

    // Store a voicemail recording
    if (request.method === 'POST' && path.match(/^\/api\/voicemail\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      // SECURITY: require device key or authenticated session with send:voicemail permission
      const vmStoreKey = request.headers.get('X-Ken-Device-Key');
      if (!(await verifyDeviceKey(env, deviceId, vmStoreKey))) {
        const auth = await requireAuth(request, env);
        if (auth.error) return auth.response;
        const vmRole = getUserRole(auth.user, deviceId);
        if (!hasPermission(vmRole, 'send:voicemail')) return json({ error: 'Insufficient permissions' }, 403);
      }
      try {
        const body = await request.json();
        const { from, type, media, duration, timestamp } = body;
        if (!from || !media) return json({ error: 'from and media required' }, 400);
        if (media.length > MAX_VOICEMAIL_BASE64 * 1.4) return json({ error: 'Voicemail too large (max 5MB)' }, 400);
        const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
        const vmId = crypto.randomUUID();
        const vmType = type || 'video';
        // If R2 binding exists, store media bytes in R2 and only metadata in KV
        if (env.KEN_MEDIA) {
          // Detect content type and extension from data URL or default by type
          let contentType = 'video/webm';
          let ext = 'webm';
          const dataUrlMatch = media.match(/^data:([^;]+);base64,/);
          if (dataUrlMatch) {
            contentType = dataUrlMatch[1];
            const extMap = { 'video/webm': 'webm', 'video/mp4': 'mp4', 'audio/webm': 'webm', 'audio/mp3': 'mp3', 'audio/mpeg': 'mp3', 'audio/ogg': 'ogg', 'audio/wav': 'wav' };
            ext = extMap[contentType] || contentType.split('/')[1] || 'bin';
          } else if (vmType === 'audio') {
            contentType = 'audio/webm';
          }
          const base64Data = media.replace(/^data:[^;]+;base64,/, '');
          const binaryStr = atob(base64Data);
          const bytes = new Uint8Array(binaryStr.length);
          for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
          const r2Key = `voicemails/${deviceId}/${vmId}.${ext}`;
          await env.KEN_MEDIA.put(r2Key, bytes.buffer, {
            httpMetadata: { contentType }
          });
          voicemails.push({
            id: vmId,
            from: from.trim(),
            type: vmType,
            r2Key,
            duration: duration || 0,
            timestamp: timestamp || new Date().toISOString(),
            played: false
          });
        } else {
          voicemails.push({
            id: vmId,
            from: from.trim(),
            type: vmType,
            media,
            duration: duration || 0,
            timestamp: timestamp || new Date().toISOString(),
            played: false
          });
        }
        // Keep max 20 voicemails (remove oldest, clean up R2 if needed)
        while (voicemails.length > 20) {
          const removed = voicemails.shift();
          if (removed && removed.r2Key && env.KEN_MEDIA) {
            await env.KEN_MEDIA.delete(removed.r2Key);
          }
        }
        await env.KEN_KV.put(`voicemails:${deviceId}`, JSON.stringify(voicemails));
        // Clear the voicemail request signal
        await env.KEN_KV.delete(`voicemail-req:${deviceId}`);
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // Get all voicemails for a device
    if (request.method === 'GET' && path.match(/^\/api\/voicemail\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
      // For R2-backed voicemails, return a media URL instead of base64
      const mapped = voicemails.map(v => {
        if (v.r2Key) {
          const { media, ...rest } = v; // strip any leftover media field
          return { ...rest, mediaUrl: `/api/media/${v.r2Key}` };
        }
        return v; // Legacy base64 voicemails returned as-is
      });
      return json({ voicemails: mapped });
    }

    // Delete a voicemail
    if (request.method === 'DELETE' && path.match(/^\/api\/voicemail\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const vmId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (!role) return json({ error: 'Access denied' }, 403);
      const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
      // Find voicemail to check for R2 key before filtering
      const toDelete = voicemails.find(v => v.id === vmId);
      if (toDelete && toDelete.r2Key && env.KEN_MEDIA) {
        await env.KEN_MEDIA.delete(toDelete.r2Key);
      }
      const filtered = voicemails.filter(v => v.id !== vmId);
      await env.KEN_KV.put(`voicemails:${deviceId}`, JSON.stringify(filtered));
      await logAudit(env, deviceId, auth.user.email, 'Deleted voicemail', { vmId });
      return json({ success: true });
    }

    // Mark voicemail as delivered (Pi calls this when it picks up a new voicemail)
    if (request.method === 'POST' && path.match(/^\/api\/voicemail\/[\w-]+\/[\w-]+\/delivered$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const vmId = parts[4];
      const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
      const vm = voicemails.find(v => v.id === vmId);
      if (vm) {
        vm.delivered = true;
        vm.deliveredAt = new Date().toISOString();
        await env.KEN_KV.put(`voicemails:${deviceId}`, JSON.stringify(voicemails));
      }
      return json({ success: true });
    }

    // Mark voicemail as watched (Pi calls this when user plays it)
    if (request.method === 'POST' && path.match(/^\/api\/voicemail\/[\w-]+\/[\w-]+\/watched$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const vmId = parts[4];
      const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
      const vm = voicemails.find(v => v.id === vmId);
      if (vm) {
        vm.played = true;
        vm.playedAt = new Date().toISOString();
        await env.KEN_KV.put(`voicemails:${deviceId}`, JSON.stringify(voicemails));
      }
      return json({ success: true });
    }

    // Read receipts preference per device
    if (request.method === 'POST' && path.match(/^\/api\/voicemail\/[\w-]+\/read-receipts$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        await env.KEN_KV.put(`vm-read-receipts:${deviceId}`, JSON.stringify({ enabled: !!body.enabled }));
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    if (request.method === 'GET' && path.match(/^\/api\/voicemail\/[\w-]+\/read-receipts$/)) {
      const deviceId = path.split('/')[3];
      const pref = await env.KEN_KV.get(`vm-read-receipts:${deviceId}`, 'json');
      return json(pref || { enabled: false });
    }

    // ===== ACTIVITY HEARTBEAT (portal sends on user interaction) =====
    if (request.method === 'POST' && path === '/api/auth/activity') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      await env.KEN_KV.put(`activity:${auth.user.email}`, new Date().toISOString(), { expirationTtl: 600 });
      return json({ success: true });
    }

    // ===== NOTIFICATION COUNTS (for portal bell) =====
    if (request.method === 'GET' && path.match(/^\/api\/notifications\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      // Unread messages: messages in history that are replies (from device) without readAt
      const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
      const unreadMessages = history.filter(m => m.isReply && !m.readAt && !m.deletedForEveryone && !m.deletedBySender).length;
      // Unread voicemails
      const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
      const unreadVoicemails = voicemails.filter(v => !v.played).length;
      // Missed calls (from call history, missed in last 24h)
      const callHistory = await env.KEN_KV.get(`callhistory:${deviceId}`, 'json') || {};
      const calls = callHistory.calls || [];
      const oneDayAgo = Date.now() - 86400000;
      const missedCalls = calls.filter(c => c.status === 'missed' && new Date(c.timestamp).getTime() > oneDayAgo).length;
      // Medication alerts (for carers): check recent reminder responses marked not-taken
      const medAlerts = await env.KEN_KV.get(`med-alerts:${deviceId}`, 'json') || [];
      const unresolvedMedAlerts = medAlerts.filter(a => !a.resolved).length;
      return json({ unreadMessages, unreadVoicemails, missedCalls, medicationAlerts: unresolvedMedAlerts, total: unreadMessages + unreadVoicemails + missedCalls + unresolvedMedAlerts });
    }

    // ===== NOTIFICATION PREFERENCES (per user) =====
    if (request.method === 'GET' && path === '/api/auth/notification-preferences') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const prefs = await env.KEN_KV.get(`notif-prefs:${auth.user.email}`, 'json');
      return json(prefs || { timing: '2min', messages: true, voicemails: true, missedCalls: true, medicationAlerts: true });
    }

    if (request.method === 'POST' && path === '/api/auth/notification-preferences') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const validTimings = ['immediate', '2min', '5min', '15min', 'hourly', 'off'];
        const prefs = {
          timing: validTimings.includes(body.timing) ? body.timing : '2min',
          messages: body.messages !== false,
          voicemails: body.voicemails !== false,
          missedCalls: body.missedCalls !== false,
          medicationAlerts: body.medicationAlerts !== false,
        };
        await env.KEN_KV.put(`notif-prefs:${auth.user.email}`, JSON.stringify(prefs));
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== MESSAGE REACTIONS (emoji) =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/[\w-]+\/react$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const messageId = parts[4];
      try {
        const body = await request.json();
        const { emoji } = body;
        const allowedEmoji = ['❤️', '👍', '😊', '👏'];
        if (!emoji || !allowedEmoji.includes(emoji)) return json({ error: 'Invalid emoji. Allowed: ' + allowedEmoji.join(' ') }, 400);
        // Determine reactor identity
        const deviceKey = request.headers.get('X-Ken-Device-Key');
        const isDevice = deviceKey ? await verifyDeviceKey(env, deviceId, deviceKey) : false;
        const session = await getSession(request, env);
        let reactorName, reactorId;
        if (isDevice) {
          const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
          reactorName = deviceInfo.userName || 'Ken';
          reactorId = 'device:' + deviceId;
        } else if (session) {
          const user = await env.KEN_KV.get(`user:${session.email}`, 'json');
          reactorName = user ? user.name : session.email;
          reactorId = 'user:' + session.email;
        } else {
          return json({ error: 'Authentication required' }, 401);
        }
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        const msg = history.find(m => m.id === messageId);
        if (!msg) return json({ error: 'Message not found' }, 404);
        if (!msg.reactions) msg.reactions = [];
        // One reaction per person — remove existing then add
        msg.reactions = msg.reactions.filter(r => r.reactorId !== reactorId);
        msg.reactions.push({ emoji, reactorName, reactorId, reactedAt: new Date().toISOString() });
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== MEDICATION REMINDER RESPONSE (from device) =====
    if (request.method === 'POST' && path.match(/^\/api\/reminders\/[\w-]+\/[\w-]+\/response$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const reminderId = parts[4];
      try {
        const body = await request.json();
        const { action } = body; // 'taken', 'not-taken', 'snoozed', 'ignored'
        if (!action || !['taken', 'not-taken', 'snoozed', 'ignored'].includes(action)) {
          return json({ error: 'action must be taken, not-taken, snoozed, or ignored' }, 400);
        }
        const reminders = await env.KEN_KV.get(`reminders:${deviceId}`, 'json') || [];
        const reminder = reminders.find(r => r.id === reminderId);
        const label = reminder ? (reminder.label || reminder.text || 'Medication') : 'Medication';
        // Log to audit
        await logAudit(env, deviceId, 'device', 'Medication reminder: ' + action, { reminderId, label, snoozeCount: body.snoozeCount || 0 });
        if (action === 'not-taken' || action === 'ignored') {
          // Alert carers via email
          const medAlerts = await env.KEN_KV.get(`med-alerts:${deviceId}`, 'json') || [];
          medAlerts.push({ id: crypto.randomUUID(), reminderId, label, action, timestamp: new Date().toISOString(), resolved: false });
          if (medAlerts.length > 50) medAlerts.splice(0, medAlerts.length - 50);
          await env.KEN_KV.put(`med-alerts:${deviceId}`, JSON.stringify(medAlerts));
          // Email carers/admins
          const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
          const userName = deviceInfo.userName || 'The Ken user';
          const actionText = action === 'ignored' ? 'did not respond to' : 'marked as not taken';
          const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
          for (const key of allUsers.keys) {
            try {
              const u = await env.KEN_KV.get(key.name, 'json');
              if (!u || !u.devices || !u.devices[deviceId]) continue;
              const uRole = u.devices[deviceId].role;
              if (uRole === 'admin' || uRole === 'carer') {
                await sendEmail(env, u.email,
                  'Medication alert — ' + userName,
                  'Medication not taken',
                  '<p style="color:#6B6459;line-height:1.7;"><strong>' + sanitize(userName) + '</strong> ' + actionText + ' their medication reminder:</p>' +
                  '<p style="color:#1A1714;font-weight:500;font-size:16px;margin:12px 0;">' + sanitize(label) + '</p>' +
                  '<p style="color:#6B6459;line-height:1.7;">Please check on them when possible.</p>' +
                  '<a href="https://theken.uk/portal/" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Open Portal</a>'
                );
              }
            } catch {}
          }
        }
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== MEDICATION ALERTS (for portal notification bell) =====
    if (request.method === 'GET' && path.match(/^\/api\/med-alerts\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const alerts = await env.KEN_KV.get(`med-alerts:${deviceId}`, 'json') || [];
      return json({ alerts });
    }

    if (request.method === 'POST' && path.match(/^\/api\/med-alerts\/[\w-]+\/[\w-]+\/resolve$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const alertId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const alerts = await env.KEN_KV.get(`med-alerts:${deviceId}`, 'json') || [];
      const alert = alerts.find(a => a.id === alertId);
      if (alert) {
        alert.resolved = true;
        alert.resolvedBy = auth.user.email;
        alert.resolvedAt = new Date().toISOString();
        await env.KEN_KV.put(`med-alerts:${deviceId}`, JSON.stringify(alerts));
      }
      return json({ success: true });
    }

    // ===== BIRTHDAY REMINDER SETTINGS =====
    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/birthdays$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'edit:settings')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const prefs = {
          enabled: body.enabled !== false,
          notifyTime: body.notifyTime || '09:00', // HH:MM when to send reminder
          daysBefore: body.daysBefore || [0, 1, 7], // days before birthday to notify (0 = on the day)
        };
        await env.KEN_KV.put(`birthday-prefs:${deviceId}`, JSON.stringify(prefs));
        await logAudit(env, deviceId, auth.user.email, 'Updated birthday reminder settings', prefs);
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    if (request.method === 'GET' && path.match(/^\/api\/settings\/[\w-]+\/birthdays$/)) {
      const deviceId = path.split('/')[3];
      const prefs = await env.KEN_KV.get(`birthday-prefs:${deviceId}`, 'json');
      return json(prefs || { enabled: true, notifyTime: '09:00', daysBefore: [0, 1, 7] });
    }

    // ===== GROUP ENDPOINTS =====

    // Create a group
    if (request.method === 'POST' && path.match(/^\/api\/groups\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const { name, coverPhoto, members } = body;
        if (!name || !name.trim()) return json({ error: 'Group name required' }, 400);
        const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json') || [];
        const group = {
          id: crypto.randomUUID(),
          name: sanitize(name),
          coverPhoto: coverPhoto || '',
          members: (members || []).map(m => ({ userId: m.userId || m.email, name: sanitize(m.name || ''), role: m.role === 'admin' ? 'admin' : 'member' })),
          createdBy: auth.user.email,
          createdAt: new Date().toISOString(),
        };
        // Ensure creator is admin member
        if (!group.members.find(m => m.userId === auth.user.email)) {
          group.members.unshift({ userId: auth.user.email, name: auth.user.name, role: 'admin' });
        }
        groups.push(group);
        await env.KEN_KV.put(`groups:${deviceId}`, JSON.stringify(groups));
        await logAudit(env, deviceId, auth.user.email, 'Created group', { groupName: group.name, memberCount: group.members.length });
        return json({ success: true, group });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // List groups for a device
    if (request.method === 'GET' && path.match(/^\/api\/groups\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json') || [];
      return json({ groups });
    }

    // Get single group
    if (request.method === 'GET' && path.match(/^\/api\/groups\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const groupId = parts[4];
      const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json') || [];
      const group = groups.find(g => g.id === groupId);
      if (!group) return json({ error: 'Group not found' }, 404);
      return json({ group });
    }

    // Update group (name, coverPhoto, members)
    if (request.method === 'POST' && path.match(/^\/api\/groups\/[\w-]+\/[\w-]+\/update$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const groupId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json') || [];
      const group = groups.find(g => g.id === groupId);
      if (!group) return json({ error: 'Group not found' }, 404);
      // Only group admins can update
      const memberEntry = group.members.find(m => m.userId === auth.user.email);
      if (!memberEntry || memberEntry.role !== 'admin') return json({ error: 'Group admin access required' }, 403);
      try {
        const body = await request.json();
        if (body.name !== undefined) group.name = sanitize(body.name);
        if (body.coverPhoto !== undefined) group.coverPhoto = body.coverPhoto;
        if (body.members !== undefined) {
          group.members = body.members.map(m => ({ userId: m.userId || m.email, name: sanitize(m.name || ''), role: m.role === 'admin' ? 'admin' : 'member' }));
        }
        group.updatedAt = new Date().toISOString();
        await env.KEN_KV.put(`groups:${deviceId}`, JSON.stringify(groups));
        await logAudit(env, deviceId, auth.user.email, 'Updated group', { groupId, groupName: group.name });
        return json({ success: true, group });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // Delete group
    if (request.method === 'DELETE' && path.match(/^\/api\/groups\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const groupId = parts[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json') || [];
      const group = groups.find(g => g.id === groupId);
      if (!group) return json({ error: 'Group not found' }, 404);
      const memberEntry = group.members.find(m => m.userId === auth.user.email);
      const userRole = getUserRole(auth.user, deviceId);
      if ((!memberEntry || memberEntry.role !== 'admin') && !['admin', 'hq'].includes(userRole)) {
        return json({ error: 'Group admin or device admin access required' }, 403);
      }
      const filtered = groups.filter(g => g.id !== groupId);
      await env.KEN_KV.put(`groups:${deviceId}`, JSON.stringify(filtered));
      await logAudit(env, deviceId, auth.user.email, 'Deleted group', { groupId, groupName: group.name });
      return json({ success: true });
    }

    // Send group message (delivers to device pending queue + history, tagged with group)
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/group\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const groupId = parts[5];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'send:messages')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const { text } = body;
        if (!text || !text.trim()) return json({ error: 'Text required' }, 400);
        const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json') || [];
        const group = groups.find(g => g.id === groupId);
        if (!group) return json({ error: 'Group not found' }, 404);
        const message = {
          id: crypto.randomUUID(),
          from: auth.user.name || auth.user.email,
          fromEmail: auth.user.email,
          text: sanitize(text),
          sentAt: new Date().toISOString(),
          deliveredAt: null, readAt: null,
          groupId, groupName: group.name,
          deletedBySender: false, deletedByRecipient: false, deletedForEveryone: false,
          emailNotificationSent: false,
        };
        // Add to pending (Pi will poll) and history
        const pending = await env.KEN_KV.get(`messages:${deviceId}`, 'json') || [];
        pending.push(message);
        await env.KEN_KV.put(`messages:${deviceId}`, JSON.stringify(pending));
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        history.push(message);
        if (history.length > 100) history.splice(0, history.length - 100);
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        return json({ success: true, message: { id: message.id } });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== SCHEDULED MESSAGES =====
    // Schedule a message for future delivery
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/schedule$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!hasPermission(userRole, 'send:messages')) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const { from, text, scheduledFor } = body;
        if (!from || !text || !scheduledFor) return json({ error: 'from, text, and scheduledFor required' }, 400);
        if (new Date(scheduledFor).getTime() <= Date.now()) return json({ error: 'scheduledFor must be in the future' }, 400);
        const scheduled = await env.KEN_KV.get(`scheduled-msgs:${deviceId}`, 'json') || [];
        const item = {
          id: crypto.randomUUID(),
          from: sanitize(from),
          fromEmail: auth.user.email,
          text: sanitize(text),
          scheduledFor,
          status: 'scheduled',
          createdAt: new Date().toISOString(),
        };
        scheduled.push(item);
        await env.KEN_KV.put(`scheduled-msgs:${deviceId}`, JSON.stringify(scheduled));
        await logAudit(env, deviceId, auth.user.email, 'Scheduled message', { scheduledFor, preview: text.slice(0, 50) });
        return json({ success: true, id: item.id });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // List scheduled messages
    if (request.method === 'GET' && path.match(/^\/api\/messages\/[\w-]+\/scheduled$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const scheduled = await env.KEN_KV.get(`scheduled-msgs:${deviceId}`, 'json') || [];
      // Users see only their own; admin/hq see all
      const userRole = getUserRole(auth.user, deviceId);
      const filtered = ['admin', 'hq'].includes(userRole) ? scheduled : scheduled.filter(s => s.fromEmail === auth.user.email);
      return json({ scheduled: filtered.filter(s => s.status === 'scheduled') });
    }

    // Cancel or send-now a scheduled message
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/scheduled\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const schedId = parts[5];
      const action = parts[6]; // 'cancel' or 'send-now'
      if (!['cancel', 'send-now'].includes(action)) return json({ error: 'Action must be cancel or send-now' }, 400);
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const scheduled = await env.KEN_KV.get(`scheduled-msgs:${deviceId}`, 'json') || [];
      const item = scheduled.find(s => s.id === schedId);
      if (!item) return json({ error: 'Scheduled message not found' }, 404);
      if (item.fromEmail !== auth.user.email) {
        const userRole = getUserRole(auth.user, deviceId);
        if (!['admin', 'hq'].includes(userRole)) return json({ error: 'Can only manage your own scheduled messages' }, 403);
      }
      if (action === 'cancel') {
        item.status = 'cancelled';
        await env.KEN_KV.put(`scheduled-msgs:${deviceId}`, JSON.stringify(scheduled));
        await logAudit(env, deviceId, auth.user.email, 'Cancelled scheduled message', { schedId });
      } else {
        // send-now: deliver immediately
        item.status = 'sent';
        await env.KEN_KV.put(`scheduled-msgs:${deviceId}`, JSON.stringify(scheduled));
        // Add to pending + history (same as handleSendMessage)
        const message = {
          id: crypto.randomUUID(), from: item.from, fromEmail: item.fromEmail, text: item.text,
          sentAt: new Date().toISOString(), deliveredAt: null, readAt: null,
          deletedBySender: false, deletedByRecipient: false, deletedForEveryone: false, emailNotificationSent: false,
        };
        const pending = await env.KEN_KV.get(`messages:${deviceId}`, 'json') || [];
        pending.push(message);
        await env.KEN_KV.put(`messages:${deviceId}`, JSON.stringify(pending));
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        history.push(message);
        if (history.length > 100) history.splice(0, history.length - 100);
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        await logAudit(env, deviceId, auth.user.email, 'Sent scheduled message now', { schedId });
      }
      return json({ success: true });
    }

    // ===== MESSAGE SEARCH =====
    if (request.method === 'GET' && path.match(/^\/api\/messages\/[\w-]+\/search$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const url = new URL(request.url);
      const query = (url.searchParams.get('q') || '').toLowerCase().trim();
      const contact = url.searchParams.get('contact') || '';
      const type = url.searchParams.get('type') || 'all'; // all, messages, calls
      const fromDate = url.searchParams.get('from') || '';
      const toDate = url.searchParams.get('to') || '';
      if (!query && !contact) return json({ error: 'Search query (q) or contact filter required' }, 400);
      const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
      let results = history.filter(m => !m.deletedForEveryone);
      if (query) results = results.filter(m => (m.text || '').toLowerCase().includes(query) || (m.from || '').toLowerCase().includes(query));
      if (contact) results = results.filter(m => m.from === contact || m.to === contact);
      if (fromDate) results = results.filter(m => new Date(m.sentAt) >= new Date(fromDate));
      if (toDate) results = results.filter(m => new Date(m.sentAt) <= new Date(toDate));
      // Include call history if requested
      let callResults = [];
      if (type === 'all' || type === 'calls') {
        const callData = await env.KEN_KV.get(`callhistory:${deviceId}`, 'json') || {};
        const calls = callData.calls || [];
        if (contact) callResults = calls.filter(c => (c.contactName || '').toLowerCase() === contact.toLowerCase());
        else if (query) callResults = calls.filter(c => (c.contactName || '').toLowerCase().includes(query));
      }
      if (type === 'calls') results = [];
      if (type === 'messages') callResults = [];
      return json({ messages: results.slice(-100), calls: callResults.slice(-50) });
    }

    // ===== DATA EXPORT (GDPR) =====
    if (request.method === 'GET' && path.match(/^\/api\/export\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!['admin', 'hq'].includes(userRole)) return json({ error: 'Admin access required for data export' }, 403);
      // Collect all device data
      const [history, contacts, medical, settings, audit, reminders, voicemails, callHistoryData, deviceInfo, feedback] = await Promise.all([
        env.KEN_KV.get(`history:${deviceId}`, 'json'),
        env.KEN_KV.get(`contactlist:${deviceId}`, 'json'),
        env.KEN_KV.get(`medical:${deviceId}`, 'json'),
        env.KEN_KV.get(`settings:${deviceId}`, 'json'),
        env.KEN_KV.get(`audit:${deviceId}`, 'json'),
        env.KEN_KV.get(`reminders:${deviceId}`, 'json'),
        env.KEN_KV.get(`voicemails:${deviceId}`, 'json'),
        env.KEN_KV.get(`callhistory:${deviceId}`, 'json'),
        env.KEN_KV.get(`device:${deviceId}`, 'json'),
        env.KEN_KV.get(`feedback:${deviceId}`, 'json'),
      ]);
      const exportData = {
        exportedAt: new Date().toISOString(),
        exportedBy: auth.user.email,
        deviceId,
        deviceInfo: deviceInfo || {},
        messages: (history || []).map(m => ({ id: m.id, from: m.from, text: m.text, sentAt: m.sentAt, deliveredAt: m.deliveredAt, readAt: m.readAt, isReply: m.isReply, reactions: m.reactions })),
        contacts: contacts || [],
        medical: medical || {},
        settings: settings || {},
        reminders: reminders || [],
        voicemails: (voicemails || []).map(v => ({ id: v.id, from: v.from, type: v.type, duration: v.duration, timestamp: v.timestamp, played: v.played })),
        callHistory: callHistoryData || {},
        auditLog: audit || [],
        feedback: (feedback || []).map(f => ({ id: f.id, from: f.from, text: f.text, category: f.category, status: f.status, timestamp: f.timestamp })),
      };
      await logAudit(env, deviceId, auth.user.email, 'Exported device data', {});
      return new Response(JSON.stringify(exportData, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="ken-export-' + deviceId + '.json"', ...getCorsHeaders(request) },
      });
    }

    // ===== USER MANAGEMENT (per device) =====
    // List all users with access to this device
    if (request.method === 'GET' && path.match(/^\/api\/device\/[\w-]+\/users$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!['admin', 'hq'].includes(userRole)) return json({ error: 'Admin access required' }, 403);
      const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
      const deviceUsers = [];
      for (const key of allUsers.keys) {
        try {
          const u = await env.KEN_KV.get(key.name, 'json');
          if (!u) continue;
          // Check if user has access via devices object or globalRole
          let role = null;
          if (u.globalRole === 'hq') role = 'hq';
          else if (u.globalRole === 'carer' && (u.carerDevices || []).includes(deviceId)) role = 'carer';
          else if (u.devices && u.devices[deviceId]) role = u.devices[deviceId].role;
          if (role) {
            deviceUsers.push({ email: u.email, name: u.name, role, phone: u.phone || '', mfaEnabled: !!u.mfaEnabled, createdAt: u.createdAt });
          }
        } catch {}
      }
      return json({ users: deviceUsers });
    }

    // Change a user's role on this device
    if (request.method === 'POST' && path.match(/^\/api\/device\/[\w-]+\/users\/role$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!['admin', 'hq'].includes(userRole)) return json({ error: 'Admin access required' }, 403);
      try {
        const body = await request.json();
        const { email, role } = body;
        if (!email || !role) return json({ error: 'email and role required' }, 400);
        if (!VALID_ROLES.includes(role)) return json({ error: 'Invalid role' }, 400);
        const targetUser = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (!targetUser) return json({ error: 'User not found' }, 404);
        if (!targetUser.devices) targetUser.devices = {};
        targetUser.devices[deviceId] = { role };
        await saveUserDual(env, email, targetUser);
        await logAudit(env, deviceId, auth.user.email, 'Changed user role', { targetEmail: email, newRole: role });
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // Revoke a user's access to this device
    if (request.method === 'POST' && path.match(/^\/api\/device\/[\w-]+\/users\/revoke$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!['admin', 'hq'].includes(userRole)) return json({ error: 'Admin access required' }, 403);
      try {
        const body = await request.json();
        const { email } = body;
        if (!email) return json({ error: 'email required' }, 400);
        if (email.toLowerCase() === auth.user.email) return json({ error: 'Cannot revoke your own access' }, 400);
        const targetUser = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (!targetUser) return json({ error: 'User not found' }, 404);
        if (targetUser.devices && targetUser.devices[deviceId]) {
          delete targetUser.devices[deviceId];
          await saveUserDual(env, email, targetUser);
        }
        await logAudit(env, deviceId, auth.user.email, 'Revoked user access', { targetEmail: email });
        return json({ success: true });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== USER DELETION (GDPR-compliant tokenisation) =====
    // HQ-only. Tokenises PII, replaces across all device records, deletes account.
    if (request.method === 'POST' && path === '/api/admin/user/delete') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ access required' }, 403);
      try {
        const body = await request.json();
        const { email, confirm } = body;
        if (!email) return json({ error: 'email required' }, 400);
        if (!confirm) return json({ error: 'Set confirm: true to delete user' }, 400);
        if (email.toLowerCase() === auth.user.email) return json({ error: 'Cannot delete your own account' }, 400);

        const targetEmail = email.toLowerCase();
        const targetUser = await env.KEN_KV.get(`user:${targetEmail}`, 'json');
        if (!targetUser) return json({ error: 'User not found' }, 404);

        // Generate PII token and store encrypted mapping in KEN_PII
        const piiData = {
          name: targetUser.name,
          email: targetUser.email,
          phone: targetUser.phone || null,
        };
        const token = await tokenisePii(env, piiData, 'audit');
        const emailToToken = { [targetEmail]: token };
        if (targetUser.name) emailToToken[targetUser.name] = token;

        // Get all devices this user had access to
        const userDevices = Object.keys(targetUser.devices || {});

        // Tokenise PII in all device records
        for (const deviceId of userDevices) {
          // --- Messages: tokenise sender/recipient references ---
          const history = await env.KEN_KV.get(`history:${deviceId}`, 'json');
          if (history && history.length) {
            const tokenised = history.map(m => tokeniseRecord(m, emailToToken));
            await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(tokenised));
          }
          const pending = await env.KEN_KV.get(`messages:${deviceId}`, 'json');
          if (pending && pending.length) {
            const tokenised = pending.map(m => tokeniseRecord(m, emailToToken));
            await env.KEN_KV.put(`messages:${deviceId}`, JSON.stringify(tokenised));
          }

          // --- Audit logs: tokenise userId references ---
          const audit = await env.KEN_KV.get(`audit:${deviceId}`, 'json');
          if (audit && audit.length) {
            const tokenised = audit.map(a => tokeniseRecord(a, emailToToken));
            await env.KEN_KV.put(`audit:${deviceId}`, JSON.stringify(tokenised));
          }
          // Also tokenise archived audit logs
          const archiveList = await env.KEN_KV.list({ prefix: `audit-archive:${deviceId}:` });
          for (const ak of archiveList.keys) {
            const archived = await env.KEN_KV.get(ak.name, 'json');
            if (archived && archived.length) {
              const tokenised = archived.map(a => tokeniseRecord(a, emailToToken));
              await env.KEN_KV.put(ak.name, JSON.stringify(tokenised));
            }
          }

          // --- Care notes: tokenise author references ---
          const medical = await env.KEN_KV.get(`medical:${deviceId}`, 'json');
          if (medical && medical.careNotesLog) {
            let notesLog = medical.careNotesLog;
            if (typeof notesLog === 'string' && notesLog.startsWith('ENC:')) {
              notesLog = await decryptField(env, notesLog);
              try { notesLog = JSON.parse(notesLog); } catch {}
            }
            if (Array.isArray(notesLog)) {
              medical.careNotesLog = notesLog.map(n => {
                const updated = { ...n };
                if (updated.author === targetEmail || updated.author === targetUser.name) updated.author = token;
                if (updated.authorEmail === targetEmail) updated.authorEmail = token;
                return updated;
              });
              if (typeof medical.careNotesLog !== 'string') {
                medical.careNotesLog = await encryptField(env, JSON.stringify(medical.careNotesLog));
              }
              await env.KEN_KV.put(`medical:${deviceId}`, JSON.stringify(medical));
            }
          }

          // --- Feedback: tokenise submitter ---
          const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json');
          if (feedback && feedback.length) {
            const tokenised = feedback.map(f => {
              const updated = { ...f };
              if (updated.from === targetEmail || updated.from === targetUser.name) updated.from = token;
              return updated;
            });
            await env.KEN_KV.put(`feedback:${deviceId}`, JSON.stringify(tokenised));
          }

          // --- Scheduled messages: tokenise sender ---
          const scheduledMsgs = await env.KEN_KV.get(`scheduled-msgs:${deviceId}`, 'json');
          if (scheduledMsgs && scheduledMsgs.length) {
            const tokenised = scheduledMsgs.map(m => tokeniseRecord(m, emailToToken));
            await env.KEN_KV.put(`scheduled-msgs:${deviceId}`, JSON.stringify(tokenised));
          }

          // --- Groups: tokenise member references ---
          const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json');
          if (groups && groups.length) {
            const tokenised = groups.map(g => ({
              ...g,
              members: (g.members || []).map(m => {
                if (m.userId === targetEmail) return { ...m, userId: token, name: token };
                return m;
              }),
              createdBy: g.createdBy === targetEmail ? token : g.createdBy,
            }));
            await env.KEN_KV.put(`groups:${deviceId}`, JSON.stringify(tokenised));
          }

          // --- Clean up per-user keyed data for this device ---
          await env.KEN_PII.put(`deleted-carer-alerts:${token}:${deviceId}`, JSON.stringify({
            deletedAt: new Date().toISOString(),
            retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.general).toISOString(),
          }));
          await env.KEN_KV.delete(`carer-alerts:${deviceId}:${targetEmail}`);
          await env.KEN_KV.delete(`check-ins:${deviceId}:${targetEmail}`);

          // --- HQ access records ---
          const hqAccessKeys = await env.KEN_KV.list({ prefix: `hq-access:${deviceId}:${targetEmail}:` });
          for (const hk of hqAccessKeys.keys) {
            await env.KEN_KV.delete(hk.name);
          }
        }

        // --- Delete HQ access requests authored by this user ---
        for (const deviceId of userDevices) {
          const requests = await env.KEN_KV.get(`hq-access-requests:${deviceId}`, 'json');
          if (requests && requests.length) {
            const tokenised = requests.map(r => {
              if (r.hqEmail === targetEmail) return { ...r, hqEmail: token };
              if (r.approvedBy === targetEmail) return { ...r, approvedBy: token };
              return r;
            });
            await env.KEN_KV.put(`hq-access-requests:${deviceId}`, JSON.stringify(tokenised));
          }
        }

        // --- Delete user-level data ---
        await env.KEN_KV.delete(`user:${targetEmail}`);
        await env.KEN_KV.delete(`activity:${targetEmail}`);
        await env.KEN_KV.delete(`notif-prefs:${targetEmail}`);

        // --- Delete all sessions for this user ---
        const sessionList = await env.KEN_KV.list({ prefix: 'session:' });
        for (const sk of sessionList.keys) {
          const sess = await env.KEN_KV.get(sk.name, 'json');
          if (sess && sess.email === targetEmail) {
            await env.KEN_KV.delete(sk.name);
          }
        }

        // --- Delete any pending invites ---
        const inviteList = await env.KEN_KV.list({ prefix: 'invite:' });
        for (const ik of inviteList.keys) {
          if (ik.name.endsWith(`:${targetEmail}`)) {
            await env.KEN_KV.delete(ik.name);
          }
        }

        // --- Log deletion across all affected devices ---
        for (const deviceId of userDevices) {
          await logAudit(env, deviceId, auth.user.email, 'User deleted (tokenised)', {
            token, deletedEmail: token, devicesAffected: userDevices.length,
          });
        }

        return json({ success: true, token, devicesAffected: userDevices.length });
      } catch (e) { return json({ error: 'User deletion failed: ' + e.message }, 500); }
    }

    // ===== SUBJECT ACCESS REQUEST (HQ-only) =====
    // Collects all data for a given email across all devices, including tokenised records
    if (request.method === 'POST' && path === '/api/admin/sar') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ access required' }, 403);
      try {
        const body = await request.json();
        const { email } = body;
        if (!email) return json({ error: 'email required' }, 400);
        const targetEmail = email.toLowerCase();
        const targetUser = await env.KEN_KV.get(`user:${targetEmail}`, 'json');

        const result = {
          exportedAt: new Date().toISOString(),
          exportedBy: auth.user.email,
          requestType: 'Subject Access Request',
          email: targetEmail,
        };

        if (targetUser) {
          // Active user — collect all their data
          result.userRecord = {
            email: targetUser.email, name: targetUser.name, phone: targetUser.phone,
            createdAt: targetUser.createdAt, mfaEnabled: !!targetUser.mfaEnabled,
            poa: targetUser.poa || false, globalRole: targetUser.globalRole || null,
          };
          result.consent = targetUser.consent || null;
          result.subscriptions = targetUser.subscriptions || {};
          result.devices = [];
          let totalMessages = 0, totalAuditEntries = 0;

          for (const [deviceId, deviceRole] of Object.entries(targetUser.devices || {})) {
            const deviceData = { deviceId, role: deviceRole.role || deviceRole };
            const [history, contacts, medical, settings, audit, reminders, voicemails, callHistory, feedback, groups] = await Promise.all([
              env.KEN_KV.get(`history:${deviceId}`, 'json'),
              env.KEN_KV.get(`contactlist:${deviceId}`, 'json'),
              env.KEN_KV.get(`medical:${deviceId}`, 'json'),
              env.KEN_KV.get(`settings:${deviceId}`, 'json'),
              env.KEN_KV.get(`audit:${deviceId}`, 'json'),
              env.KEN_KV.get(`reminders:${deviceId}`, 'json'),
              env.KEN_KV.get(`voicemails:${deviceId}`, 'json'),
              env.KEN_KV.get(`callhistory:${deviceId}`, 'json'),
              env.KEN_KV.get(`feedback:${deviceId}`, 'json'),
              env.KEN_KV.get(`groups:${deviceId}`, 'json'),
            ]);
            // Filter messages to/from this user
            const userMessages = (history || []).filter(m => m.fromEmail === targetEmail || m.toEmail === targetEmail);
            deviceData.messages = userMessages;
            totalMessages += userMessages.length;
            // Filter audit entries by this user
            const userAudit = (audit || []).filter(a => a.userId === targetEmail);
            deviceData.auditEntries = userAudit;
            totalAuditEntries += userAudit.length;
            deviceData.contacts = contacts || [];
            deviceData.medical = medical || {};
            deviceData.settings = settings || {};
            deviceData.reminders = reminders || [];
            deviceData.voicemails = voicemails || [];
            deviceData.callHistory = callHistory || {};
            deviceData.feedback = (feedback || []).filter(f => f.from === targetEmail || f.from === targetUser.name);
            deviceData.groups = (groups || []).filter(g => (g.members || []).some(m => m.userId === targetEmail));
            // Per-user keyed data
            deviceData.carerAlerts = await env.KEN_KV.get(`carer-alerts:${deviceId}:${targetEmail}`, 'json');
            deviceData.checkIns = await env.KEN_KV.get(`check-ins:${deviceId}:${targetEmail}`, 'json');
            result.devices.push(deviceData);
          }
          result.totalMessages = totalMessages;
          result.totalAuditEntries = totalAuditEntries;
          result.notificationPrefs = await env.KEN_KV.get(`notif-prefs:${targetEmail}`, 'json');
        } else {
          // User may have been deleted — search for their token in tokenised records
          result.userRecord = null;
          result.note = 'No active account found. Searching tokenised records...';
          // Search PII vault for a token matching this email
          const piiKeys = await env.KEN_PII.list({ prefix: 'pii:' });
          let foundToken = null;
          for (const key of piiKeys.keys) {
            const record = await env.KEN_PII.get(key.name, 'json');
            if (record && record.data) {
              const decrypted = await resolvePiiToken(env, key.name.replace('pii:', ''));
              if (decrypted && decrypted.email === targetEmail) {
                foundToken = key.name.replace('pii:', '');
                break;
              }
            }
          }
          if (foundToken) {
            result.token = foundToken;
            result.note = 'User was deleted. Data retained under token ' + foundToken;
            // Collect retained records
            result.retainedRecords = {};
            const retainedKeys = await env.KEN_PII.list({ prefix: 'retained:' });
            for (const rk of retainedKeys.keys) {
              const retained = await env.KEN_PII.get(rk.name, 'json');
              if (retained && retained.data) {
                const hasToken = JSON.stringify(retained.data).includes(foundToken);
                if (hasToken) result.retainedRecords[rk.name] = retained;
              }
            }
          } else {
            result.note = 'No active or tokenised records found for this email address.';
          }
        }

        // Audit log the SAR
        const globalAudit = await env.KEN_KV.get('audit:pii-access', 'json') || [];
        globalAudit.push({
          id: crypto.randomUUID(), type: 'SAR', email: targetEmail,
          accessedBy: auth.user.email, timestamp: new Date().toISOString(),
        });
        await env.KEN_KV.put('audit:pii-access', JSON.stringify(globalAudit));

        return json(result);
      } catch (e) { return json({ error: 'SAR failed: ' + e.message }, 500); }
    }

    // ===== PII TOKEN RESOLVE (HQ-only, audit-logged) =====
    if (request.method === 'POST' && path === '/api/admin/pii/resolve') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ access required' }, 403);
      const rateCheck = await checkRateLimit(env, request, 'pii-resolve', 10, 60);
      if (rateCheck.limited) return json({ error: 'Rate limited', retryAfter: rateCheck.retryAfter }, 429);
      try {
        const body = await request.json();
        const { token, reason } = body;
        if (!token || !token.startsWith('TOK_')) return json({ error: 'Valid token required' }, 400);
        if (!reason || reason.trim().length < 10) return json({ error: 'Reason required (min 10 chars)' }, 400);

        const piiData = await resolvePiiToken(env, token);
        if (!piiData) return json({ error: 'Token not found or expired' }, 404);

        // Audit log the PII access — log to a global audit key
        const globalAudit = await env.KEN_KV.get('audit:pii-access', 'json') || [];
        globalAudit.push({
          id: crypto.randomUUID(),
          token,
          accessedBy: auth.user.email,
          reason,
          timestamp: new Date().toISOString(),
        });
        await env.KEN_KV.put('audit:pii-access', JSON.stringify(globalAudit));

        return json({ success: true, token, pii: piiData });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // ===== KV → D1 MIGRATION (HQ-only, temporary) =====
    if (request.method === 'POST' && path === '/api/admin/migrate-d1') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ access required' }, 403);
      if (!env.KEN_DB) return json({ error: 'D1 database not configured' }, 500);

      const results = { users: 0, devices: 0, userDevices: 0, deviceKeys: 0, invites: 0, errors: [] };
      try {
        // Migrate devices
        const devicesAll = await env.KEN_KV.get('devices:all', 'json') || [];
        for (const deviceId of devicesAll) {
          try {
            const info = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
            await env.KEN_DB.prepare('INSERT OR IGNORE INTO devices (device_id, user_name, created_at, extra) VALUES (?, ?, ?, ?)')
              .bind(deviceId, info.userName || 'The Ken', info.createdAt || new Date().toISOString(), JSON.stringify(info)).run();
            results.devices++;
            // Device key
            const keyHash = await env.KEN_KV.get(`device-key:${deviceId}`);
            if (keyHash) {
              await env.KEN_DB.prepare('INSERT OR IGNORE INTO device_keys (device_id, key_hash) VALUES (?, ?)').bind(deviceId, keyHash).run();
              results.deviceKeys++;
            }
          } catch (e) { results.errors.push(`device:${deviceId}: ${e.message}`); }
        }
        // Migrate users
        const userList = await env.KEN_KV.list({ prefix: 'user:' });
        for (const key of userList.keys) {
          try {
            const user = await env.KEN_KV.get(key.name, 'json');
            if (!user || !user.email) continue;
            await d1SaveUser(env, user);
            results.users++;
            if (user.devices) results.userDevices += Object.keys(user.devices).length;
          } catch (e) { results.errors.push(`${key.name}: ${e.message}`); }
        }
        // Migrate invites
        const inviteList = await env.KEN_KV.list({ prefix: 'invite:' });
        for (const key of inviteList.keys) {
          try {
            const invite = await env.KEN_KV.get(key.name, 'json');
            if (!invite) continue;
            const parts = key.name.replace('invite:', '').split(':');
            const deviceId = parts[0];
            const email = parts.slice(1).join(':');
            await env.KEN_DB.prepare('INSERT OR IGNORE INTO invites (device_id, email, role, invited_by, created_at) VALUES (?, ?, ?, ?, ?)')
              .bind(deviceId, email, invite.role || 'standard', invite.invitedBy || null, invite.createdAt || new Date().toISOString()).run();
            results.invites++;
          } catch (e) { results.errors.push(`${key.name}: ${e.message}`); }
        }
      } catch (e) { results.errors.push(`Fatal: ${e.message}`); }
      return json(results);
    }

    // ===== DEVICE PROVISIONING TOKENS (HQ-only) =====
    // One-time tokens required for first heartbeat from unknown devices
    if (request.method === 'POST' && path === '/api/admin/provision-token') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'hq') return json({ error: 'HQ access required' }, 403);
      try {
        const body = await request.json();
        const label = sanitize(body.label || 'unnamed');
        const token = 'prov-' + crypto.randomUUID();
        await env.KEN_KV.put(`provision-token:${token}`, JSON.stringify({
          createdBy: auth.user.email,
          label,
          createdAt: new Date().toISOString(),
        }), { expirationTtl: 86400 }); // 24-hour TTL
        await logAudit(env, 'system', auth.user.email, 'Provision token created', { label });
        return json({ success: true, token, expiresIn: '24 hours' });
      } catch (e) { return json({ error: 'Failed to create provision token: ' + e.message }, 500); }
    }

    // ===== DEVICE DECOMMISSION (GDPR-compliant tokenised cascade) =====
    if (request.method === 'POST' && path.match(/^\/api\/device\/[\w-]+\/decommission$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (userRole !== 'admin' && userRole !== 'hq') return json({ error: 'Admin or HQ access required' }, 403);
      try {
        const body = await request.json();
        if (!body.confirm) return json({ error: 'Set confirm: true to decommission' }, 400);

        const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
        const now = new Date().toISOString();

        // Tokenise device user name if present
        const devicePii = { deviceId, userName: deviceInfo.userName || null, location: deviceInfo.location || null };
        const deviceToken = await tokenisePii(env, devicePii, 'audit');

        // --- Tokenise PII in all user records associated with this device ---
        const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
        const emailToToken = {};
        for (const key of allUsers.keys) {
          try {
            const u = await env.KEN_KV.get(key.name, 'json');
            if (u && u.devices && u.devices[deviceId]) {
              // Create a token for each user associated with this device
              if (!emailToToken[u.email]) {
                const userToken = await tokenisePii(env, { name: u.name, email: u.email, phone: u.phone }, 'audit');
                emailToToken[u.email] = userToken;
              }
              // Remove device from user's access
              delete u.devices[deviceId];
              await env.KEN_KV.put(key.name, JSON.stringify(u));
            }
          } catch {}
        }

        // --- Tokenise messages history ---
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json');
        if (history && history.length) {
          const tokenised = history.map(m => tokeniseRecord(m, emailToToken));
          await env.KEN_PII.put(`retained:history:${deviceId}`, JSON.stringify({
            data: tokenised, deletedAt: now, deviceToken,
            retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.messages).toISOString(),
          }));
        }

        // --- Retain audit logs (6 year retention) ---
        const audit = await env.KEN_KV.get(`audit:${deviceId}`, 'json');
        if (audit && audit.length) {
          const tokenised = audit.map(a => tokeniseRecord(a, emailToToken));
          await env.KEN_PII.put(`retained:audit:${deviceId}`, JSON.stringify({
            data: tokenised, deletedAt: now, deviceToken,
            retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.audit).toISOString(),
          }));
        }
        // Archive audit logs too
        const archiveList = await env.KEN_KV.list({ prefix: `audit-archive:${deviceId}:` });
        for (const ak of archiveList.keys) {
          const archived = await env.KEN_KV.get(ak.name, 'json');
          if (archived && archived.length) {
            const tokenised = archived.map(a => tokeniseRecord(a, emailToToken));
            await env.KEN_PII.put(`retained:${ak.name}`, JSON.stringify({
              data: tokenised, deletedAt: now, deviceToken,
              retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.audit).toISOString(),
            }));
          }
          await env.KEN_KV.delete(ak.name);
        }

        // --- Retain medical/care data (3 year retention) ---
        const medical = await env.KEN_KV.get(`medical:${deviceId}`, 'json');
        if (medical) {
          await env.KEN_PII.put(`retained:medical:${deviceId}`, JSON.stringify({
            data: medical, deletedAt: now, deviceToken,
            retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.medical).toISOString(),
          }));
        }
        const patient = await env.KEN_KV.get(`patient:${deviceId}`, 'json');
        if (patient) {
          await env.KEN_PII.put(`retained:patient:${deviceId}`, JSON.stringify({
            data: patient, deletedAt: now, deviceToken,
            retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.medical).toISOString(),
          }));
        }
        const medAlerts = await env.KEN_KV.get(`med-alerts:${deviceId}`, 'json');
        if (medAlerts && medAlerts.length) {
          await env.KEN_PII.put(`retained:med-alerts:${deviceId}`, JSON.stringify({
            data: medAlerts, deletedAt: now, deviceToken,
            retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.medical).toISOString(),
          }));
        }

        // --- Retain feedback (1 year) ---
        const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json');
        if (feedback && feedback.length) {
          const tokenised = feedback.map(f => {
            const updated = { ...f };
            if (emailToToken[updated.from]) updated.from = emailToToken[updated.from];
            return updated;
          });
          await env.KEN_PII.put(`retained:feedback:${deviceId}`, JSON.stringify({
            data: tokenised, deletedAt: now, deviceToken,
            retentionExpiry: new Date(Date.now() + RETENTION_PERIODS.messages).toISOString(),
          }));
        }

        // --- Delete all device KV data (now safely retained in KEN_PII) ---
        const keysToDelete = [
          `device:${deviceId}`, `device-key:${deviceId}`, `heartbeat:${deviceId}`, `heartbeat-time:${deviceId}`,
          `messages:${deviceId}`, `history:${deviceId}`, `contactlist:${deviceId}`, `pending:${deviceId}`,
          `medical:${deviceId}`, `patient:${deviceId}`, `settings:${deviceId}`, `queue:${deviceId}`,
          `reminders:${deviceId}`, `voicemails:${deviceId}`, `callhistory:${deviceId}`,
          `feedback:${deviceId}`, `audit:${deviceId}`, `room:${deviceId}`, `groups:${deviceId}`,
          `offline-alerts:${deviceId}`, `read-receipts:${deviceId}`, `birthday-prefs:${deviceId}`,
          `scheduled-msgs:${deviceId}`, `med-alerts:${deviceId}`,
          `screen:active:${deviceId}`, `screen:frame:${deviceId}`,
          `vm-read-receipts:${deviceId}`, `callhistory:${deviceId}`,
        ];
        for (const key of keysToDelete) {
          await env.KEN_KV.delete(key);
        }

        // --- Clean up per-user keyed data (previously missing cascade) ---
        for (const email of Object.keys(emailToToken)) {
          await env.KEN_KV.delete(`carer-alerts:${deviceId}:${email}`);
          await env.KEN_KV.delete(`check-ins:${deviceId}:${email}`);
          const hqKeys = await env.KEN_KV.list({ prefix: `hq-access:${deviceId}:${email}:` });
          for (const hk of hqKeys.keys) await env.KEN_KV.delete(hk.name);
        }
        await env.KEN_KV.delete(`hq-access-requests:${deviceId}`);

        // Remove from devices:all list
        const devices = await env.KEN_KV.get('devices:all', 'json') || [];
        const filtered = devices.filter(d => d !== deviceId);
        await env.KEN_KV.put('devices:all', JSON.stringify(filtered));

        // Log to retained audit (the device audit was just deleted)
        const decommissionAudit = {
          id: crypto.randomUUID(), userId: auth.user.email, action: 'Device decommissioned (tokenised)',
          timestamp: now, details: { deviceToken, usersTokenised: Object.keys(emailToToken).length },
        };
        const piiAudit = await env.KEN_KV.get('audit:pii-access', 'json') || [];
        piiAudit.push(decommissionAudit);
        await env.KEN_KV.put('audit:pii-access', JSON.stringify(piiAudit));

        return json({ success: true, deviceToken, usersTokenised: Object.keys(emailToToken).length });
      } catch (e) { return json({ error: 'Decommission failed: ' + e.message }, 500); }
    }

    // ===== REMOTE PIN RESET (admin clears device passcode) =====
    if (request.method === 'POST' && path.match(/^\/api\/device\/[\w-]+\/reset-pin$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (userRole !== 'admin' && userRole !== 'hq') return json({ error: 'Admin or HQ access required' }, 403);
      // Queue a settings change to clear the passcode on next sync
      const queue = await env.KEN_KV.get(`queue:${deviceId}`, 'json') || [];
      queue.push({ id: crypto.randomUUID(), setting: 'clearPasscode', value: true, queuedAt: new Date().toISOString() });
      await env.KEN_KV.put(`queue:${deviceId}`, JSON.stringify(queue));
      await logAudit(env, deviceId, auth.user.email, 'Remote PIN reset initiated', {});
      return json({ success: true });
    }

    // ===== CARER CHECK-IN SCHEDULES =====
    if (request.method === 'POST' && path.match(/^\/api\/carer\/check-ins\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const role = getUserRole(auth.user, deviceId);
      if (role !== 'carer' && role !== 'admin') return json({ error: 'Carer or admin access required' }, 403);
      try {
        const body = await request.json();
        const { frequency, preferredTime, type, notes } = body;
        if (!frequency || !preferredTime || !type) return json({ error: 'frequency, preferredTime, and type required' }, 400);
        const validFreqs = ['daily', 'weekly', 'biweekly', 'monthly'];
        if (!validFreqs.includes(frequency)) return json({ error: 'frequency must be: ' + validFreqs.join(', ') }, 400);
        const validTypes = ['visit', 'phone', 'video'];
        if (!validTypes.includes(type)) return json({ error: 'type must be: ' + validTypes.join(', ') }, 400);
        const checkIns = await env.KEN_KV.get(`check-ins:${deviceId}:${auth.user.email}`, 'json') || [];
        const item = {
          id: crypto.randomUUID(),
          carerId: auth.user.email,
          carerName: auth.user.name,
          deviceId,
          frequency,
          preferredTime,
          type,
          notes: sanitize(notes || ''),
          nextDue: calculateNextDue(frequency, preferredTime),
          lastCompleted: null,
          createdAt: new Date().toISOString(),
        };
        checkIns.push(item);
        await env.KEN_KV.put(`check-ins:${deviceId}:${auth.user.email}`, JSON.stringify(checkIns));
        await logAudit(env, deviceId, auth.user.email, 'Created check-in schedule', { frequency, type, time: preferredTime });
        return json({ success: true, checkIn: item });
      } catch (e) { console.error('API error:', e.message); return json({ error: 'Something went wrong. Please try again.' }, 400); }
    }

    // Cross-patient check-in overview (all devices for this carer)
    if (request.method === 'GET' && path === '/api/carer/check-ins-overview') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      if (auth.user.globalRole !== 'carer') return json({ error: 'Carer role required' }, 403);
      const deviceIds = auth.user.carerDevices || [];
      const overview = [];
      for (const did of deviceIds) {
        const info = await env.KEN_KV.get(`device:${did}`, 'json') || {};
        const checkIns = await env.KEN_KV.get(`check-ins:${did}:${auth.user.email}`, 'json') || [];
        for (const ci of checkIns) {
          overview.push({
            ...ci,
            deviceId: did,
            patientName: info.userName || 'Unknown',
          });
        }
      }
      // Sort by time
      overview.sort((a, b) => {
        const ta = a.preferredTime || a.time || '23:59';
        const tb = b.preferredTime || b.time || '23:59';
        return ta.localeCompare(tb);
      });
      return json({ checkIns: overview });
    }

    // List check-ins for this carer + device
    if (request.method === 'GET' && path.match(/^\/api\/carer\/check-ins\/[\w-]+$/)) {
      const deviceId = path.split('/')[4];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const checkIns = await env.KEN_KV.get(`check-ins:${deviceId}:${auth.user.email}`, 'json') || [];
      return json({ checkIns });
    }

    // Mark check-in complete
    if (request.method === 'POST' && path.match(/^\/api\/carer\/check-ins\/[\w-]+\/[\w-]+\/complete$/)) {
      const parts = path.split('/');
      const deviceId = parts[4];
      const checkInId = parts[5];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const checkIns = await env.KEN_KV.get(`check-ins:${deviceId}:${auth.user.email}`, 'json') || [];
      const item = checkIns.find(c => c.id === checkInId);
      if (!item) return json({ error: 'Check-in not found' }, 404);
      item.lastCompleted = new Date().toISOString();
      item.nextDue = calculateNextDue(item.frequency, item.preferredTime);
      await env.KEN_KV.put(`check-ins:${deviceId}:${auth.user.email}`, JSON.stringify(checkIns));
      await logAudit(env, deviceId, auth.user.email, 'Completed check-in', { checkInId, type: item.type });
      return json({ success: true, nextDue: item.nextDue });
    }

    // Delete check-in schedule
    if (request.method === 'DELETE' && path.match(/^\/api\/carer\/check-ins\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[4];
      const checkInId = parts[5];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const checkIns = await env.KEN_KV.get(`check-ins:${deviceId}:${auth.user.email}`, 'json') || [];
      const filtered = checkIns.filter(c => c.id !== checkInId);
      await env.KEN_KV.put(`check-ins:${deviceId}:${auth.user.email}`, JSON.stringify(filtered));
      await logAudit(env, deviceId, auth.user.email, 'Deleted check-in schedule', { checkInId });
      return json({ success: true });
    }

    // ===== MEDIA SERVING (R2) =====
    // Serves photos and voicemails stored in R2 — requires authentication
    if (request.method === 'GET' && path.startsWith('/api/media/')) {
      // Authenticate: session cookie OR device key
      const session = await getSession(request, env);
      const deviceKey = request.headers.get('X-Ken-Device-Key');
      let isDeviceAuthed = false;
      if (!session && deviceKey) {
        // Extract deviceId from the R2 key path (e.g., photos/{deviceId}/... or voicemails/{deviceId}/...)
        const r2Key = path.slice('/api/media/'.length);
        const keyParts = r2Key.split('/');
        if (keyParts.length >= 2) {
          const scopedDeviceId = keyParts[1];
          isDeviceAuthed = await verifyDeviceKey(env, scopedDeviceId, deviceKey);
        }
      }
      if (!session && !isDeviceAuthed) {
        return json({ error: 'Not authenticated' }, 401);
      }
      // Device-level access control: verify user has access to the device in the R2 path
      const r2Key = path.slice('/api/media/'.length);
      if (!r2Key) return json({ error: 'Missing media key' }, 400);
      const r2Parts = r2Key.split('/');
      if (r2Parts.length >= 2) {
        const mediaDeviceId = r2Parts[1];
        if (session) {
          const mediaUser = await env.KEN_KV.get(`user:${session.email}`, 'json');
          if (!mediaUser || !mediaUser.devices || !mediaUser.devices[mediaDeviceId]) {
            return json({ error: 'Access denied to this device media' }, 403);
          }
        }
      }
      if (!env.KEN_MEDIA) {
        return json({ error: 'Media storage not configured' }, 503);
      }
      const object = await env.KEN_MEDIA.get(r2Key);
      if (!object) return json({ error: 'Media not found' }, 404);
      // Determine content type from R2 metadata or file extension
      let contentType = (object.httpMetadata && object.httpMetadata.contentType) || 'application/octet-stream';
      if (contentType === 'application/octet-stream') {
        const extMatch = r2Key.match(/\.(\w+)$/);
        if (extMatch) {
          const extTypes = { jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif', webp: 'image/webp', webm: 'video/webm', mp4: 'video/mp4', mp3: 'audio/mpeg', ogg: 'audio/ogg', wav: 'audio/wav' };
          contentType = extTypes[extMatch[1].toLowerCase()] || contentType;
        }
      }
      return new Response(object.body, {
        headers: {
          'Content-Type': contentType,
          'Cache-Control': 'private, max-age=3600',
          'Access-Control-Allow-Origin': request.headers.get('Origin') || '*',
          'Access-Control-Allow-Credentials': 'true'
        }
      });
    }

    // ===== ESCALATION WORKFLOW =====
    // GET /api/escalation/{deviceId} — return escalation config
    if (request.method === 'GET' && path.match(/^\/api\/escalation\/[\w-]+$/) && !path.includes('/active') && !path.includes('/acknowledge')) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!userRole || !['admin', 'carer', 'hq'].includes(userRole)) return json({ error: 'Insufficient permissions' }, 403);
      const config = await env.KEN_KV.get(`escalation-config:${deviceId}`, 'json');
      if (config) return json(config);
      // Return default config
      return json({
        enabled: true,
        triggers: {
          deviceOffline: { enabled: true, delayMinutes: 5 },
          missedMedication: { enabled: true, delayMinutes: 0 },
          missedCall: { enabled: false, delayMinutes: 0 }
        },
        tiers: [
          { role: 'carer', delayMinutes: 0, method: 'email' },
          { role: 'admin', delayMinutes: 15, method: 'email' },
          { role: 'hq', delayMinutes: 45, method: 'email' }
        ]
      });
    }

    // POST /api/escalation/{deviceId} — save escalation config
    if (request.method === 'POST' && path.match(/^\/api\/escalation\/[\w-]+$/) && !path.includes('/acknowledge')) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!userRole || !['admin', 'carer', 'hq'].includes(userRole)) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const config = {
          enabled: !!body.enabled,
          triggers: {
            deviceOffline: {
              enabled: !!(body.triggers && body.triggers.deviceOffline && body.triggers.deviceOffline.enabled),
              delayMinutes: (body.triggers && body.triggers.deviceOffline && typeof body.triggers.deviceOffline.delayMinutes === 'number') ? body.triggers.deviceOffline.delayMinutes : 5
            },
            missedMedication: {
              enabled: !!(body.triggers && body.triggers.missedMedication && body.triggers.missedMedication.enabled),
              delayMinutes: (body.triggers && body.triggers.missedMedication && typeof body.triggers.missedMedication.delayMinutes === 'number') ? body.triggers.missedMedication.delayMinutes : 0
            },
            missedCall: {
              enabled: !!(body.triggers && body.triggers.missedCall && body.triggers.missedCall.enabled),
              delayMinutes: (body.triggers && body.triggers.missedCall && typeof body.triggers.missedCall.delayMinutes === 'number') ? body.triggers.missedCall.delayMinutes : 0
            }
          },
          tiers: Array.isArray(body.tiers) ? body.tiers.slice(0, 5).map(t => ({
            role: ['carer', 'admin', 'hq'].includes(t.role) ? t.role : 'carer',
            delayMinutes: typeof t.delayMinutes === 'number' ? t.delayMinutes : 0,
            method: t.method === 'email' ? 'email' : 'email'
          })) : [
            { role: 'carer', delayMinutes: 0, method: 'email' },
            { role: 'admin', delayMinutes: 15, method: 'email' },
            { role: 'hq', delayMinutes: 45, method: 'email' }
          ]
        };
        await env.KEN_KV.put(`escalation-config:${deviceId}`, JSON.stringify(config));
        await logAudit(env, deviceId, auth.user.email, 'Updated escalation config', config);
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // POST /api/escalation/{deviceId}/acknowledge — acknowledge an active escalation
    if (request.method === 'POST' && path.match(/^\/api\/escalation\/[\w-]+\/acknowledge$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!userRole) return json({ error: 'Insufficient permissions' }, 403);
      try {
        const body = await request.json();
        const triggerType = body.triggerType;
        if (!triggerType) return json({ error: 'triggerType required' }, 400);
        const escKey = `escalation-active:${deviceId}:${triggerType}`;
        const active = await env.KEN_KV.get(escKey, 'json');
        if (!active) return json({ error: 'No active escalation found' }, 404);
        active.acknowledged = true;
        active.acknowledgedBy = auth.user.email;
        active.acknowledgedAt = new Date().toISOString();
        await env.KEN_KV.put(escKey, JSON.stringify(active), { expirationTtl: 86400 });
        await logAudit(env, deviceId, auth.user.email, 'Acknowledged escalation', { triggerType });
        return json({ success: true });
      } catch {
        return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
      }
    }

    // GET /api/escalation/{deviceId}/active — return active unacknowledged escalations
    if (request.method === 'GET' && path.match(/^\/api\/escalation\/[\w-]+\/active$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const userRole = getUserRole(auth.user, deviceId);
      if (!userRole) return json({ error: 'Insufficient permissions' }, 403);
      const triggerTypes = ['deviceOffline', 'missedMedication', 'missedCall'];
      const active = [];
      for (const tt of triggerTypes) {
        const esc = await env.KEN_KV.get(`escalation-active:${deviceId}:${tt}`, 'json');
        if (esc && !esc.acknowledged) {
          active.push(esc);
        }
      }
      return json({ escalations: active });
    }

    return new Response('Not found', { status: 404 });
  },

  async scheduled(event, env, ctx) {
    // Cron trigger: check all devices for offline alerts
    const devices = await env.KEN_KV.get('devices:all', 'json') || [];
    for (const deviceId of devices) {
      try {
        // Check if device is offline
        const hb = await env.KEN_KV.get(`heartbeat:${deviceId}`, 'json');
        if (hb) continue; // Device is online

        const lastTime = await env.KEN_KV.get(`heartbeat-time:${deviceId}`);
        if (!lastTime) continue;

        const offlineMinutes = Math.floor((Date.now() - new Date(lastTime).getTime()) / 60000);
        const alertSettings = await env.KEN_KV.get(`offline-alerts:${deviceId}`, 'json');
        if (!alertSettings || !alertSettings.enabled) continue;
        if (offlineMinutes < alertSettings.delayMinutes) continue;
        if (alertSettings.lastAlertSent) continue;

        // Send alerts
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || { userName: 'The Ken' };
        const deviceName = deviceInfo.userName || 'The Ken';
        const alertText = deviceName + ' has been offline for ' + offlineMinutes + ' minutes. Please check the internet connection.';
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];

        for (const contactName of alertSettings.contactNames) {
          const contact = contacts.find(c => c.name === contactName);
          if (contact) {
            history.push({
              id: crypto.randomUUID(),
              from: 'System',
              text: alertText,
              sentAt: new Date().toISOString(),
              isSystemAlert: true,
              alertTo: contactName
            });
          }
        }

        if (history.length > 100) history.splice(0, history.length - 100);
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));

        // Email all admin/carer users for this device
        try {
          const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
          for (const key of allUsers.keys) {
            const u = await env.KEN_KV.get(key.name, 'json');
            if (!u || !u.devices || !u.devices[deviceId]) continue;
            const uRole = u.devices[deviceId].role;
            if (uRole === 'admin' || uRole === 'carer') {
              await sendEmail(env, u.email,
                deviceName + ' is offline \u2014 The Ken',
                'Device offline alert',
                '<p style="color:#6B6459;line-height:1.7;"><strong>' + deviceName + '</strong> has been offline for <strong>' + offlineMinutes + ' minutes</strong>.</p>' +
                '<p style="color:#6B6459;line-height:1.7;">Please check the device\'s internet connection and power supply.</p>' +
                '<a href="https://theken.uk/portal/" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Open Portal</a>'
              );
            }
          }
        } catch {}

        // Mark alert as sent
        alertSettings.lastAlertSent = new Date().toISOString();
        await env.KEN_KV.put(`offline-alerts:${deviceId}`, JSON.stringify(alertSettings));
      } catch {
        // Continue to next device on error
      }
    }

    // ===== ESCALATION WORKFLOW PROCESSING =====
    for (const deviceId of devices) {
      try {
        const escConfig = await env.KEN_KV.get(`escalation-config:${deviceId}`, 'json');
        if (!escConfig || !escConfig.enabled) continue;
        const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
        const deviceName = deviceInfo.userName || 'The Ken';
        const escNow = Date.now();

        // Check each trigger
        const triggerChecks = [];

        // 1. Device offline trigger
        if (escConfig.triggers.deviceOffline && escConfig.triggers.deviceOffline.enabled) {
          const hb = await env.KEN_KV.get(`heartbeat:${deviceId}`, 'json');
          if (!hb) {
            const lastTime = await env.KEN_KV.get(`heartbeat-time:${deviceId}`);
            if (lastTime) {
              const offlineMin = Math.floor((escNow - new Date(lastTime).getTime()) / 60000);
              if (offlineMin >= escConfig.triggers.deviceOffline.delayMinutes) {
                triggerChecks.push({ type: 'deviceOffline', message: deviceName + ' has been offline for ' + offlineMin + ' minutes' });
              }
            }
          }
        }

        // 2. Missed medication trigger
        if (escConfig.triggers.missedMedication && escConfig.triggers.missedMedication.enabled) {
          const medAlerts = await env.KEN_KV.get(`med-alerts:${deviceId}`, 'json') || [];
          const unresolved = medAlerts.filter(a => !a.resolved && a.timestamp && (escNow - new Date(a.timestamp).getTime()) > (escConfig.triggers.missedMedication.delayMinutes || 0) * 60000);
          if (unresolved.length > 0) {
            triggerChecks.push({ type: 'missedMedication', message: unresolved.length + ' missed medication reminder' + (unresolved.length > 1 ? 's' : '') + ' for ' + deviceName });
          }
        }

        // 3. Missed call trigger
        if (escConfig.triggers.missedCall && escConfig.triggers.missedCall.enabled) {
          const callData = await env.KEN_KV.get(`callhistory:${deviceId}`, 'json') || {};
          const calls = callData.calls || [];
          const recentMissed = calls.filter(c => c.status === 'missed' && c.timestamp && (escNow - new Date(c.timestamp).getTime()) < 3600000 && (escNow - new Date(c.timestamp).getTime()) > (escConfig.triggers.missedCall.delayMinutes || 0) * 60000);
          if (recentMissed.length > 0) {
            triggerChecks.push({ type: 'missedCall', message: recentMissed.length + ' missed call' + (recentMissed.length > 1 ? 's' : '') + ' for ' + deviceName });
          }
        }

        // Process each triggered condition through escalation tiers
        for (const trigger of triggerChecks) {
          const escKey = `escalation-active:${deviceId}:${trigger.type}`;
          let active = await env.KEN_KV.get(escKey, 'json');

          if (active && active.acknowledged) continue; // Already acknowledged

          if (!active) {
            // Create new escalation
            active = {
              triggerType: trigger.type,
              triggeredAt: new Date().toISOString(),
              currentTier: 0,
              acknowledged: false,
              acknowledgedBy: null,
              acknowledgedAt: null,
              lastNotifiedTier: -1,
              message: trigger.message
            };
          }

          // Determine which tier should be notified based on elapsed time
          const elapsedMin = Math.floor((escNow - new Date(active.triggeredAt).getTime()) / 60000);
          let targetTier = 0;
          for (let i = escConfig.tiers.length - 1; i >= 0; i--) {
            if (elapsedMin >= escConfig.tiers[i].delayMinutes) {
              targetTier = i;
              break;
            }
          }

          // Send notification if we've reached a new tier
          if (targetTier > active.lastNotifiedTier) {
            const tier = escConfig.tiers[targetTier];
            active.currentTier = targetTier;
            active.lastNotifiedTier = targetTier;

            // Find users with the tier's role for this device
            try {
              const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
              for (const key of allUsers.keys) {
                const u = await env.KEN_KV.get(key.name, 'json');
                if (!u || !u.devices) continue;
                const uRole = getUserRole(u, deviceId);
                if (!uRole) continue;
                // Match tier role: 'hq' matches hq, 'admin' matches admin, 'carer' matches carer
                if (uRole === tier.role || (tier.role === 'hq' && u.globalRole === 'hq')) {
                  const tierLabel = 'Tier ' + (targetTier + 1) + ' (' + tier.role + ')';
                  await sendEmail(env, u.email,
                    'Escalation: ' + trigger.message + ' \u2014 The Ken',
                    'Escalation Alert \u2014 ' + tierLabel,
                    '<p style="color:#6B6459;line-height:1.7;"><strong>' + sanitize(trigger.message) + '</strong></p>' +
                    '<p style="color:#6B6459;line-height:1.7;">This is a <strong>' + tierLabel + '</strong> escalation notification. The issue has been active for <strong>' + elapsedMin + ' minutes</strong>.</p>' +
                    '<p style="color:#6B6459;line-height:1.7;">Please log in to the portal to acknowledge and resolve.</p>' +
                    '<a href="https://theken.uk/portal/" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Open Portal</a>'
                  );
                }
              }
            } catch {}
          }

          // Store escalation state (TTL 24h so stale escalations auto-expire)
          await env.KEN_KV.put(escKey, JSON.stringify(active), { expirationTtl: 86400 });
        }
      } catch {
        // Continue to next device on error
      }
    }

    // ===== INTELLIGENT EMAIL NOTIFICATIONS =====
    // Check all devices for unread messages/voicemails/missed calls
    // Email users only if they've been inactive for their configured delay
    const TIMING_MS = { 'immediate': 0, '2min': 120000, '5min': 300000, '15min': 900000, 'hourly': 3600000 };
    const now = Date.now();

    for (const deviceId of devices) {
      try {
        // Get all users with access to this device
        const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
        const callHistoryData = await env.KEN_KV.get(`callhistory:${deviceId}`, 'json') || {};
        const calls = callHistoryData.calls || [];
        const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
        const userName = deviceInfo.userName || 'The Ken';

        for (const key of allUsers.keys) {
          try {
            const u = await env.KEN_KV.get(key.name, 'json');
            if (!u || !u.devices || !u.devices[deviceId]) continue;
            const prefs = await env.KEN_KV.get(`notif-prefs:${u.email}`, 'json') || { timing: '2min', messages: true, voicemails: true, missedCalls: true, medicationAlerts: true };
            if (prefs.timing === 'off') continue;
            const delayMs = TIMING_MS[prefs.timing] || 120000;

            // Check if user is active (suppress email if active)
            const lastActivity = await env.KEN_KV.get(`activity:${u.email}`);
            if (lastActivity && (now - new Date(lastActivity).getTime()) < delayMs) continue;

            let shouldEmail = false;
            let emailSubject = '';
            let emailBody = '';
            const items = [];

            // Check unread messages (replies from device that this user hasn't seen)
            if (prefs.messages) {
              const unread = history.filter(m => m.isReply && !m.readAt && !m.emailNotificationSent && !m.deletedForEveryone &&
                m.sentAt && (now - new Date(m.sentAt).getTime()) > delayMs);
              if (unread.length > 0) {
                items.push(unread.length + ' new message' + (unread.length > 1 ? 's' : '') + ' from ' + userName);
                // Mark as notified
                unread.forEach(m => { m.emailNotificationSent = true; });
                shouldEmail = true;
              }
            }

            // Check unwatched voicemails
            if (prefs.voicemails) {
              const unwatched = voicemails.filter(v => !v.played && !v.emailNotificationSent &&
                v.timestamp && (now - new Date(v.timestamp).getTime()) > delayMs);
              if (unwatched.length > 0) {
                items.push(unwatched.length + ' new voicemail' + (unwatched.length > 1 ? 's' : ''));
                unwatched.forEach(v => { v.emailNotificationSent = true; });
                shouldEmail = true;
              }
            }

            // Check missed calls (last 24h, not already notified)
            if (prefs.missedCalls) {
              const missed = calls.filter(c => c.status === 'missed' && !c.emailNotificationSent &&
                c.timestamp && (now - new Date(c.timestamp).getTime()) > delayMs &&
                (now - new Date(c.timestamp).getTime()) < 86400000);
              if (missed.length > 0) {
                items.push(missed.length + ' missed call' + (missed.length > 1 ? 's' : ''));
                missed.forEach(c => { c.emailNotificationSent = true; });
                shouldEmail = true;
              }
            }

            if (shouldEmail && items.length > 0) {
              emailSubject = items[0] + ' — The Ken';
              emailBody = '<p style="color:#6B6459;line-height:1.7;">You have notifications from <strong>' + sanitize(userName) + '</strong>:</p>' +
                '<ul style="color:#1A1714;line-height:2;">' + items.map(i => '<li>' + i + '</li>').join('') + '</ul>' +
                '<a href="https://theken.uk/portal/" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Open Portal</a>';
              await sendEmail(env, u.email, emailSubject, 'New notifications', emailBody);
            }
          } catch {}
        }

        // Persist emailNotificationSent flags
        if (history.length > 0) await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        if (voicemails.length > 0) await env.KEN_KV.put(`voicemails:${deviceId}`, JSON.stringify(voicemails));
        if (calls.length > 0) await env.KEN_KV.put(`callhistory:${deviceId}`, JSON.stringify({ calls }));
      } catch {}
    }

    // ===== SCHEDULED MESSAGE DELIVERY =====
    for (const deviceId of devices) {
      try {
        const scheduled = await env.KEN_KV.get(`scheduled-msgs:${deviceId}`, 'json') || [];
        let modified = false;
        for (const item of scheduled) {
          if (item.status !== 'scheduled') continue;
          if (new Date(item.scheduledFor).getTime() > now) continue;
          // Deliver this message
          item.status = 'sent';
          const message = {
            id: crypto.randomUUID(), from: item.from, fromEmail: item.fromEmail, text: item.text,
            sentAt: new Date().toISOString(), deliveredAt: null, readAt: null,
            deletedBySender: false, deletedByRecipient: false, deletedForEveryone: false, emailNotificationSent: false,
            wasScheduled: true,
          };
          const pending = await env.KEN_KV.get(`messages:${deviceId}`, 'json') || [];
          pending.push(message);
          await env.KEN_KV.put(`messages:${deviceId}`, JSON.stringify(pending));
          const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
          history.push(message);
          if (history.length > 100) history.splice(0, history.length - 100);
          await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
          modified = true;
        }
        if (modified) await env.KEN_KV.put(`scheduled-msgs:${deviceId}`, JSON.stringify(scheduled));
      } catch {}
    }

    // ===== CARER CHECK-IN REMINDERS =====
    // Email carers 30 minutes before their scheduled check-ins
    for (const deviceId of devices) {
      try {
        const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
        for (const key of allUsers.keys) {
          try {
            const u = await env.KEN_KV.get(key.name, 'json');
            if (!u || !u.devices || !u.devices[deviceId]) continue;
            const uRole = u.devices[deviceId].role;
            if (uRole !== 'carer' && uRole !== 'admin') continue;
            const checkIns = await env.KEN_KV.get(`check-ins:${deviceId}:${u.email}`, 'json') || [];
            const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
            const userName = deviceInfo.userName || 'The Ken user';
            for (const ci of checkIns) {
              if (!ci.nextDue) continue;
              const dueTime = new Date(ci.nextDue).getTime();
              const thirtyMinBefore = dueTime - 1800000;
              // Send reminder if we're within the 30-min window and haven't sent one yet
              if (now >= thirtyMinBefore && now < dueTime && !ci.reminderSent) {
                ci.reminderSent = true;
                await sendEmail(env, u.email,
                  'Check-in reminder — ' + userName,
                  'Upcoming check-in',
                  '<p style="color:#6B6459;line-height:1.7;">You have a <strong>' + ci.type + '</strong> check-in with <strong>' + sanitize(userName) + '</strong> in 30 minutes.</p>' +
                  (ci.notes ? '<p style="color:#6B6459;line-height:1.7;">Notes: ' + sanitize(ci.notes) + '</p>' : '') +
                  '<a href="https://theken.uk/portal/" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Open Portal</a>'
                );
              }
              // Reset reminder flag when due time passes (for next cycle)
              if (now > dueTime && ci.reminderSent) {
                ci.reminderSent = false;
              }
            }
            await env.KEN_KV.put(`check-ins:${deviceId}:${u.email}`, JSON.stringify(checkIns));
          } catch {}
        }
      } catch {}
    }

    // ===== BIRTHDAY REMINDERS =====
    const today = new Date();
    const todayMonth = today.getUTCMonth() + 1;
    const todayDay = today.getUTCDate();
    const currentHour = today.getUTCHours();
    const currentMinute = today.getUTCMinutes();

    for (const deviceId of devices) {
      try {
        const prefs = await env.KEN_KV.get(`birthday-prefs:${deviceId}`, 'json');
        if (!prefs || !prefs.enabled) continue;
        const [notifH, notifM] = (prefs.notifyTime || '09:00').split(':').map(Number);
        // Only check within the 2-minute cron window of the notification time
        if (currentHour !== notifH || currentMinute < notifM || currentMinute > notifM + 2) continue;
        const daysBefore = prefs.daysBefore || [0, 1, 7];
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
        const userName = deviceInfo.userName || 'The Ken user';
        const sentKey = `birthday-sent:${deviceId}:${today.toISOString().slice(0, 10)}`;
        const alreadySent = await env.KEN_KV.get(sentKey, 'json') || [];

        for (const contact of contacts) {
          if (!contact.birthday) continue;
          const [bYear, bMonth, bDay] = contact.birthday.split('-').map(Number);
          // Check each daysBefore offset
          for (const daysOffset of daysBefore) {
            const targetDate = new Date(Date.UTC(today.getUTCFullYear(), todayMonth - 1, todayDay + daysOffset));
            const targetMonth = targetDate.getUTCMonth() + 1;
            const targetDay = targetDate.getUTCDate();
            if (bMonth === targetMonth && bDay === targetDay) {
              const notifKey = contact.id + ':' + daysOffset;
              if (alreadySent.includes(notifKey)) continue;
              alreadySent.push(notifKey);
              // Send birthday reminder to all admin/carer users
              const allUsers = await env.KEN_KV.list({ prefix: 'user:' });
              const msgText = daysOffset === 0
                ? "Today is " + contact.name + "'s birthday!"
                : contact.name + "'s birthday is in " + daysOffset + " day" + (daysOffset > 1 ? 's' : '') + " (" + contact.birthday + ")";
              for (const key of allUsers.keys) {
                try {
                  const u = await env.KEN_KV.get(key.name, 'json');
                  if (!u || !u.devices || !u.devices[deviceId]) continue;
                  await sendEmail(env, u.email,
                    (daysOffset === 0 ? "Happy birthday " + contact.name + "!" : "Birthday reminder — " + contact.name) + " — The Ken",
                    daysOffset === 0 ? 'Happy birthday!' : 'Birthday reminder',
                    '<p style="color:#6B6459;line-height:1.7;">' + msgText + '</p>' +
                    '<p style="color:#6B6459;line-height:1.7;">Send ' + sanitize(userName) + ' a message or give them a call.</p>' +
                    '<a href="https://theken.uk/portal/" style="display:inline-block;background:#C4A962;color:#1A1714;text-decoration:none;padding:12px 28px;font-weight:500;font-size:14px;letter-spacing:1px;text-transform:uppercase;margin:16px 0;">Open Portal</a>'
                  );
                } catch {}
              }
            }
          }
        }
        await env.KEN_KV.put(sentKey, JSON.stringify(alreadySent), { expirationTtl: 86400 });
      } catch {}
    }

    // ===== RETENTION PURGE: delete expired PII tokens and retained records =====
    // Runs every 2 minutes with existing cron, but only processes once per day
    const purgeCheck = await env.KEN_KV.get('retention-purge-last', 'json');
    const todayStr = new Date().toISOString().slice(0, 10);
    if (!purgeCheck || purgeCheck.date !== todayStr) {
      try {
        let purged = 0;
        const now = Date.now();

        // Purge expired PII token mappings
        const piiKeys = await env.KEN_PII.list({ prefix: 'pii:' });
        for (const key of piiKeys.keys) {
          try {
            const record = await env.KEN_PII.get(key.name, 'json');
            if (record && record.retentionExpiry && new Date(record.retentionExpiry).getTime() <= now) {
              await env.KEN_PII.delete(key.name);
              purged++;
            }
          } catch {}
        }

        // Purge expired retained records (history, audit, medical, feedback)
        const retainedKeys = await env.KEN_PII.list({ prefix: 'retained:' });
        for (const key of retainedKeys.keys) {
          try {
            const record = await env.KEN_PII.get(key.name, 'json');
            if (record && record.retentionExpiry && new Date(record.retentionExpiry).getTime() <= now) {
              await env.KEN_PII.delete(key.name);
              purged++;
            }
          } catch {}
        }

        await env.KEN_KV.put('retention-purge-last', JSON.stringify({ date: todayStr, purged }), { expirationTtl: 86400 });
      } catch {}
    }

    // ===== BREACH DETECTION: anomaly monitoring =====
    try {
      const now = Date.now();
      const window5min = 5 * 60 * 1000;

      // Check for excessive auth failures (potential brute force)
      const rlKeys = await env.KEN_KV.list({ prefix: 'ratelimit:login:' });
      for (const key of rlKeys.keys) {
        const rl = await env.KEN_KV.get(key.name, 'json');
        if (rl && rl.count >= 10 && (now - rl.start) < window5min) {
          const ip = key.name.replace('ratelimit:login:', '');
          const alertKey = `breach-alert:login:${ip}`;
          const existing = await env.KEN_KV.get(alertKey);
          if (!existing) {
            const globalAudit = await env.KEN_KV.get('audit:pii-access', 'json') || [];
            globalAudit.push({
              id: crypto.randomUUID(), type: 'BREACH_ALERT', severity: 'HIGH',
              description: 'Excessive login failures from IP ' + ip + ' (' + rl.count + ' attempts)',
              timestamp: new Date().toISOString(),
            });
            await env.KEN_KV.put('audit:pii-access', JSON.stringify(globalAudit));
            await env.KEN_KV.put(alertKey, '1', { expirationTtl: 3600 }); // Don't re-alert for 1hr
          }
        }
      }

      // Check for excessive PII resolve activity (potential data exfiltration)
      const piiAudit = await env.KEN_KV.get('audit:pii-access', 'json') || [];
      const recentPiiAccess = piiAudit.filter(a => a.token && (now - new Date(a.timestamp).getTime()) < window5min);
      if (recentPiiAccess.length >= 5) {
        const alertKey = 'breach-alert:pii-bulk';
        const existing = await env.KEN_KV.get(alertKey);
        if (!existing) {
          piiAudit.push({
            id: crypto.randomUUID(), type: 'BREACH_ALERT', severity: 'CRITICAL',
            description: 'Bulk PII token resolution detected: ' + recentPiiAccess.length + ' lookups in 5 minutes',
            users: [...new Set(recentPiiAccess.map(a => a.accessedBy))],
            timestamp: new Date().toISOString(),
          });
          await env.KEN_KV.put('audit:pii-access', JSON.stringify(piiAudit));
          await env.KEN_KV.put(alertKey, '1', { expirationTtl: 3600 });
        }
      }

      // Check for excessive password reset attempts
      const resetKeys = await env.KEN_KV.list({ prefix: 'ratelimit:forgot:' });
      for (const key of resetKeys.keys) {
        const rl = await env.KEN_KV.get(key.name, 'json');
        if (rl && rl.count >= 5 && (now - rl.start) < window5min) {
          const ip = key.name.replace('ratelimit:forgot:', '');
          const alertKey = `breach-alert:reset:${ip}`;
          const existing = await env.KEN_KV.get(alertKey);
          if (!existing) {
            const globalAudit = await env.KEN_KV.get('audit:pii-access', 'json') || [];
            globalAudit.push({
              id: crypto.randomUUID(), type: 'BREACH_ALERT', severity: 'MEDIUM',
              description: 'Excessive password reset attempts from IP ' + ip + ' (' + rl.count + ' attempts)',
              timestamp: new Date().toISOString(),
            });
            await env.KEN_KV.put('audit:pii-access', JSON.stringify(globalAudit));
            await env.KEN_KV.put(alertKey, '1', { expirationTtl: 3600 });
          }
        }
      }
    } catch {} // Breach detection should never break the cron

    // Daily summary email removed — dashboard is source of truth for daily activity
  },
};

async function handleAddContact(request, env, deviceId) {
  try {
    const body = await request.json();
    const { name, relationship, phoneNumber, photo, birthday } = body;
    if (!name || !name.trim()) {
      return json({ error: 'Name is required' }, 400);
    }
    const existing = await env.KEN_KV.get(`pending:${deviceId}`, 'json') || [];
    const contact = {
      id: crypto.randomUUID(),
      name: sanitize(name),
      relationship: sanitize(relationship || ''),
      phoneNumber: sanitize(phoneNumber || ''),
      birthday: sanitize(birthday || ''),
      photo: photo || '',
      submittedAt: new Date().toISOString(),
    };
    existing.push(contact);
    await env.KEN_KV.put(`pending:${deviceId}`, JSON.stringify(existing));
    return json({ success: true, contact: { name: contact.name, id: contact.id } });
  } catch {
    return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
  }
}

async function handleSendMessage(request, env, deviceId) {
  try {
    const body = await request.json();
    const { from, text } = body;
    if (!from || !text || !text.trim()) {
      return json({ error: 'From and text are required' }, 400);
    }
    // Attach sender email if authenticated
    const session = await getSession(request, env);
    const senderEmail = session ? session.email : null;
    const message = {
      id: crypto.randomUUID(),
      from: sanitize(from),
      fromEmail: senderEmail,
      text: sanitize(text),
      sentAt: new Date().toISOString(),
      deliveredAt: null,
      readAt: null,
      deletedBySender: false,
      deletedByRecipient: false,
      deletedForEveryone: false,
      emailNotificationSent: false,
    };

    // Add to pending (Pi will poll this)
    const pending = await env.KEN_KV.get(`messages:${deviceId}`, 'json') || [];
    pending.push(message);
    await env.KEN_KV.put(`messages:${deviceId}`, JSON.stringify(pending));

    // Add to history (family can see sent messages)
    const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
    history.push(message);
    // Keep last 100 messages
    if (history.length > 100) history.splice(0, history.length - 100);
    await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));

    return json({ success: true, message: { id: message.id } });
  } catch {
    return json({ error: 'Something went wrong. Please check your input and try again.' }, 400);
  }
}

function json(data, status = 200, corsHeaders = null) {
  const cors = corsHeaders || _currentCorsHeaders || {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Ken-CSRF, X-Ken-Device-Key',
    'Access-Control-Allow-Credentials': 'true',
  };
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains', ...cors },
  });
}

function html(body) {
  return new Response(body, {
    headers: {
      'Content-Type': 'text/html',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' https://api.theken.uk https://*.daily.co wss://*.daily.co; frame-src https://*.daily.co; media-src 'self' blob:",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
  });
}

// ===== EMAIL (Resend) =====
function emailTemplate(heading, bodyHtml) {
  return '<div style="font-family:Jost,Helvetica,sans-serif;max-width:480px;margin:0 auto;padding:32px;background:#FDFAF5;">' +
    '<div style="border-bottom:2px solid #C4A962;padding-bottom:16px;margin-bottom:24px;">' +
      '<span style="font-family:Georgia,serif;font-size:20px;font-weight:300;letter-spacing:3px;color:#1A1714;">THE KEN</span>' +
    '</div>' +
    '<h1 style="font-size:22px;font-weight:500;color:#1A1714;margin-bottom:12px;">' + heading + '</h1>' +
    bodyHtml +
    '<p style="color:#6B6459;font-size:12px;opacity:0.5;margin-top:32px;border-top:1px solid #E8E3DA;padding-top:16px;">&copy; 2026 The Ken &middot; theken.uk</p>' +
  '</div>';
}

async function sendEmail(env, to, subject, heading, bodyHtml) {
  if (!env.RESEND_API_KEY) return false;
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'The Ken <hello@theken.uk>',
        to,
        subject,
        html: emailTemplate(heading, bodyHtml),
      })
    });
    return true;
  } catch {
    return false;
  }
}

// ===== ADD CONTACT HTML =====
// ===== ADMIN FEEDBACK VIEWER =====
function feedbackViewerHTML(deviceId) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>The Ken — Feedback</title>
  <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400&family=Jost:wght@300;400;500&display=swap" rel="stylesheet" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Jost', sans-serif; background: #FDFAF5; color: #1A1714; min-height: 100vh; max-width: 640px; margin: 0 auto; padding: 24px; }
    h1 { font-family: 'Cormorant Garamond', serif; font-weight: 400; font-size: 28px; margin-bottom: 4px; }
    .subtitle { font-size: 14px; color: #6B6459; margin-bottom: 24px; }
    .item { background: #fff; border: 2px solid rgba(196,169,98,0.2); border-radius: 12px; padding: 16px; margin-bottom: 12px; }
    .item-from { font-weight: 500; font-size: 15px; color: #C4A962; margin-bottom: 4px; }
    .item-text { font-size: 16px; color: #1A1714; line-height: 1.4; margin-bottom: 8px; }
    .item-time { font-size: 13px; color: #6B6459; }
    .item-audio { margin-top: 8px; }
    .item-audio audio { width: 100%; }
    .empty { text-align: center; padding: 48px; color: #6B6459; }
    .voice-badge { display: inline-block; background: rgba(196,169,98,0.15); color: #C4A962; font-size: 12px; font-weight: 500; padding: 2px 8px; border-radius: 6px; margin-left: 8px; }
    .status-badge { display: inline-block; font-size: 12px; font-weight: 500; padding: 2px 10px; border-radius: 6px; margin-left: 8px; }
    .status-open { background: rgba(59,130,246,0.15); color: #3B82F6; }
    .status-in-progress { background: rgba(245,158,11,0.15); color: #F59E0B; }
    .status-resolved { background: rgba(34,197,94,0.15); color: #22C55E; }
    .status-closed { background: rgba(107,100,89,0.15); color: #6B6459; }
    .category-badge { display: inline-block; background: rgba(139,92,246,0.12); color: #8B5CF6; font-size: 12px; font-weight: 500; padding: 2px 8px; border-radius: 6px; margin-right: 8px; }
    .reply-count { display: inline-block; font-size: 12px; color: #6B6459; margin-left: 8px; }
    .item-meta { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; margin-bottom: 8px; }
  </style>
</head>
<body>
  <h1>Feedback</h1>
  <div class="subtitle">Device: ${escapeHtml(deviceId)}</div>
  <div id="feedbackList"><div class="empty">Loading...</div></div>
  <script>
    function esc(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;'); }
    function escAttr(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    async function load() {
      try {
        const resp = await fetch('/api/feedback/${escapeHtml(deviceId)}');
        const data = await resp.json();
        const list = document.getElementById('feedbackList');
        if (!data.feedback || data.feedback.length === 0) {
          list.innerHTML = '<div class="empty">No feedback yet.</div>';
          return;
        }
        list.innerHTML = data.feedback.slice().reverse().map(f => {
          const date = new Date(f.timestamp);
          const timeStr = date.toLocaleDateString('en-GB', { day:'numeric', month:'short', year:'numeric' }) + ' at ' +
            date.toLocaleTimeString('en-GB', { hour:'2-digit', minute:'2-digit' });
          let content = '';
          if (f.type === 'voice' && f.audio) {
            content = '<div class="item-text"><span class="voice-badge">Voice message</span></div>' +
              '<div class="item-audio"><audio controls src="' + escAttr(f.audio) + '"></audio></div>';
          } else if (f.text) {
            content = '<div class="item-text">' + f.text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
          } else if (f.rating) {
            content = '<div class="item-text">Rating: ' + f.rating + '</div>';
          }
          let screenshotHtml = '';
          if (f.screenshot) {
            screenshotHtml = '<div style="margin-top:8px;"><img src="' + escAttr(f.screenshot) + '" style="max-width:100%;border-radius:8px;border:1px solid rgba(196,169,98,0.2);" alt="Screenshot at time of feedback" /></div>';
          }
          let recentScreensHtml = '';
          if (f.recentScreens && f.recentScreens.length > 0) {
            recentScreensHtml = '<div style="margin-top:12px;"><strong>Recent screens (' + f.recentScreens.length + '):</strong><div style="display:flex;gap:8px;overflow-x:auto;padding:8px 0;">' +
              f.recentScreens.map(function(s) {
                return '<div style="flex-shrink:0;text-align:center;"><img src="' + escAttr(s.frame) + '" style="height:200px;border:1px solid #ccc;border-radius:4px;" /><div style="font-size:11px;color:#666;margin-top:4px;">' + esc(s.screen) + ' — ' + esc(new Date(s.timestamp).toLocaleTimeString()) + '</div></div>';
              }).join('') +
            '</div></div>';
          }
          let categoryHtml = '';
          if (f.category) {
            categoryHtml = '<span class="category-badge">' + esc(f.category) + '</span>';
          }
          const statusClass = f.status ? 'status-' + esc(f.status) : 'status-open';
          const statusLabel = f.status ? esc(f.status.replace('-', ' ')) : 'open';
          const statusHtml = '<span class="status-badge ' + statusClass + '">' + statusLabel + '</span>';
          const replyCount = f.replies ? f.replies.length : 0;
          const replyHtml = replyCount > 0 ? '<span class="reply-count">' + replyCount + ' repl' + (replyCount === 1 ? 'y' : 'ies') + '</span>' : '';
          const submitter = f.submittedBy ? ' (' + esc(f.submittedBy.email) + ')' : '';
          return '<div class="item">' +
            '<div class="item-meta">' +
              '<span class="item-from" style="margin-bottom:0;">' + esc(f.from || 'Unknown') + submitter + '</span>' +
              statusHtml + categoryHtml + replyHtml +
            '</div>' +
            content +
            screenshotHtml +
            recentScreensHtml +
            (f.page ? '<div style="font-size:12px;color:#8B5CF6;margin-top:4px;">Page: ' + esc(f.page) + '</div>' : '') +
            '<div class="item-time">' + esc(timeStr) + (f.id ? ' &middot; #' + esc(f.id.slice(0,8)) : '') + '</div>' +
            '</div>';
        }).join('');
      } catch {
        document.getElementById('feedbackList').innerHTML = '<div class="empty">Could not load feedback.</div>';
      }
    }
    load();
  </script>
</body>
</html>`;
}

function addContactHTML(deviceId) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Add Yourself to The Ken</title>
  <link href="https://fonts.googleapis.com/css2?family=Jost:wght@300;400;500&display=swap" rel="stylesheet" />
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Jost', sans-serif; background: #FDFAF5; color: #1A1714; min-height: 100vh; padding: 24px; max-width: 480px; margin: 0 auto; }
    h1 { font-weight: 400; font-size: 28px; text-align: center; margin-bottom: 8px; }
    .subtitle { font-weight: 300; font-size: 16px; color: #6B6459; text-align: center; margin-bottom: 32px; }
    label { display: block; font-weight: 400; font-size: 16px; color: #6B6459; margin-bottom: 8px; margin-top: 20px; }
    input[type="text"], input[type="tel"] { width: 100%; padding: 16px; font-family: 'Jost', sans-serif; font-size: 18px; border: 2px solid rgba(196, 169, 98, 0.3); border-radius: 12px; background: #fff; color: #1A1714; outline: none; }
    input:focus { border-color: #C4A962; }
    .photo-area { margin-top: 20px; display: flex; flex-direction: column; align-items: center; gap: 12px; }
    .photo-preview { width: 150px; height: 150px; border-radius: 12px; border: 3px solid #F5F0E8; background: #F5F0E8; overflow: hidden; display: flex; align-items: center; justify-content: center; color: #6B6459; font-size: 14px; }
    .photo-preview img { width: 100%; height: 100%; object-fit: cover; }
    .photo-buttons { display: flex; gap: 12px; }
    .photo-btn { font-family: 'Jost', sans-serif; font-weight: 400; font-size: 16px; color: #C4A962; background: #F5F0E8; border: 2px solid rgba(196, 169, 98, 0.3); border-radius: 10px; padding: 12px 20px; cursor: pointer; }
    .submit-btn { width: 100%; margin-top: 32px; padding: 18px; font-family: 'Jost', sans-serif; font-weight: 500; font-size: 20px; color: #FDFAF5; background: #C4A962; border: none; border-radius: 14px; cursor: pointer; }
    .submit-btn:disabled { background: rgba(196, 169, 98, 0.4); color: #6B6459; }
    .success { display: none; text-align: center; padding: 48px 24px; }
    .success h2 { font-weight: 400; font-size: 28px; color: #C4A962; margin-bottom: 16px; }
    .success p { font-weight: 300; font-size: 18px; color: #6B6459; }
  </style>
</head>
<body>
  <div id="formArea">
    <h1>Add Yourself to The Ken</h1>
    <div class="subtitle">Fill in your details to appear on this device</div>

    <label for="nameInput">Your Name *</label>
    <input type="text" id="nameInput" placeholder="e.g. Sarah" autocomplete="name" />

    <label for="relInput">Relationship</label>
    <input type="text" id="relInput" placeholder="e.g. Daughter, Son, GP, Friend" />

    <label for="phoneInput">Phone Number</label>
    <input type="tel" id="phoneInput" placeholder="e.g. +44 7700 900001" autocomplete="tel" />

    <div class="photo-area">
      <label style="margin:0;">Your Photo</label>
      <div class="photo-preview" id="photoPreview">No photo</div>
      <div class="photo-buttons">
        <input type="file" id="cameraInput" accept="image/*" capture="user" onchange="handlePhoto(event)" style="display:none;" />
        <button class="photo-btn" onclick="document.getElementById('cameraInput').click()">Take Selfie</button>
        <input type="file" id="galleryInput" accept="image/*" onchange="handlePhoto(event)" style="display:none;" />
        <button class="photo-btn" onclick="document.getElementById('galleryInput').click()">Choose Photo</button>
      </div>
    </div>

    <button class="submit-btn" id="submitBtn" onclick="submitContact()">Add Me to The Ken</button>
  </div>

  <div class="success" id="successArea">
    <h2>You have been added</h2>
    <p>Your contact will appear on The Ken shortly.</p>
  </div>

  <script>
    const DEVICE_ID = '${deviceId}';
    let photoBase64 = '';

    function handlePhoto(e) {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (ev) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          canvas.width = 480; canvas.height = 480;
          const ctx = canvas.getContext('2d');
          const size = Math.min(img.width, img.height);
          const sx = (img.width - size) / 2;
          const sy = (img.height - size) / 2;
          ctx.drawImage(img, sx, sy, size, size, 0, 0, 480, 480);
          photoBase64 = canvas.toDataURL('image/jpeg', 0.8);
          document.getElementById('photoPreview').innerHTML = '<img src="' + photoBase64 + '" />';
        };
        img.src = ev.target.result;
      };
      reader.readAsDataURL(file);
    }

    async function submitContact() {
      const name = document.getElementById('nameInput').value.trim();
      if (!name) { alert('Please enter your name'); return; }
      const btn = document.getElementById('submitBtn');
      btn.disabled = true; btn.textContent = 'Adding...';
      try {
        const resp = await fetch('/api/contacts/' + DEVICE_ID, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name, relationship: document.getElementById('relInput').value.trim(),
            phoneNumber: document.getElementById('phoneInput').value.trim(),
            photo: photoBase64 || ''
          })
        });
        const data = await resp.json();
        if (data.success) {
          document.getElementById('formArea').style.display = 'none';
          document.getElementById('successArea').style.display = 'block';
        } else {
          alert('Error: ' + (data.error || 'Unknown error'));
          btn.disabled = false; btn.textContent = 'Add Me to The Ken';
        }
      } catch (err) {
        alert('Something went wrong. Please try again.');
        btn.disabled = false; btn.textContent = 'Add Me to The Ken';
      }
    }
  </script>
</body>
</html>`;
}

// ===== FAMILY INTERFACE HTML =====
function familyHTML(deviceId) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>The Ken — Family</title>
  <link rel="manifest" href="data:application/json,${encodeURIComponent(JSON.stringify({
    name: 'The Ken',
    short_name: 'The Ken',
    start_url: '/family/' + deviceId,
    display: 'standalone',
    background_color: '#FDFAF5',
    theme_color: '#C4A962'
  }))}">
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-title" content="The Ken" />
  <meta name="theme-color" content="#C4A962" />
  <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@300;400&family=Jost:wght@300;400;500&display=swap" rel="stylesheet" />
  <script crossorigin src="https://unpkg.com/@daily-co/daily-js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Jost', sans-serif; background: #FDFAF5; color: #1A1714; min-height: 100vh; max-width: 480px; margin: 0 auto; }

    .header {
      background: #F5F0E8;
      padding: 20px 24px;
      border-bottom: 2px solid rgba(196, 169, 98, 0.25);
      text-align: center;
    }
    .header h1 {
      font-family: 'Cormorant Garamond', serif;
      font-weight: 400;
      font-size: 28px;
      color: #1A1714;
    }
    .header .subtitle {
      font-weight: 300;
      font-size: 14px;
      color: #6B6459;
      margin-top: 4px;
    }

    .tab-bar {
      display: flex;
      border-bottom: 2px solid rgba(196, 169, 98, 0.15);
    }
    .tab {
      flex: 1;
      font-family: 'Jost', sans-serif;
      font-weight: 400;
      font-size: 15px;
      color: #6B6459;
      background: none;
      border: none;
      padding: 12px 6px;
      cursor: pointer;
      text-align: center;
      border-bottom: 3px solid transparent;
      margin-bottom: -2px;
    }
    .tab.active {
      color: #C4A962;
      font-weight: 500;
      border-bottom-color: #C4A962;
    }

    .panel { display: none; padding: 24px; }
    .panel.active { display: block; }

    /* Message compose */
    .compose-area { margin-bottom: 24px; }
    .compose-label {
      font-weight: 400;
      font-size: 14px;
      color: #6B6459;
      margin-bottom: 8px;
      display: block;
    }
    .compose-input {
      width: 100%;
      padding: 14px;
      font-family: 'Jost', sans-serif;
      font-size: 16px;
      border: 2px solid rgba(196, 169, 98, 0.3);
      border-radius: 12px;
      background: #fff;
      color: #1A1714;
      outline: none;
      margin-bottom: 12px;
    }
    .compose-input:focus { border-color: #C4A962; }
    textarea.compose-input { min-height: 100px; resize: vertical; font-family: 'Jost', sans-serif; }
    .send-btn {
      width: 100%;
      padding: 16px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 18px;
      color: #FDFAF5;
      background: #C4A962;
      border: none;
      border-radius: 12px;
      cursor: pointer;
    }
    .send-btn:disabled { background: rgba(196, 169, 98, 0.4); color: #6B6459; }
    .send-btn:active { background: #D9C48A; }

    .send-success {
      display: none;
      text-align: center;
      padding: 16px;
      background: rgba(196, 169, 98, 0.15);
      border-radius: 12px;
      color: #C4A962;
      font-weight: 500;
      margin-bottom: 24px;
    }

    /* Message history */
    .message-list { display: flex; flex-direction: column; gap: 12px; }
    .message-item {
      background: #fff;
      border: 2px solid rgba(196, 169, 98, 0.2);
      border-radius: 12px;
      padding: 14px 16px;
    }
    .message-from {
      font-weight: 500;
      font-size: 14px;
      color: #C4A962;
      margin-bottom: 4px;
    }
    .message-text {
      font-weight: 400;
      font-size: 16px;
      color: #1A1714;
      line-height: 1.4;
      margin-bottom: 6px;
    }
    .message-time {
      font-weight: 300;
      font-size: 13px;
      color: #6B6459;
    }
    .empty-state {
      text-align: center;
      padding: 48px 24px;
      color: #6B6459;
      font-weight: 300;
      font-size: 16px;
    }

    /* Your name setup */
    .name-setup {
      background: rgba(196, 169, 98, 0.1);
      border: 2px solid rgba(196, 169, 98, 0.3);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
      text-align: center;
    }
    .name-setup p { font-size: 14px; color: #6B6459; margin-bottom: 12px; }
    .name-setup input {
      width: 100%;
      padding: 12px;
      font-family: 'Jost', sans-serif;
      font-size: 18px;
      border: 2px solid rgba(196, 169, 98, 0.3);
      border-radius: 10px;
      background: #fff;
      color: #1A1714;
      outline: none;
      text-align: center;
      margin-bottom: 12px;
    }
    .name-setup button {
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 16px;
      color: #FDFAF5;
      background: #C4A962;
      border: none;
      border-radius: 10px;
      padding: 12px 32px;
      cursor: pointer;
    }

    .bookmark-hint {
      background: rgba(196, 169, 98, 0.08);
      border-radius: 12px;
      padding: 16px;
      margin-top: 24px;
      text-align: center;
    }
    .bookmark-hint p {
      font-size: 14px;
      color: #6B6459;
      line-height: 1.5;
    }
    .bookmark-hint strong { color: #C4A962; }

    /* Call panel */
    .call-btn {
      width: 100%;
      padding: 24px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 22px;
      color: #FDFAF5;
      background: #C4A962;
      border: none;
      border-radius: 14px;
      cursor: pointer;
      margin-bottom: 20px;
    }
    .call-btn:disabled { background: rgba(196, 169, 98, 0.4); color: #6B6459; }
    .call-btn:active { background: #D9C48A; }

    .call-status {
      text-align: center;
      font-weight: 400;
      font-size: 16px;
      color: #6B6459;
      margin-bottom: 20px;
      line-height: 1.5;
    }

    .call-active-area {
      display: none;
      flex-direction: column;
      align-items: center;
    }
    .call-active-area.visible { display: flex; }

    .call-video-container {
      width: 100%;
      aspect-ratio: 3/4;
      max-height: 50vh;
      background: #1A1714;
      border-radius: 14px;
      overflow: hidden;
      position: relative;
      margin-bottom: 20px;
    }
    .call-video-container video {
      width: 100%;
      height: 100%;
      object-fit: cover;
    }
    .call-local-pip {
      position: absolute;
      bottom: 12px;
      right: 12px;
      width: 100px;
      height: 133px;
      border-radius: 10px;
      border: 2px solid #C4A962;
      overflow: hidden;
      background: #333;
    }
    .call-local-pip video {
      width: 100%;
      height: 100%;
      object-fit: cover;
      transform: scaleX(-1);
    }

    .end-call-btn {
      width: 100%;
      padding: 18px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 18px;
      color: #FDFAF5;
      background: #C25B40;
      border: none;
      border-radius: 12px;
      cursor: pointer;
    }
    .end-call-btn:active { background: #A8432D; }

    .call-timer {
      font-weight: 300;
      font-size: 14px;
      color: #6B6459;
      margin-top: 12px;
    }

    .call-hint {
      font-weight: 300;
      font-size: 14px;
      color: #6B6459;
      text-align: center;
      margin-top: 16px;
      line-height: 1.5;
    }

    /* Online status */
    .status-dot {
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      margin-right: 6px;
      vertical-align: middle;
    }
    .status-dot.online { background: #C4A962; }
    .status-dot.offline { background: #6B6459; }
    .status-text {
      font-weight: 400;
      font-size: 13px;
      color: #6B6459;
      vertical-align: middle;
    }

    /* Outbound call notification */
    .call-notification {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(26, 23, 20, 0.7);
      z-index: 1000;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .call-notification.visible { display: flex; }

    .call-notif-card {
      background: #FDFAF5;
      border-radius: 20px;
      padding: 36px 28px;
      text-align: center;
      max-width: 380px;
      width: 100%;
      box-shadow: 0 8px 32px rgba(26, 23, 20, 0.3);
      animation: notifSlideIn 0.3s ease;
    }
    @keyframes notifSlideIn {
      from { transform: translateY(40px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .call-notif-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }

    .call-notif-title {
      font-family: 'Cormorant Garamond', serif;
      font-weight: 400;
      font-size: 26px;
      color: #1A1714;
      margin-bottom: 8px;
    }

    .call-notif-subtitle {
      font-weight: 400;
      font-size: 16px;
      color: #6B6459;
      margin-bottom: 24px;
      line-height: 1.4;
    }

    .call-notif-join {
      width: 100%;
      padding: 18px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 20px;
      color: #FDFAF5;
      background: #C4A962;
      border: none;
      border-radius: 14px;
      cursor: pointer;
      margin-bottom: 12px;
    }
    .call-notif-join:active { background: #D9C48A; }

    .call-notif-dismiss {
      width: 100%;
      padding: 14px;
      font-family: 'Jost', sans-serif;
      font-weight: 400;
      font-size: 16px;
      color: #6B6459;
      background: none;
      border: 2px solid rgba(196, 169, 98, 0.3);
      border-radius: 12px;
      cursor: pointer;
    }

    /* Voicemail recording UI */
    .voicemail-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: #FDFAF5;
      z-index: 1100;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 32px 24px;
    }
    .voicemail-overlay.visible { display: flex; }

    .vm-header {
      font-family: 'Cormorant Garamond', serif;
      font-weight: 400;
      font-size: 32px;
      color: #1A1714;
      margin-bottom: 32px;
      text-align: center;
    }

    .vm-countdown {
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 64px;
      color: #C4A962;
      margin-bottom: 24px;
      text-align: center;
    }

    .vm-countdown-label {
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 20px;
      color: #6B6459;
      margin-bottom: 16px;
    }

    .vm-options {
      width: 100%;
      max-width: 380px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .vm-btn-video {
      width: 100%;
      padding: 20px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 20px;
      color: #FDFAF5;
      background: #C4A962;
      border: none;
      border-radius: 14px;
      cursor: pointer;
    }
    .vm-btn-video:active { background: #D9C48A; }

    .vm-btn-audio {
      width: 100%;
      padding: 20px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 20px;
      color: #C4A962;
      background: none;
      border: 3px solid #C4A962;
      border-radius: 14px;
      cursor: pointer;
    }
    .vm-btn-audio:active { background: rgba(196,169,98,0.1); }

    .vm-btn-hangup {
      width: 100%;
      padding: 16px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 18px;
      color: #6B6459;
      background: #F5F0E8;
      border: none;
      border-radius: 14px;
      cursor: pointer;
    }
    .vm-btn-hangup:active { background: #E8E0D0; }

    .vm-preview {
      width: 100%;
      max-width: 380px;
      aspect-ratio: 4/3;
      background: #1A1714;
      border-radius: 14px;
      overflow: hidden;
      margin-bottom: 20px;
    }
    .vm-preview video {
      width: 100%;
      height: 100%;
      object-fit: cover;
      transform: scaleX(-1);
    }

    .vm-audio-viz {
      width: 100%;
      max-width: 380px;
      height: 180px;
      background: #F5F0E8;
      border-radius: 14px;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
    }

    .vm-audio-bar {
      width: 8px;
      background: #C4A962;
      border-radius: 4px;
      animation: vmPulse 1.2s ease-in-out infinite;
    }
    .vm-audio-bar:nth-child(1) { height: 30px; animation-delay: 0s; }
    .vm-audio-bar:nth-child(2) { height: 50px; animation-delay: 0.15s; }
    .vm-audio-bar:nth-child(3) { height: 70px; animation-delay: 0.3s; }
    .vm-audio-bar:nth-child(4) { height: 50px; animation-delay: 0.45s; }
    .vm-audio-bar:nth-child(5) { height: 30px; animation-delay: 0.6s; }
    .vm-audio-bar:nth-child(6) { height: 60px; animation-delay: 0.75s; }
    .vm-audio-bar:nth-child(7) { height: 40px; animation-delay: 0.9s; }

    @keyframes vmPulse {
      0%, 100% { transform: scaleY(0.4); }
      50% { transform: scaleY(1); }
    }

    .vm-stop-btn {
      width: 100%;
      max-width: 380px;
      padding: 20px;
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 20px;
      color: #FDFAF5;
      background: #C25B40;
      border: none;
      border-radius: 14px;
      cursor: pointer;
    }
    .vm-stop-btn:active { background: #A8432D; }

    .vm-recording-time {
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 18px;
      color: #C25B40;
      margin-bottom: 16px;
    }

    .vm-sent-msg {
      font-family: 'Jost', sans-serif;
      font-weight: 500;
      font-size: 24px;
      color: #C4A962;
      text-align: center;
    }
  </style>
</head>
<body>
  <!-- Outbound call notification overlay -->
  <div class="call-notification" id="callNotification">
    <div class="call-notif-card">
      <div class="call-notif-icon">\u{1F4DE}</div>
      <div class="call-notif-title" id="callNotifTitle">The Ken is calling</div>
      <div class="call-notif-subtitle" id="callNotifSubtitle">Tap below to join the video call</div>
      <button class="call-notif-join" onclick="joinOutboundCall()">Join Call</button>
      <button class="call-notif-dismiss" onclick="dismissCallNotif()">Not now</button>
    </div>
  </div>

  <!-- Voicemail recording overlay -->
  <div class="voicemail-overlay" id="voicemailOverlay">
    <div class="vm-header" id="vmHeader">Leave a message</div>
    <div id="vmCountdownArea" style="display:none;">
      <div class="vm-countdown-label">Recording in</div>
      <div class="vm-countdown" id="vmCountdown">3</div>
    </div>
    <div id="vmOptionsArea">
      <div class="vm-options">
        <button class="vm-btn-video" onclick="startVoicemail('video')">Video Voicemail</button>
        <button class="vm-btn-audio" onclick="startVoicemail('audio')">Voice Only</button>
        <button class="vm-btn-hangup" onclick="cancelVoicemail()">Hang Up</button>
      </div>
    </div>
    <div id="vmRecordingArea" style="display:none;">
      <div class="vm-preview" id="vmPreview" style="display:none;"><video id="vmPreviewVideo" autoplay playsinline muted></video></div>
      <div class="vm-audio-viz" id="vmAudioViz" style="display:none;">
        <div class="vm-audio-bar"></div><div class="vm-audio-bar"></div><div class="vm-audio-bar"></div>
        <div class="vm-audio-bar"></div><div class="vm-audio-bar"></div><div class="vm-audio-bar"></div>
        <div class="vm-audio-bar"></div>
      </div>
      <div class="vm-recording-time" id="vmRecordingTime">0:00</div>
      <button class="vm-stop-btn" onclick="stopVoicemail()">Stop &amp; Send</button>
    </div>
    <div id="vmSentArea" style="display:none;">
      <div class="vm-sent-msg">Voicemail sent</div>
    </div>
  </div>

  <div class="header">
    <h1>The Ken</h1>
    <div class="subtitle" id="headerSubtitle">Family Portal</div>
    <div style="margin-top:6px;">
      <span class="status-dot offline" id="statusDot"></span>
      <span class="status-text" id="statusText">Checking...</span>
    </div>
  </div>

  <div class="tab-bar">
    <button class="tab" onclick="showTab('call')">Call</button>
    <button class="tab active" onclick="showTab('message')">Message</button>
    <button class="tab" onclick="showTab('history')">History</button>
    <button class="tab" onclick="showTab('contacts')">Contacts</button>
    <button class="tab" onclick="showTab('settings')">Settings</button>
  </div>

  <!-- Name setup (shown once) -->
  <div class="name-setup" id="nameSetup" style="margin:24px;">
    <p>What is your name? This will appear on messages and calls.</p>
    <input type="text" id="senderNameInput" placeholder="e.g. Sarah" />
    <button onclick="saveSenderName()">Save</button>
  </div>

  <!-- Call Panel -->
  <div class="panel" id="callPanel">
    <div id="callIdle">
      <button class="call-btn" id="callBtn" onclick="startCall()">Call The Ken</button>
      <div class="call-hint">This will ring The Ken. When answered, a video call will begin.<br>Other family members can join too — just open this page and call.</div>
    </div>
    <div class="call-active-area" id="callActiveArea">
      <div class="call-status" id="callStatusText">Ringing The Ken...</div>
      <div class="call-video-container" id="callVideoContainer">
        <video id="remoteVideoEl" autoplay playsinline></video>
        <div class="call-local-pip" id="callLocalPip">
          <video id="localVideoEl" autoplay playsinline muted></video>
        </div>
      </div>
      <button class="end-call-btn" onclick="endFamilyCall()">End Call</button>
      <div class="call-timer" id="familyCallTimer"></div>
    </div>
  </div>

  <!-- Send Message Panel -->
  <div class="panel active" id="messagePanel">
    <div class="send-success" id="sendSuccess">Message sent — it will appear on The Ken shortly.</div>
    <div class="compose-area">
      <label class="compose-label">Your message</label>
      <textarea class="compose-input" id="messageText" placeholder="e.g. Hi Mum, just checking in! We'll call you at 3pm today."></textarea>
      <button class="send-btn" id="sendBtn" onclick="sendMessage()">Send Message</button>
    </div>

    <div class="bookmark-hint">
      <p><strong>Tip:</strong> Bookmark this page or add it to your home screen for quick access.</p>
      <button onclick="sharePortalLink()" style="margin-top:12px;font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#C4A962;background:none;border:2px solid rgba(196,169,98,0.3);border-radius:8px;padding:8px 20px;cursor:pointer;">Share this link with family</button>
    </div>
  </div>

  <!-- History Panel -->
  <div class="panel" id="historyPanel">
    <div class="message-list" id="messageList">
      <div class="empty-state">No messages sent yet.</div>
    </div>
  </div>

  <!-- Contacts Panel -->
  <div class="panel" id="contactsPanel">
    <div id="contactsList" class="message-list">
      <div class="empty-state">Loading contacts...</div>
    </div>
    <div style="padding:16px 0;">
      <button class="send-btn" onclick="window.location.href='/add/${deviceId}'">Add Yourself as a Contact</button>
    </div>
  </div>

  <!-- Settings Panel -->
  <div class="panel" id="settingsPanel">
    <!-- Call History -->
    <div style="margin-bottom:24px;">
      <div style="font-weight:500;font-size:16px;color:#C4A962;margin-bottom:12px;">Call History</div>
      <div id="callHistoryList" class="message-list">
        <div class="empty-state">Loading...</div>
      </div>
    </div>

    <!-- Do Not Disturb -->
    <div style="margin-bottom:24px;background:rgba(196,169,98,0.08);border-radius:12px;padding:16px;">
      <div style="font-weight:500;font-size:16px;color:#C4A962;margin-bottom:12px;">Do Not Disturb</div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <span style="font-size:15px;color:#1A1714;">Enabled</span>
        <button id="dndToggle" onclick="toggleDND()" style="font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#FDFAF5;background:#C4A962;border:none;border-radius:8px;padding:8px 16px;cursor:pointer;">Off</button>
      </div>
      <div style="display:flex;gap:12px;align-items:center;">
        <span style="font-size:14px;color:#6B6459;">Quiet hours:</span>
        <input type="time" id="dndStart" value="22:00" style="font-family:'Jost',sans-serif;font-size:14px;padding:6px;border:1px solid rgba(196,169,98,0.3);border-radius:6px;" />
        <span style="font-size:14px;color:#6B6459;">to</span>
        <input type="time" id="dndEnd" value="08:00" style="font-family:'Jost',sans-serif;font-size:14px;padding:6px;border:1px solid rgba(196,169,98,0.3);border-radius:6px;" />
      </div>
      <button onclick="saveDNDSettings()" style="margin-top:12px;width:100%;font-family:'Jost',sans-serif;font-weight:500;font-size:15px;color:#FDFAF5;background:#C4A962;border:none;border-radius:10px;padding:12px;cursor:pointer;">Save</button>
    </div>

    <!-- Nightlight -->
    <div style="margin-bottom:24px;background:rgba(196,169,98,0.08);border-radius:12px;padding:16px;">
      <div style="font-weight:500;font-size:16px;color:#C4A962;margin-bottom:12px;">Nightlight Mode</div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <span style="font-size:15px;color:#1A1714;">Auto-dim at night</span>
        <button id="nightlightToggle" onclick="toggleNightlight()" style="font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#FDFAF5;background:#C4A962;border:none;border-radius:8px;padding:8px 16px;cursor:pointer;">On</button>
      </div>
      <div style="font-size:13px;color:#6B6459;">Dims screen between 9pm and 7am</div>
    </div>

    <!-- Offline Alerts -->
    <div style="margin-bottom:24px;background:rgba(196,169,98,0.08);border-radius:12px;padding:16px;">
      <div style="font-weight:500;font-size:16px;color:#C4A962;margin-bottom:12px;">Offline Alerts</div>
      <div style="font-size:13px;color:#6B6459;margin-bottom:12px;">Get notified when The Ken goes offline for too long.</div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <span style="font-size:15px;color:#1A1714;font-weight:500;">Enable alerts</span>
        <button id="offlineAlertToggle" onclick="toggleOfflineAlerts()" style="font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#FDFAF5;background:#C4A962;border:none;border-radius:8px;padding:8px 16px;cursor:pointer;">Off</button>
      </div>
      <div style="margin-bottom:12px;">
        <div style="font-size:14px;color:#6B6459;margin-bottom:8px;font-weight:500;">Alert after offline for:</div>
        <div id="offlineDelayBtns" style="display:flex;gap:8px;flex-wrap:wrap;">
          <button onclick="setOfflineDelay(10)" class="delay-btn" data-delay="10" style="flex:1;min-width:60px;font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#1A1714;background:#F5F0E8;border:2px solid rgba(196,169,98,0.3);border-radius:8px;padding:10px 8px;cursor:pointer;">10 min</button>
          <button onclick="setOfflineDelay(15)" class="delay-btn" data-delay="15" style="flex:1;min-width:60px;font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#1A1714;background:#F5F0E8;border:2px solid rgba(196,169,98,0.3);border-radius:8px;padding:10px 8px;cursor:pointer;">15 min</button>
          <button onclick="setOfflineDelay(30)" class="delay-btn" data-delay="30" style="flex:1;min-width:60px;font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#1A1714;background:#F5F0E8;border:2px solid rgba(196,169,98,0.3);border-radius:8px;padding:10px 8px;cursor:pointer;">30 min</button>
          <button onclick="setOfflineDelay(60)" class="delay-btn" data-delay="60" style="flex:1;min-width:60px;font-family:'Jost',sans-serif;font-weight:500;font-size:14px;color:#1A1714;background:#F5F0E8;border:2px solid rgba(196,169,98,0.3);border-radius:8px;padding:10px 8px;cursor:pointer;">60 min</button>
        </div>
      </div>
      <div style="margin-bottom:12px;">
        <div style="font-size:14px;color:#6B6459;margin-bottom:8px;font-weight:500;">Notify these contacts:</div>
        <div id="offlineAlertContacts" style="display:flex;flex-direction:column;gap:6px;">
          <span style="font-size:13px;color:#6B6459;">Loading contacts...</span>
        </div>
      </div>
      <button onclick="saveOfflineAlerts()" style="width:100%;font-family:'Jost',sans-serif;font-weight:500;font-size:15px;color:#FDFAF5;background:#C4A962;border:none;border-radius:10px;padding:12px;cursor:pointer;">Save Offline Alert Settings</button>
    </div>

    <!-- Reminders -->
    <div style="margin-bottom:24px;">
      <div style="font-weight:500;font-size:16px;color:#C4A962;margin-bottom:12px;">Reminders</div>
      <div id="remindersList" class="message-list" style="margin-bottom:12px;">
        <div class="empty-state">No reminders set.</div>
      </div>
      <div style="background:rgba(196,169,98,0.08);border-radius:12px;padding:16px;">
        <input type="time" id="reminderTime" style="width:100%;font-family:'Jost',sans-serif;font-size:16px;padding:10px;border:2px solid rgba(196,169,98,0.3);border-radius:8px;margin-bottom:8px;" />
        <input type="text" id="reminderText" placeholder="e.g. Take your medication" style="width:100%;font-family:'Jost',sans-serif;font-size:16px;padding:10px;border:2px solid rgba(196,169,98,0.3);border-radius:8px;margin-bottom:8px;color:#1A1714;" />
        <button onclick="addReminder()" style="width:100%;font-family:'Jost',sans-serif;font-weight:500;font-size:15px;color:#FDFAF5;background:#C4A962;border:none;border-radius:10px;padding:12px;cursor:pointer;">Add Reminder</button>
      </div>
    </div>

  </div>

  <script>
    const DEVICE_ID = '${deviceId}';
    let senderName = localStorage.getItem('ken-sender-name') || '';
    let familyCallObject = null;
    let familyCallTimerInterval = null;
    let familyCallStart = null;

    function init() {
      if (senderName) {
        document.getElementById('nameSetup').style.display = 'none';
        document.getElementById('headerSubtitle').textContent = 'Signed in as ' + senderName;
        showTab('message');
      } else {
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      }
    }

    function saveSenderName() {
      const name = document.getElementById('senderNameInput').value.trim();
      if (!name) return;
      senderName = name;
      localStorage.setItem('ken-sender-name', name);
      document.getElementById('nameSetup').style.display = 'none';
      document.getElementById('headerSubtitle').textContent = 'Signed in as ' + name;
      showTab('message');
    }

    function showTab(tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => {
        p.classList.remove('active');
        p.style.display = '';
      });
      const tabs = document.querySelectorAll('.tab');
      if (tab === 'call') {
        tabs[0].classList.add('active');
        document.getElementById('callPanel').classList.add('active');
      } else if (tab === 'message') {
        tabs[1].classList.add('active');
        document.getElementById('messagePanel').classList.add('active');
      } else if (tab === 'history') {
        tabs[2].classList.add('active');
        document.getElementById('historyPanel').classList.add('active');
        loadHistory();
      } else if (tab === 'contacts') {
        tabs[3].classList.add('active');
        document.getElementById('contactsPanel').classList.add('active');
        loadContacts();
      } else if (tab === 'settings') {
        tabs[4].classList.add('active');
        document.getElementById('settingsPanel').classList.add('active');
        loadCallHistory();
        loadDeviceSettings();
        loadOfflineAlerts();
        loadReminders();
      }
    }

    // ===== CALLING =====
    async function startCall() {
      if (!senderName) { alert('Please set your name first.'); return; }
      const btn = document.getElementById('callBtn');
      btn.disabled = true; btn.textContent = 'Connecting...';

      try {
        // Get the device room URL
        const roomResp = await fetch('/api/calls/' + DEVICE_ID + '/room');
        const roomData = await roomResp.json();
        if (!roomData.roomUrl) {
          alert('The Ken is not online yet. Please try again later.');
          btn.disabled = false; btn.textContent = 'Call The Ken';
          return;
        }

        // Signal the Ken that we're calling
        await fetch('/api/calls/' + DEVICE_ID, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
          body: JSON.stringify({ from: senderName })
        });

        // Join the Daily room
        document.getElementById('callIdle').style.display = 'none';
        document.getElementById('callActiveArea').classList.add('visible');
        document.getElementById('callStatusText').textContent = 'Ringing The Ken...';

        familyCallObject = window.DailyIframe.createCallObject({
          audioSource: true,
          videoSource: true
        });

        familyCallObject.on('joined-meeting', () => {
          document.getElementById('callStatusText').textContent = 'Waiting for The Ken to answer...';
          // Attach local video
          const localTrack = familyCallObject.participants().local?.tracks?.video?.track;
          if (localTrack) {
            document.getElementById('localVideoEl').srcObject = new MediaStream([localTrack]);
          }
          familyCallStart = Date.now();
          familyCallTimerInterval = setInterval(updateFamilyCallTimer, 1000);
          // Start polling for voicemail signal
          startVoicemailPolling();
        });

        familyCallObject.on('participant-joined', (e) => {
          if (!e.participant.local) {
            document.getElementById('callStatusText').textContent = 'Connected';
            attachFamilyRemoteVideo(e.participant);
          }
        });

        familyCallObject.on('participant-updated', (e) => {
          if (e.participant.local) {
            const localTrack = e.participant.tracks?.video?.track;
            if (localTrack) {
              document.getElementById('localVideoEl').srcObject = new MediaStream([localTrack]);
            }
          } else {
            attachFamilyRemoteVideo(e.participant);
          }
        });

        familyCallObject.on('participant-left', (e) => {
          if (!e.participant.local) {
            const participants = familyCallObject.participants();
            const remoteCount = Object.keys(participants).filter(k => k !== 'local').length;
            if (remoteCount === 0) {
              document.getElementById('callStatusText').textContent = 'Everyone has left';
              setTimeout(() => endFamilyCall(), 3000);
            } else {
              document.getElementById('callStatusText').textContent = remoteCount + ' in call';
            }
          }
        });

        familyCallObject.on('error', () => { endFamilyCall(); });
        familyCallObject.on('left-meeting', () => { resetCallUI(); });

        await familyCallObject.join({ url: roomData.roomUrl });
      } catch (err) {
        alert('Could not start the call. Please try again.');
        resetCallUI();
      }
    }

    function attachFamilyRemoteVideo(participant) {
      const vt = participant.tracks?.video?.track;
      const at = participant.tracks?.audio?.track;
      const el = document.getElementById('remoteVideoEl');
      const streams = [];
      if (vt) streams.push(vt);
      if (at) streams.push(at);
      if (streams.length > 0) {
        el.srcObject = new MediaStream(streams);
      }
    }

    function updateFamilyCallTimer() {
      if (!familyCallStart) return;
      const s = Math.floor((Date.now() - familyCallStart) / 1000);
      document.getElementById('familyCallTimer').textContent =
        Math.floor(s/60) + ':' + String(s%60).padStart(2,'0');
    }

    function endFamilyCall() {
      // Signal end (clears both inbound and outbound signals)
      fetch('/api/calls/' + DEVICE_ID + '/end', { method: 'POST', headers: { 'X-Ken-CSRF': '1' } }).catch(() => {});
      if (familyCallObject) {
        familyCallObject.leave().catch(() => {});
        familyCallObject.destroy().catch(() => {});
        familyCallObject = null;
      }
      stopTitleFlash();
      stopVoicemailPolling();
      resetCallUI();
    }

    function resetCallUI() {
      if (familyCallTimerInterval) { clearInterval(familyCallTimerInterval); familyCallTimerInterval = null; }
      familyCallStart = null;
      familyCallObject = null;
      document.getElementById('callIdle').style.display = 'block';
      document.getElementById('callActiveArea').classList.remove('visible');
      const btn = document.getElementById('callBtn');
      btn.disabled = false; btn.textContent = 'Call The Ken';
      document.getElementById('remoteVideoEl').srcObject = null;
      document.getElementById('localVideoEl').srcObject = null;
      document.getElementById('familyCallTimer').textContent = '';
    }

    // ===== VOICEMAIL =====
    let vmPollInterval = null;
    let vmMediaRecorder = null;
    let vmStream = null;
    let vmChunks = [];
    let vmType = 'video';
    let vmRecordingTimer = null;
    let vmRecordStart = null;
    let vmCallerName = '';

    function startVoicemailPolling() {
      if (vmPollInterval) return;
      vmPollInterval = setInterval(async () => {
        if (!familyCallObject) { stopVoicemailPolling(); return; }
        try {
          const resp = await fetch('/api/calls/' + DEVICE_ID + '/voicemail');
          const data = await resp.json();
          if (data.voicemailRequested) {
            // Leave the Daily room
            if (familyCallObject) {
              familyCallObject.leave().catch(() => {});
              familyCallObject.destroy().catch(() => {});
              familyCallObject = null;
            }
            stopVoicemailPolling();
            stopTitleFlash();
            resetCallUI();
            vmCallerName = senderName || 'Family';
            showVoicemailUI();
          }
        } catch {}
      }, 3000);
    }

    function stopVoicemailPolling() {
      if (vmPollInterval) { clearInterval(vmPollInterval); vmPollInterval = null; }
    }

    function showVoicemailUI() {
      document.getElementById('vmHeader').textContent = 'Leave a message';
      document.getElementById('vmOptionsArea').style.display = 'block';
      document.getElementById('vmCountdownArea').style.display = 'none';
      document.getElementById('vmRecordingArea').style.display = 'none';
      document.getElementById('vmSentArea').style.display = 'none';
      document.getElementById('voicemailOverlay').classList.add('visible');
    }

    async function startVoicemail(type) {
      vmType = type;
      document.getElementById('vmOptionsArea').style.display = 'none';

      // 3-second countdown
      document.getElementById('vmCountdownArea').style.display = 'block';
      let count = 3;
      document.getElementById('vmCountdown').textContent = count;
      await new Promise(resolve => {
        const ci = setInterval(() => {
          count--;
          if (count <= 0) {
            clearInterval(ci);
            document.getElementById('vmCountdownArea').style.display = 'none';
            resolve();
          } else {
            document.getElementById('vmCountdown').textContent = count;
          }
        }, 1000);
      });

      // Get media stream
      try {
        const constraints = type === 'video'
          ? { video: true, audio: true }
          : { audio: true };
        vmStream = await navigator.mediaDevices.getUserMedia(constraints);

        if (type === 'video') {
          document.getElementById('vmPreview').style.display = 'block';
          document.getElementById('vmAudioViz').style.display = 'none';
          document.getElementById('vmPreviewVideo').srcObject = vmStream;
        } else {
          document.getElementById('vmPreview').style.display = 'none';
          document.getElementById('vmAudioViz').style.display = 'flex';
        }

        document.getElementById('vmRecordingArea').style.display = 'block';

        // Start recording
        vmChunks = [];
        vmMediaRecorder = new MediaRecorder(vmStream, { mimeType: type === 'video' ? 'video/webm' : 'audio/webm' });
        vmMediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) vmChunks.push(e.data); };
        vmMediaRecorder.start();

        vmRecordStart = Date.now();
        document.getElementById('vmRecordingTime').textContent = '0:00';
        vmRecordingTimer = setInterval(() => {
          const s = Math.floor((Date.now() - vmRecordStart) / 1000);
          document.getElementById('vmRecordingTime').textContent =
            Math.floor(s/60) + ':' + String(s%60).padStart(2, '0');
        }, 1000);
      } catch (err) {
        alert('Could not access camera/microphone.');
        cancelVoicemail();
      }
    }

    async function stopVoicemail() {
      if (!vmMediaRecorder || vmMediaRecorder.state === 'inactive') return;

      const duration = vmRecordStart ? Math.floor((Date.now() - vmRecordStart) / 1000) : 0;
      if (vmRecordingTimer) { clearInterval(vmRecordingTimer); vmRecordingTimer = null; }

      vmMediaRecorder.stop();
      await new Promise(resolve => { vmMediaRecorder.onstop = resolve; });

      // Convert to base64
      const blob = new Blob(vmChunks, { type: vmType === 'video' ? 'video/webm' : 'audio/webm' });
      const reader = new FileReader();
      reader.onloadend = async () => {
        const base64 = reader.result;
        // Upload
        document.getElementById('vmRecordingArea').style.display = 'none';
        document.getElementById('vmSentArea').style.display = 'block';
        document.getElementById('vmHeader').textContent = '';

        try {
          await fetch('/api/voicemail/' + DEVICE_ID, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
            body: JSON.stringify({
              from: vmCallerName,
              type: vmType,
              media: base64,
              duration,
              timestamp: new Date().toISOString()
            })
          });
        } catch {}

        // Cleanup stream
        if (vmStream) { vmStream.getTracks().forEach(t => t.stop()); vmStream = null; }

        // Auto-close after 2 seconds
        setTimeout(() => {
          document.getElementById('voicemailOverlay').classList.remove('visible');
        }, 2000);
      };
      reader.readAsDataURL(blob);
    }

    function cancelVoicemail() {
      if (vmRecordingTimer) { clearInterval(vmRecordingTimer); vmRecordingTimer = null; }
      if (vmMediaRecorder && vmMediaRecorder.state !== 'inactive') {
        vmMediaRecorder.stop();
      }
      if (vmStream) { vmStream.getTracks().forEach(t => t.stop()); vmStream = null; }
      vmChunks = [];
      document.getElementById('voicemailOverlay').classList.remove('visible');
    }

    // ===== MESSAGING =====
    async function sendMessage() {
      const text = document.getElementById('messageText').value.trim();
      if (!text) return;
      if (!senderName) { alert('Please set your name first.'); return; }

      const btn = document.getElementById('sendBtn');
      btn.disabled = true; btn.textContent = 'Sending...';

      try {
        const resp = await fetch('/api/messages/' + DEVICE_ID, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
          body: JSON.stringify({ from: senderName, text })
        });
        const data = await resp.json();
        if (data.success) {
          document.getElementById('messageText').value = '';
          const s = document.getElementById('sendSuccess');
          s.style.display = 'block';
          setTimeout(() => { s.style.display = 'none'; }, 4000);
        } else {
          alert('Error: ' + (data.error || 'Unknown error'));
        }
      } catch {
        alert('Something went wrong. Please try again.');
      }
      btn.disabled = false; btn.textContent = 'Send Message';
    }

    async function loadHistory() {
      try {
        const resp = await fetch('/api/messages/' + DEVICE_ID + '/history');
        const data = await resp.json();
        const list = document.getElementById('messageList');
        if (!data.messages || data.messages.length === 0) {
          list.innerHTML = '<div class="empty-state">No messages sent yet.</div>';
          return;
        }
        list.innerHTML = data.messages.slice().reverse().map(m => {
          const date = new Date(m.sentAt);
          const timeStr = date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) + ' at ' +
            date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
          const replyStyle = m.isReply ? 'border-left:4px solid #C4A962;' : '';
          const fromLabel = m.isReply ? escHtml(m.from) + ' (reply)' : escHtml(m.from);
          return '<div class="message-item" style="' + replyStyle + '">' +
            '<div class="message-from">' + fromLabel + '</div>' +
            '<div class="message-text">' + escHtml(m.text) + '</div>' +
            '<div class="message-time">' + timeStr + '</div>' +
            '</div>';
        }).join('');
      } catch {
        document.getElementById('messageList').innerHTML = '<div class="empty-state">Could not load messages.</div>';
      }
    }

    function escHtml(str) {
      return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    // ===== SHARE =====
    // ===== CALL HISTORY =====
    async function loadCallHistory() {
      try {
        const resp = await fetch('/api/history/' + DEVICE_ID + '/calls');
        const data = await resp.json();
        const list = document.getElementById('callHistoryList');
        if (!data.calls || data.calls.length === 0) {
          list.innerHTML = '<div class="empty-state">No calls yet.</div>';
          return;
        }
        list.innerHTML = data.calls.slice().reverse().slice(0, 20).map(c => {
          const date = new Date(c.timestamp);
          const timeStr = date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) + ' ' +
            date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
          const icon = c.type === 'inbound' ? '\\u{1F4F2}' : '\\u{1F4DE}';
          const statusColor = c.status === 'missed' ? '#C25B40' : (c.status === 'rejected' ? '#6B6459' : '#C4A962');
          return '<div class="message-item" style="padding:10px 14px;">' +
            '<div style="display:flex;justify-content:space-between;align-items:center;">' +
            '<div><span style="font-size:16px;">' + icon + '</span> <span style="font-weight:500;font-size:15px;">' + escHtml(c.contactName) + '</span></div>' +
            '<span style="font-size:12px;font-weight:500;color:' + statusColor + ';text-transform:capitalize;">' + escHtml(c.status) + '</span>' +
            '</div>' +
            '<div style="font-size:13px;color:#6B6459;margin-top:4px;">' + c.type + ' — ' + timeStr + '</div>' +
            '</div>';
        }).join('');
      } catch {
        document.getElementById('callHistoryList').innerHTML = '<div class="empty-state">Could not load history.</div>';
      }
    }

    // ===== DEVICE SETTINGS (DND, Nightlight) =====
    let deviceSettings = {};
    async function loadDeviceSettings() {
      try {
        const resp = await fetch('/api/settings/' + DEVICE_ID);
        deviceSettings = await resp.json();
        document.getElementById('dndToggle').textContent = deviceSettings.dndEnabled ? 'On' : 'Off';
        document.getElementById('dndStart').value = deviceSettings.dndStart || '22:00';
        document.getElementById('dndEnd').value = deviceSettings.dndEnd || '08:00';
        document.getElementById('nightlightToggle').textContent = deviceSettings.nightlightEnabled !== false ? 'On' : 'Off';
      } catch {}
    }

    function toggleDND() {
      deviceSettings.dndEnabled = !deviceSettings.dndEnabled;
      document.getElementById('dndToggle').textContent = deviceSettings.dndEnabled ? 'On' : 'Off';
    }

    function toggleNightlight() {
      deviceSettings.nightlightEnabled = !(deviceSettings.nightlightEnabled !== false);
      document.getElementById('nightlightToggle').textContent = deviceSettings.nightlightEnabled ? 'On' : 'Off';
      saveDNDSettings();
    }

    async function saveDNDSettings() {
      deviceSettings.dndStart = document.getElementById('dndStart').value;
      deviceSettings.dndEnd = document.getElementById('dndEnd').value;
      try {
        await fetch('/api/settings/' + DEVICE_ID, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
          body: JSON.stringify(deviceSettings)
        });
      } catch {}
    }

    // ===== OFFLINE ALERTS =====
    let offlineAlertSettings = { enabled: false, delayMinutes: 10, contactNames: [], lastAlertSent: null };
    let offlineAlertContactList = [];

    async function loadOfflineAlerts() {
      try {
        const [alertResp, contactResp] = await Promise.all([
          fetch('/api/settings/' + DEVICE_ID + '/offline-alerts'),
          fetch('/api/contacts/' + DEVICE_ID + '/list')
        ]);
        offlineAlertSettings = await alertResp.json();
        const contactData = await contactResp.json();
        offlineAlertContactList = contactData.contacts || [];

        // Update toggle
        document.getElementById('offlineAlertToggle').textContent = offlineAlertSettings.enabled ? 'On' : 'Off';

        // Highlight selected delay
        updateDelayButtons();

        // Render contact checkboxes
        renderOfflineAlertContacts();
      } catch {}
    }

    function updateDelayButtons() {
      document.querySelectorAll('.delay-btn').forEach(btn => {
        const d = parseInt(btn.getAttribute('data-delay'));
        if (d === offlineAlertSettings.delayMinutes) {
          btn.style.background = '#C4A962';
          btn.style.color = '#FDFAF5';
          btn.style.borderColor = '#C4A962';
        } else {
          btn.style.background = '#F5F0E8';
          btn.style.color = '#1A1714';
          btn.style.borderColor = 'rgba(196,169,98,0.3)';
        }
      });
    }

    function setOfflineDelay(minutes) {
      offlineAlertSettings.delayMinutes = minutes;
      updateDelayButtons();
    }

    function toggleOfflineAlerts() {
      offlineAlertSettings.enabled = !offlineAlertSettings.enabled;
      document.getElementById('offlineAlertToggle').textContent = offlineAlertSettings.enabled ? 'On' : 'Off';
    }

    function toggleOfflineContact(name) {
      const idx = offlineAlertSettings.contactNames.indexOf(name);
      if (idx >= 0) {
        offlineAlertSettings.contactNames.splice(idx, 1);
      } else {
        offlineAlertSettings.contactNames.push(name);
      }
      renderOfflineAlertContacts();
    }

    function renderOfflineAlertContacts() {
      const container = document.getElementById('offlineAlertContacts');
      if (!offlineAlertContactList.length) {
        container.innerHTML = '<span style="font-size:13px;color:#6B6459;">No contacts added yet.</span>';
        return;
      }
      container.innerHTML = offlineAlertContactList.map(c => {
        const selected = offlineAlertSettings.contactNames.includes(c.name);
        return '<button onclick="toggleOfflineContact(\\'' + escHtml(c.name).replace(/'/g, "\\\\'") + '\\')" style="' +
          'display:flex;align-items:center;gap:12px;width:100%;min-height:48px;padding:10px 14px;' +
          'font-family:\\'Jost\\',sans-serif;font-weight:500;font-size:15px;' +
          'background:' + (selected ? 'rgba(196,169,98,0.15)' : '#F5F0E8') + ';' +
          'color:' + (selected ? '#C4A962' : '#1A1714') + ';' +
          'border:2px solid ' + (selected ? '#C4A962' : 'rgba(196,169,98,0.2)') + ';' +
          'border-radius:10px;cursor:pointer;text-align:left;">' +
          '<span style="width:24px;height:24px;border-radius:6px;border:2px solid ' +
          (selected ? '#C4A962' : 'rgba(196,169,98,0.3)') + ';background:' +
          (selected ? '#C4A962' : 'transparent') + ';display:flex;align-items:center;justify-content:center;flex-shrink:0;">' +
          (selected ? '<span style="color:#FDFAF5;font-size:14px;">&#10003;</span>' : '') +
          '</span>' +
          escHtml(c.name) +
          '</button>';
      }).join('');
    }

    async function saveOfflineAlerts() {
      try {
        await fetch('/api/settings/' + DEVICE_ID + '/offline-alerts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
          body: JSON.stringify(offlineAlertSettings)
        });
        // Brief visual feedback
        const btn = event.target;
        btn.textContent = 'Saved!';
        setTimeout(() => { btn.textContent = 'Save Offline Alert Settings'; }, 1500);
      } catch {
        alert('Could not save offline alert settings.');
      }
    }

    // ===== REMINDERS =====
    async function loadReminders() {
      try {
        const resp = await fetch('/api/reminders/' + DEVICE_ID);
        const data = await resp.json();
        const list = document.getElementById('remindersList');
        if (!data.reminders || data.reminders.length === 0) {
          list.innerHTML = '<div class="empty-state">No reminders set.</div>';
          return;
        }
        list.innerHTML = data.reminders.map(r =>
          '<div class="message-item" style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;">' +
          '<div><span style="font-weight:500;color:#C4A962;">' + escHtml(r.time) + '</span> — ' + escHtml(r.text) +
          '<div style="font-size:12px;color:#6B6459;">' + escHtml(r.repeat) + '</div></div>' +
          '<button onclick="deleteReminder(\\'' + r.id + '\\')" style="font-family:\\'Jost\\',sans-serif;font-size:13px;color:#C25B40;background:none;border:1px solid rgba(194,91,64,0.3);border-radius:6px;padding:4px 10px;cursor:pointer;">Delete</button>' +
          '</div>'
        ).join('');
      } catch {
        document.getElementById('remindersList').innerHTML = '<div class="empty-state">Could not load reminders.</div>';
      }
    }

    async function addReminder() {
      const time = document.getElementById('reminderTime').value;
      const text = document.getElementById('reminderText').value.trim();
      if (!time || !text) { alert('Please enter a time and message.'); return; }
      try {
        await fetch('/api/reminders/' + DEVICE_ID, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
          body: JSON.stringify({ time, text, repeat: 'daily' })
        });
        document.getElementById('reminderText').value = '';
        loadReminders();
      } catch { alert('Could not add reminder.'); }
    }

    async function deleteReminder(id) {
      try {
        await fetch('/api/reminders/' + DEVICE_ID + '/' + id, { method: 'DELETE', headers: { 'X-Ken-CSRF': '1' } });
        loadReminders();
      } catch {}
    }

    function sharePortalLink() {
      const url = window.location.href;
      const text = (deviceName || 'The Ken') + ' — Family Portal';
      if (navigator.share) {
        navigator.share({ title: text, url: url }).catch(() => {});
      } else {
        navigator.clipboard.writeText(url).then(() => {
          alert('Link copied to clipboard!');
        }).catch(() => {
          prompt('Copy this link:', url);
        });
      }
    }

    // ===== CONTACTS VIEW =====
    async function loadContacts() {
      try {
        const resp = await fetch('/api/contacts/' + DEVICE_ID + '/list');
        const data = await resp.json();
        const list = document.getElementById('contactsList');
        if (!data.contacts || data.contacts.length === 0) {
          list.innerHTML = '<div class="empty-state">No contacts on The Ken yet.</div>';
          return;
        }
        list.innerHTML = data.contacts.sort((a,b) => a.position - b.position).map(c => {
          const initials = c.name.charAt(0).toUpperCase();
          const homeLabel = c.position <= 4 ? '<span style="color:#C4A962;font-weight:500;font-size:13px;">On home screen</span>' : '';
          return '<div class="message-item" style="display:flex;align-items:center;gap:16px;">' +
            '<div style="width:48px;height:48px;border-radius:10px;background:linear-gradient(135deg,#F5F0E8,#D9C48A);display:flex;align-items:center;justify-content:center;font-size:22px;color:#6B6459;flex-shrink:0;">' + initials + '</div>' +
            '<div style="flex:1;">' +
            '<div style="font-weight:500;font-size:16px;color:#1A1714;">' + escHtml(c.name) + '</div>' +
            (c.relationship ? '<div style="font-weight:400;font-size:14px;color:#6B6459;">' + escHtml(c.relationship) + '</div>' : '') +
            homeLabel +
            '</div></div>';
        }).join('');
      } catch {
        document.getElementById('contactsList').innerHTML = '<div class="empty-state">Could not load contacts.</div>';
      }
    }

    // ===== POLL FOR REPLIES =====
    let lastHistoryCount = 0;
    async function pollForReplies() {
      try {
        const resp = await fetch('/api/messages/' + DEVICE_ID + '/history');
        const data = await resp.json();
        const msgs = data.messages || [];
        if (msgs.length > lastHistoryCount && lastHistoryCount > 0) {
          const newMsgs = msgs.slice(lastHistoryCount);
          for (const m of newMsgs) {
            if (m.isReply) {
              showBrowserNotification('Reply from ' + m.from, m.text);
            }
          }
          // Auto-refresh history if that tab is active
          if (document.getElementById('historyPanel').classList.contains('active')) {
            loadHistory();
          }
        }
        lastHistoryCount = msgs.length;
      } catch {}
    }
    // Check every 10 seconds
    setInterval(pollForReplies, 10000);
    // Initial load to set baseline
    pollForReplies();

    // ===== BROWSER NOTIFICATIONS =====
    let notifPermission = Notification.permission || 'default';
    async function requestNotifPermission() {
      if ('Notification' in window && notifPermission === 'default') {
        notifPermission = await Notification.requestPermission();
      }
    }
    // Request on first user interaction
    document.addEventListener('click', () => { requestNotifPermission(); }, { once: true });

    function showBrowserNotification(title, body) {
      if (notifPermission === 'granted') {
        try { new Notification(title, { body, icon: 'data:image/svg+xml,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><rect width="48" height="48" rx="10" fill="%23C4A962"/><text x="24" y="32" text-anchor="middle" fill="%23FDFAF5" font-size="24" font-family="serif">K</text></svg>') }); } catch {}
      }
    }

    // Flash tab title when there's an incoming call notification
    let titleFlashInterval = null;
    function startTitleFlash(msg) {
      stopTitleFlash();
      const original = document.title;
      let toggle = false;
      titleFlashInterval = setInterval(() => {
        document.title = toggle ? original : msg;
        toggle = !toggle;
      }, 1000);
    }
    function stopTitleFlash() {
      if (titleFlashInterval) { clearInterval(titleFlashInterval); titleFlashInterval = null; }
      document.title = 'The Ken \\u2014 Family';
    }

    // ===== DEVICE INFO =====
    let deviceName = 'The Ken';
    async function loadDeviceInfo() {
      try {
        const resp = await fetch('/api/device/' + DEVICE_ID);
        const data = await resp.json();
        if (data.userName) {
          deviceName = data.userName;
          document.querySelector('.header h1').textContent = deviceName;
          document.getElementById('callBtn').textContent = 'Call ' + deviceName;
        }
      } catch {}
    }
    loadDeviceInfo();

    // ===== ONLINE STATUS =====
    async function checkOnlineStatus() {
      try {
        const resp = await fetch('/api/heartbeat/' + DEVICE_ID);
        const data = await resp.json();
        const dot = document.getElementById('statusDot');
        const text = document.getElementById('statusText');
        const callBtn = document.getElementById('callBtn');
        if (data.online) {
          dot.className = 'status-dot online';
          text.textContent = 'Online';
          callBtn.disabled = false;
        } else {
          dot.className = 'status-dot offline';
          callBtn.disabled = true;
          if (data.lastSeen) {
            const ago = Math.floor((Date.now() - new Date(data.lastSeen).getTime()) / 60000);
            text.textContent = ago < 60 ? 'Last seen ' + ago + 'm ago' : 'Offline';
          } else {
            text.textContent = 'Offline';
          }
        }
      } catch {
        document.getElementById('statusDot').className = 'status-dot offline';
        document.getElementById('statusText').textContent = 'Unknown';
      }
    }
    checkOnlineStatus();
    setInterval(checkOnlineStatus, 30000);

    // ===== OUTBOUND CALL NOTIFICATIONS =====
    let lastOutboundId = null;
    let outboundCallRoomUrl = null;
    let outboundCallDismissed = false;

    async function pollOutboundCall() {
      // Don't poll if already in a call
      if (familyCallObject) return;
      try {
        const resp = await fetch('/api/calls/' + DEVICE_ID + '/outbound');
        const data = await resp.json();
        if (data.outbound && data.outbound.id !== lastOutboundId) {
          lastOutboundId = data.outbound.id;
          outboundCallRoomUrl = data.outbound.roomUrl;
          outboundCallDismissed = false;
          // Show notification
          document.getElementById('callNotifTitle').textContent =
            'The Ken is calling ' + escHtml(data.outbound.contactName);
          document.getElementById('callNotifSubtitle').textContent =
            'Tap below to join the video call';
          document.getElementById('callNotification').classList.add('visible');
          // Browser notification + title flash
          showBrowserNotification('The Ken is calling', data.outbound.contactName + ' is being called');
          startTitleFlash('\\u{1F4DE} Incoming call!');
          // Play a notification sound
          try {
            const actx = new (window.AudioContext || window.webkitAudioContext)();
            const g = actx.createGain();
            g.connect(actx.destination);
            g.gain.setValueAtTime(0.2, actx.currentTime);
            g.gain.exponentialRampToValueAtTime(0.001, actx.currentTime + 1.0);
            const o = actx.createOscillator();
            o.type = 'sine'; o.frequency.setValueAtTime(698.46, actx.currentTime);
            o.connect(g); o.start(); o.stop(actx.currentTime + 0.4);
            const o2 = actx.createOscillator();
            const g2 = actx.createGain();
            g2.connect(actx.destination);
            g2.gain.setValueAtTime(0.2, actx.currentTime + 0.45);
            g2.gain.exponentialRampToValueAtTime(0.001, actx.currentTime + 1.4);
            o2.type = 'sine'; o2.frequency.setValueAtTime(880, actx.currentTime + 0.45);
            o2.connect(g2); o2.start(actx.currentTime + 0.45); o2.stop(actx.currentTime + 0.9);
          } catch {}
        } else if (!data.outbound && lastOutboundId) {
          // Call ended
          lastOutboundId = null;
          outboundCallRoomUrl = null;
          document.getElementById('callNotification').classList.remove('visible');
          stopTitleFlash();
        }
      } catch {}
    }
    setInterval(pollOutboundCall, 3000);

    function joinOutboundCall() {
      document.getElementById('callNotification').classList.remove('visible');
      stopTitleFlash();
      if (outboundCallRoomUrl) {
        // Switch to call tab and start the call with this room URL
        showTab('call');
        joinRoomDirectly(outboundCallRoomUrl);
      }
    }

    function dismissCallNotif() {
      outboundCallDismissed = true;
      document.getElementById('callNotification').classList.remove('visible');
      stopTitleFlash();
    }

    // Join a specific room URL directly (for outbound call join)
    async function joinRoomDirectly(roomUrl) {
      if (!senderName) {
        // Prompt for name inline
        const name = prompt('Enter your name to join the call:');
        if (!name || !name.trim()) return;
        senderName = name.trim();
        localStorage.setItem('ken-sender-name', senderName);
        document.getElementById('nameSetup').style.display = 'none';
        document.getElementById('headerSubtitle').textContent = 'Signed in as ' + senderName;
      }
      document.getElementById('callIdle').style.display = 'none';
      document.getElementById('callActiveArea').classList.add('visible');
      document.getElementById('callStatusText').textContent = 'Joining call...';

      familyCallObject = window.DailyIframe.createCallObject({
        audioSource: true, videoSource: true
      });

      familyCallObject.on('joined-meeting', () => {
        document.getElementById('callStatusText').textContent = 'Connected';
        const localTrack = familyCallObject.participants().local?.tracks?.video?.track;
        if (localTrack) {
          document.getElementById('localVideoEl').srcObject = new MediaStream([localTrack]);
        }
        familyCallStart = Date.now();
        familyCallTimerInterval = setInterval(updateFamilyCallTimer, 1000);
      });

      familyCallObject.on('participant-joined', (e) => {
        if (!e.participant.local) attachFamilyRemoteVideo(e.participant);
      });

      familyCallObject.on('participant-updated', (e) => {
        if (e.participant.local) {
          const localTrack = e.participant.tracks?.video?.track;
          if (localTrack) {
            document.getElementById('localVideoEl').srcObject = new MediaStream([localTrack]);
          }
        } else {
          attachFamilyRemoteVideo(e.participant);
        }
      });

      familyCallObject.on('participant-left', (e) => {
        if (!e.participant.local) {
          const participants = familyCallObject.participants();
          const remoteCount = Object.keys(participants).filter(k => k !== 'local').length;
          if (remoteCount === 0) {
            document.getElementById('callStatusText').textContent = 'Everyone has left';
            setTimeout(() => endFamilyCall(), 3000);
          } else {
            document.getElementById('callStatusText').textContent = remoteCount + ' in call';
          }
        }
      });

      familyCallObject.on('error', () => { endFamilyCall(); });
      familyCallObject.on('left-meeting', () => { resetCallUI(); });

      try {
        await familyCallObject.join({ url: roomUrl });
      } catch {
        alert('Could not join the call.');
        resetCallUI();
      }
    }

    init();
  </script>
</body>
</html>`;
}

// ===== AUTH & PERMISSION HELPERS =====

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  const encoder = new TextEncoder();
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

async function hashPassword(password, salt) {
  if (!salt) salt = crypto.randomUUID();
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return { hash, salt };
}

async function hashPasswordLegacy(password, salt) {
  if (!salt) salt = crypto.randomUUID();
  const encoder = new TextEncoder();
  const data = encoder.encode(password + salt);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const hashHex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  return { hash: hashHex, salt };
}

async function verifyPassword(password, storedHash, salt) {
  // Try PBKDF2 first
  const { hash: pbkdf2Hash } = await hashPassword(password, salt);
  if (timingSafeEqual(pbkdf2Hash, storedHash)) return { valid: true, needsRehash: false };
  // Fall back to legacy SHA-256
  const { hash: legacyHash } = await hashPasswordLegacy(password, salt);
  if (timingSafeEqual(legacyHash, storedHash)) return { valid: true, needsRehash: true };
  return { valid: false, needsRehash: false };
}

async function getSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/ken_session=([^;]+)/);
  if (!match) return null;
  const session = await env.KEN_KV.get(`session:${match[1]}`, 'json');
  return session;
}

async function requireAuth(request, env) {
  const session = await getSession(request, env);
  if (!session) return { error: true, response: json({ error: 'Not authenticated' }, 401) };
  // Try D1 first, fall back to KV
  let user = await d1GetUser(env, session.email);
  if (!user) user = await env.KEN_KV.get(`user:${session.email}`, 'json');
  if (!user) return { error: true, response: json({ error: 'User not found' }, 401) };
  return { error: false, user, session };
}

async function requireAdmin(request, env, deviceId) {
  const auth = await requireAuth(request, env);
  if (auth.error) return auth;
  const role = getUserRole(auth.user, deviceId);
  if (role !== 'admin' && role !== 'carer' && role !== 'hq') return { error: true, response: json({ error: 'Admin access required' }, 403) };
  auth.role = role;
  return auth;
}

function getUserRole(user, deviceId) {
  if (!user.devices) return null;
  // HQ users have a global role
  if (user.globalRole === 'hq') return 'hq';
  // Carers can have multiple devices
  if (user.globalRole === 'carer') {
    // Check if they have access to this specific device
    if (user.devices[deviceId]) return 'carer';
    if (user.carerDevices && user.carerDevices.includes(deviceId)) return 'carer';
    return null;
  }
  // Normal per-device role
  return user.devices[deviceId] ? user.devices[deviceId].role : null;
}

function requirePermission(user, deviceId, action) {
  const role = getUserRole(user, deviceId);
  if (!role) return { allowed: false, role: null };
  return { allowed: hasPermission(role, action), role };
}

// ===== TOTP (RFC 6238) =====

function generateTOTPSecret() {
  // Generate 20 random bytes and properly base32-encode them
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let secret = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    secret += chars[parseInt(bits.slice(i, i + 5), 2)];
  }
  return secret;
}

function base32Decode(str) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of str.toUpperCase()) {
    const val = chars.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

async function generateTOTPCode(secret, timeStep) {
  const key = base32Decode(secret);
  const time = Math.floor((timeStep || Date.now() / 1000) / 30);
  const timeBytes = new Uint8Array(8);
  let t = time;
  for (let i = 7; i >= 0; i--) {
    timeBytes[i] = t & 0xff;
    t = Math.floor(t / 256);
  }
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, timeBytes);
  const hmac = new Uint8Array(sig);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 | hmac[offset + 1] << 16 | hmac[offset + 2] << 8 | hmac[offset + 3]) % 1000000;
  return code.toString().padStart(6, '0');
}

async function verifyTOTP(secret, code) {
  // Check current window and ±2 windows (150 second tolerance for clock drift)
  const now = Date.now() / 1000;
  for (const offset of [-30, 0, 30]) {
    const expected = await generateTOTPCode(secret, now + offset);
    if (expected === code) return true;
  }
  return false;
}

function calculateNextDue(frequency, preferredTime) {
  const now = new Date();
  const [hours, minutes] = (preferredTime || '09:00').split(':').map(Number);
  const next = new Date(now);
  next.setHours(hours, minutes, 0, 0);
  // If the time today has passed, start from tomorrow
  if (next <= now) next.setDate(next.getDate() + 1);
  switch (frequency) {
    case 'daily': break; // already set to tomorrow or today
    case 'weekly': while (next <= now) next.setDate(next.getDate() + 7); break;
    case 'biweekly': while (next <= now) next.setDate(next.getDate() + 14); break;
    case 'monthly': while (next <= now) next.setMonth(next.getMonth() + 1); break;
  }
  return next.toISOString();
}

async function logAudit(env, deviceId, email, action, details) {
  try {
    const audit = await env.KEN_KV.get(`audit:${deviceId}`, 'json') || [];
    audit.push({
      id: crypto.randomUUID(),
      userId: email,
      action,
      timestamp: new Date().toISOString(),
      details: details || {}
    });
    // Archive when hitting 500: move oldest 250 to archive chunk, keep up to 5 archives
    if (audit.length > 500) {
      const toArchive = audit.splice(0, 250);
      const archiveKey = `audit-archive:${deviceId}:${new Date().toISOString()}`;
      await env.KEN_KV.put(archiveKey, JSON.stringify(toArchive));
      // List and prune old archives (keep max 5)
      const archiveList = await env.KEN_KV.list({ prefix: `audit-archive:${deviceId}:` });
      if (archiveList.keys.length > 5) {
        const toDelete = archiveList.keys.sort((a, b) => a.name.localeCompare(b.name)).slice(0, archiveList.keys.length - 5);
        for (const k of toDelete) await env.KEN_KV.delete(k.name);
      }
    }
    await env.KEN_KV.put(`audit:${deviceId}`, JSON.stringify(audit));
  } catch {
    // Audit logging should never break the main flow
  }
}
