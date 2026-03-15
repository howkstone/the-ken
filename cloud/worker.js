// The Ken — Cloudflare Worker API
// Handles contacts, messaging, family interface, auth, permissions & audit

const ALLOWED_ORIGINS = ['https://theken.uk', 'https://www.theken.uk', 'https://ken-api.the-ken.workers.dev'];

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const CORS_HEADERS = getCorsHeaders(request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // ===== AUTH ENDPOINTS =====
    if (request.method === 'POST' && path === '/api/auth/register') {
      try {
        const body = await request.json();
        const { email, password, name, phone, deviceId } = body;
        if (!email || !password || !name) return json({ error: 'Email, password and name are required' }, 400);
        const existing = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (existing) return json({ error: 'An account with this email already exists' }, 400);
        const passwordHash = await hashPassword(password);
        const devices = {};
        if (deviceId) {
          // Check for invite
          const invite = await env.KEN_KV.get(`invite:${deviceId}:${email.toLowerCase()}`, 'json');
          devices[deviceId] = { role: invite ? invite.role : 'standard' };
          if (invite) await env.KEN_KV.delete(`invite:${deviceId}:${email.toLowerCase()}`);
        }
        const user = {
          email: email.toLowerCase(),
          name: name.trim(),
          phone: (phone || '').trim(),
          passwordHash,
          photo: '',
          devices,
          createdAt: new Date().toISOString(),
        };
        await env.KEN_KV.put(`user:${email.toLowerCase()}`, JSON.stringify(user));
        // Create session
        const token = crypto.randomUUID();
        await env.KEN_KV.put(`session:${token}`, JSON.stringify({ email: user.email, token, createdAt: new Date().toISOString() }), { expirationTtl: 2592000 });
        if (deviceId) await logAudit(env, deviceId, user.email, 'Account created', { role: devices[deviceId]?.role || 'standard' });
        const headers = { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Set-Cookie': `ken_session=${token}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=2592000` };
        return new Response(JSON.stringify({ success: true }), { headers });
      } catch { return json({ error: 'Invalid request' }, 400); }
    }

    if (request.method === 'POST' && path === '/api/auth/login') {
      try {
        const body = await request.json();
        const { email, password, totpCode } = body;
        if (!email || !password) return json({ error: 'Email and password are required' }, 400);
        const user = await env.KEN_KV.get(`user:${email.toLowerCase()}`, 'json');
        if (!user) return json({ error: 'Invalid email or password' }, 401);
        const hash = await hashPassword(password);
        if (hash !== user.passwordHash) return json({ error: 'Invalid email or password' }, 401);
        // Check MFA
        if (user.mfaEnabled && user.mfaSecret) {
          if (!totpCode) {
            return json({ mfaRequired: true, error: 'MFA code required' }, 403);
          }
          // Try TOTP first, then backup codes
          const validTotp = await verifyTOTP(user.mfaSecret, totpCode);
          if (!validTotp) {
            // Check backup codes
            const backupIdx = (user.mfaBackupCodes || []).indexOf(totpCode);
            if (backupIdx === -1) return json({ error: 'Invalid MFA code' }, 401);
            // Consume the backup code
            user.mfaBackupCodes.splice(backupIdx, 1);
            await env.KEN_KV.put(`user:${email.toLowerCase()}`, JSON.stringify(user));
          }
        }
        const token = crypto.randomUUID();
        await env.KEN_KV.put(`session:${token}`, JSON.stringify({ email: user.email, token, createdAt: new Date().toISOString() }), { expirationTtl: 2592000 });
        const headers = { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Set-Cookie': `ken_session=${token}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=2592000` };
        return new Response(JSON.stringify({ success: true }), { headers });
      } catch { return json({ error: 'Invalid request' }, 400); }
    }

    // ===== MFA SETUP =====
    if (request.method === 'POST' && path === '/api/auth/mfa/setup') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const secret = generateTOTPSecret();
      // Store pending secret (not yet confirmed)
      auth.user.mfaPendingSecret = secret;
      await env.KEN_KV.put(`user:${auth.user.email}`, JSON.stringify(auth.user));
      const otpauth = `otpauth://totp/TheKen:${encodeURIComponent(auth.user.email)}?secret=${secret}&issuer=TheKen&digits=6&period=30`;
      return json({ secret, otpauth });
    }

    if (request.method === 'POST' && path === '/api/auth/mfa/confirm') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const { code } = body;
        if (!code || !auth.user.mfaPendingSecret) return json({ error: 'No pending MFA setup or missing code' }, 400);
        const valid = await verifyTOTP(auth.user.mfaPendingSecret, code);
        if (!valid) return json({ error: 'Invalid code. Please try again.' }, 400);
        // Activate MFA
        auth.user.mfaEnabled = true;
        auth.user.mfaSecret = auth.user.mfaPendingSecret;
        delete auth.user.mfaPendingSecret;
        // Generate backup codes
        const backupCodes = Array.from({ length: 8 }, () => crypto.randomUUID().slice(0, 8));
        auth.user.mfaBackupCodes = backupCodes;
        await env.KEN_KV.put(`user:${auth.user.email}`, JSON.stringify(auth.user));
        const deviceIds = Object.keys(auth.user.devices || {});
        if (deviceIds[0]) await logAudit(env, deviceIds[0], auth.user.email, 'Enabled MFA', {});
        return json({ success: true, backupCodes });
      } catch { return json({ error: 'Invalid request' }, 400); }
    }

    if (request.method === 'POST' && path === '/api/auth/mfa/disable') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      try {
        const body = await request.json();
        const { password } = body;
        if (!password) return json({ error: 'Password required to disable MFA' }, 400);
        const hash = await hashPassword(password);
        if (hash !== auth.user.passwordHash) return json({ error: 'Invalid password' }, 401);
        auth.user.mfaEnabled = false;
        delete auth.user.mfaSecret;
        delete auth.user.mfaPendingSecret;
        delete auth.user.mfaBackupCodes;
        await env.KEN_KV.put(`user:${auth.user.email}`, JSON.stringify(auth.user));
        const deviceIds = Object.keys(auth.user.devices || {});
        if (deviceIds[0]) await logAudit(env, deviceIds[0], auth.user.email, 'Disabled MFA', {});
        return json({ success: true });
      } catch { return json({ error: 'Invalid request' }, 400); }
    }

    if (request.method === 'GET' && path === '/api/auth/mfa/status') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      return json({ mfaEnabled: !!auth.user.mfaEnabled });
    }

    if (request.method === 'POST' && path === '/api/auth/logout') {
      const cookie = request.headers.get('Cookie') || '';
      const match = cookie.match(/ken_session=([^;]+)/);
      if (match) await env.KEN_KV.delete(`session:${match[1]}`);
      const headers = { ...CORS_HEADERS, 'Content-Type': 'application/json', 'Set-Cookie': 'ken_session=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0' };
      return new Response(JSON.stringify({ success: true }), { headers });
    }

    if (request.method === 'GET' && path === '/api/auth/me') {
      const auth = await requireAuth(request, env);
      if (auth.error) return auth.response;
      const user = auth.user;
      // Determine role from first device (or default)
      const deviceIds = Object.keys(user.devices || {});
      const firstDevice = deviceIds[0] || null;
      const role = firstDevice && user.devices[firstDevice] ? user.devices[firstDevice].role : 'standard';
      return json({ user: { email: user.email, name: user.name, phone: user.phone, photo: user.photo, role, devices: user.devices, deviceId: firstDevice, mfaEnabled: !!user.mfaEnabled } });
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
        if (role !== 'admin' && role !== 'standard') return json({ error: 'role must be admin or standard' }, 400);
        const auth = await requireAdmin(request, env, deviceId);
        if (auth.error) return auth.response;
        await env.KEN_KV.put(`invite:${deviceId}:${email.toLowerCase()}`, JSON.stringify({ role, invitedBy: auth.user.email, createdAt: new Date().toISOString() }));
        await logAudit(env, deviceId, auth.user.email, 'Invited user', { email: email.toLowerCase(), role });
        return json({ success: true });
      } catch { return json({ error: 'Invalid request' }, 400); }
    }

    // ===== AUDIT LOG ENDPOINT =====
    if (request.method === 'GET' && path.match(/^\/api\/audit\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const auth = await requireAdmin(request, env, deviceId);
      if (auth.error) return auth.response;
      const audit = await env.KEN_KV.get(`audit:${deviceId}`, 'json') || [];
      return json({ audit });
    }

    // ===== SETTINGS QUEUE (offline changes) =====
    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/queue$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const queue = await env.KEN_KV.get(`queue:${deviceId}`, 'json') || [];
        queue.push({ id: crypto.randomUUID(), ...body, queuedAt: new Date().toISOString() });
        await env.KEN_KV.put(`queue:${deviceId}`, JSON.stringify(queue));
        return json({ success: true });
      } catch { return json({ error: 'Invalid request' }, 400); }
    }

    if (request.method === 'GET' && path.match(/^\/api\/settings\/[\w-]+\/queue$/)) {
      const deviceId = path.split('/')[3];
      const queue = await env.KEN_KV.get(`queue:${deviceId}`, 'json') || [];
      return json({ queue });
    }

    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/queue\/ack$/)) {
      const deviceId = path.split('/')[3];
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
      await env.KEN_KV.delete(`messages:${deviceId}`);
      return json({ success: true });
    }

    // ===== REPLY (from device — goes to history only, not pending) =====
    if (request.method === 'POST' && path.match(/^\/api\/messages\/[\w-]+\/reply$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { from, text } = body;
        if (!from || !text || !text.trim()) {
          return json({ error: 'From and text are required' }, 400);
        }
        const message = {
          id: crypto.randomUUID(),
          from: from.trim(),
          text: text.trim(),
          sentAt: new Date().toISOString(),
          isReply: true,
        };
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        history.push(message);
        if (history.length > 100) history.splice(0, history.length - 100);
        await env.KEN_KV.put(`history:${deviceId}`, JSON.stringify(history));
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
      }
    }

    // ===== MESSAGE HISTORY (for family interface) =====
    if (request.method === 'GET' && path.match(/^\/api\/messages\/[\w-]+\/history$/)) {
      const deviceId = path.split('/')[3];
      const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
      return json({ messages: history });
    }

    // ===== CALL ENDPOINTS =====
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
        return json({ error: 'Invalid request' }, 400);
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
        return json({ error: 'Invalid request' }, 400);
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
        return json({ error: 'Invalid request' }, 400);
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
        return json({ error: 'Invalid request' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/contacts\/[\w-]+\/list$/)) {
      const deviceId = path.split('/')[3];
      const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
      return json({ contacts });
    }

    // ===== DEVICE INFO =====
    if (request.method === 'POST' && path.match(/^\/api\/device\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        await env.KEN_KV.put(`device:${deviceId}`, JSON.stringify(body));
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/device\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const info = await env.KEN_KV.get(`device:${deviceId}`, 'json');
      return json(info || { userName: 'The Ken' });
    }

    // ===== HEARTBEAT =====
    if (request.method === 'POST' && path.match(/^\/api\/heartbeat\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const now = new Date().toISOString();
      const hb = { online: true, lastSeen: now };
      await env.KEN_KV.put(`heartbeat:${deviceId}`, JSON.stringify(hb), { expirationTtl: 90 });
      // Store non-expiring timestamp for offline duration calculation
      await env.KEN_KV.put(`heartbeat-time:${deviceId}`, now);
      // Register device in the device list
      const devices = await env.KEN_KV.get('devices:all', 'json') || [];
      if (!devices.includes(deviceId)) {
        devices.push(deviceId);
        await env.KEN_KV.put('devices:all', JSON.stringify(devices));
      }
      // Clear lastAlertSent when device comes back online
      const alertSettings = await env.KEN_KV.get(`offline-alerts:${deviceId}`, 'json');
      if (alertSettings && alertSettings.lastAlertSent) {
        alertSettings.lastAlertSent = null;
        await env.KEN_KV.put(`offline-alerts:${deviceId}`, JSON.stringify(alertSettings));
      }
      // Process offline settings queue — apply any changes queued while device was offline
      const queue = await env.KEN_KV.get(`queue:${deviceId}`, 'json') || [];
      let hasQueue = false;
      if (queue.length > 0) {
        hasQueue = true;
        for (const item of queue) {
          if (item.setting && item.value !== undefined) {
            const settings = await env.KEN_KV.get(`settings:${deviceId}`, 'json') || {};
            settings[item.setting] = item.value;
            await env.KEN_KV.put(`settings:${deviceId}`, JSON.stringify(settings));
            await logAudit(env, deviceId, item.changedBy || 'system', 'Applied queued setting', { setting: item.setting, value: item.value });
          }
        }
        await env.KEN_KV.delete(`queue:${deviceId}`);
      }
      return json({ success: true, queueApplied: hasQueue, queueCount: queue.length });
    }

    if (request.method === 'GET' && path.match(/^\/api\/heartbeat\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const hb = await env.KEN_KV.get(`heartbeat:${deviceId}`, 'json');
      return json({ online: !!hb, lastSeen: hb ? hb.lastSeen : null });
    }

    // ===== OFFLINE ALERT SETTINGS =====
    if (request.method === 'POST' && path.match(/^\/api\/settings\/[\w-]+\/offline-alerts$/)) {
      const deviceId = path.split('/')[3];
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
        return json({ error: 'Invalid request' }, 400);
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
        return json({ error: 'Invalid request' }, 400);
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
        return json({ error: 'Invalid request' }, 400);
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
      try {
        const body = await request.json();
        await env.KEN_KV.put(`settings:${deviceId}`, JSON.stringify(body));
        const session = await getSession(request, env);
        await logAudit(env, deviceId, session ? session.email : 'device', 'Updated device settings', body);
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
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

    // ===== REMINDERS =====
    if (request.method === 'POST' && path.match(/^\/api\/reminders\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { text, time, repeat } = body;
        if (!text || !time) return json({ error: 'text and time required' }, 400);
        const reminders = await env.KEN_KV.get(`reminders:${deviceId}`, 'json') || [];
        reminders.push({
          id: crypto.randomUUID(),
          text: text.trim(),
          time, // HH:MM format
          repeat: repeat || 'daily', // 'daily' or 'once'
          createdAt: new Date().toISOString(),
          active: true
        });
        await env.KEN_KV.put(`reminders:${deviceId}`, JSON.stringify(reminders));
        const session = await getSession(request, env);
        await logAudit(env, deviceId, session ? session.email : 'device', 'Added reminder', { text: text.trim(), time });
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
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
      const reminders = await env.KEN_KV.get(`reminders:${deviceId}`, 'json') || [];
      const deleted = reminders.find(r => r.id === reminderId);
      const filtered = reminders.filter(r => r.id !== reminderId);
      await env.KEN_KV.put(`reminders:${deviceId}`, JSON.stringify(filtered));
      const session = await getSession(request, env);
      await logAudit(env, deviceId, session ? session.email : 'device', 'Deleted reminder', { reminderId, text: deleted ? deleted.text : 'unknown' });
      return json({ success: true });
    }

    // ===== PHOTOS =====
    if (request.method === 'POST' && path.match(/^\/api\/photos\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { photo, caption } = body;
        if (!photo) return json({ error: 'photo required' }, 400);
        const photos = await env.KEN_KV.get(`photos:${deviceId}`, 'json') || [];
        if (photos.length >= 20) return json({ error: 'Maximum 20 photos' }, 400);
        photos.push({
          id: crypto.randomUUID(),
          photo, // base64 data URL
          caption: (caption || '').trim(),
          uploadedAt: new Date().toISOString()
        });
        await env.KEN_KV.put(`photos:${deviceId}`, JSON.stringify(photos));
        const session = await getSession(request, env);
        await logAudit(env, deviceId, session ? session.email : 'device', 'Uploaded photo', { caption: (caption || '').trim() });
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/photos\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const photos = await env.KEN_KV.get(`photos:${deviceId}`, 'json') || [];
      return json({ photos });
    }

    if (request.method === 'DELETE' && path.match(/^\/api\/photos\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const photoId = parts[4];
      const photos = await env.KEN_KV.get(`photos:${deviceId}`, 'json') || [];
      const filtered = photos.filter(p => p.id !== photoId);
      await env.KEN_KV.put(`photos:${deviceId}`, JSON.stringify(filtered));
      const session = await getSession(request, env);
      await logAudit(env, deviceId, session ? session.email : 'device', 'Deleted photo', { photoId });
      return json({ success: true });
    }

    // ===== FEEDBACK =====
    if (request.method === 'POST' && path.match(/^\/api\/feedback\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
        feedback.push(body);
        if (feedback.length > 100) feedback.splice(0, feedback.length - 100);
        await env.KEN_KV.put(`feedback:${deviceId}`, JSON.stringify(feedback));
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
      }
    }

    if (request.method === 'GET' && path.match(/^\/api\/feedback\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
      return json({ feedback });
    }

    // ===== VOICEMAIL ENDPOINTS =====
    // Ken signals "send to voicemail"
    if (request.method === 'POST' && path.match(/^\/api\/calls\/[\w-]+\/voicemail$/)) {
      const deviceId = path.split('/')[3];
      try {
        const body = await request.json();
        const { from } = body;
        await env.KEN_KV.put(`voicemail-req:${deviceId}`, JSON.stringify({ voicemailRequested: true, from: from || '' }), { expirationTtl: 120 });
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
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
      try {
        const body = await request.json();
        const { from, type, media, duration, timestamp } = body;
        if (!from || !media) return json({ error: 'from and media required' }, 400);
        const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
        voicemails.push({
          id: crypto.randomUUID(),
          from: from.trim(),
          type: type || 'video',
          media,
          duration: duration || 0,
          timestamp: timestamp || new Date().toISOString(),
          played: false
        });
        // Keep max 20 voicemails (remove oldest)
        while (voicemails.length > 20) voicemails.shift();
        await env.KEN_KV.put(`voicemails:${deviceId}`, JSON.stringify(voicemails));
        // Clear the voicemail request signal
        await env.KEN_KV.delete(`voicemail-req:${deviceId}`);
        return json({ success: true });
      } catch {
        return json({ error: 'Invalid request' }, 400);
      }
    }

    // Get all voicemails for a device
    if (request.method === 'GET' && path.match(/^\/api\/voicemail\/[\w-]+$/)) {
      const deviceId = path.split('/')[3];
      const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
      return json({ voicemails });
    }

    // Delete a voicemail
    if (request.method === 'DELETE' && path.match(/^\/api\/voicemail\/[\w-]+\/[\w-]+$/)) {
      const parts = path.split('/');
      const deviceId = parts[3];
      const vmId = parts[4];
      const voicemails = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
      const filtered = voicemails.filter(v => v.id !== vmId);
      await env.KEN_KV.put(`voicemails:${deviceId}`, JSON.stringify(filtered));
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
      } catch { return json({ error: 'Invalid request' }, 400); }
    }

    if (request.method === 'GET' && path.match(/^\/api\/voicemail\/[\w-]+\/read-receipts$/)) {
      const deviceId = path.split('/')[3];
      const pref = await env.KEN_KV.get(`vm-read-receipts:${deviceId}`, 'json');
      return json(pref || { enabled: false });
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

        // Mark alert as sent
        alertSettings.lastAlertSent = new Date().toISOString();
        await env.KEN_KV.put(`offline-alerts:${deviceId}`, JSON.stringify(alertSettings));
      } catch {
        // Continue to next device on error
      }
    }
  },
};

async function handleAddContact(request, env, deviceId) {
  try {
    const body = await request.json();
    const { name, relationship, phoneNumber, photo } = body;
    if (!name || !name.trim()) {
      return json({ error: 'Name is required' }, 400);
    }
    const existing = await env.KEN_KV.get(`pending:${deviceId}`, 'json') || [];
    const contact = {
      id: crypto.randomUUID(),
      name: name.trim(),
      relationship: (relationship || '').trim(),
      phoneNumber: (phoneNumber || '').trim(),
      photo: photo || '',
      submittedAt: new Date().toISOString(),
    };
    existing.push(contact);
    await env.KEN_KV.put(`pending:${deviceId}`, JSON.stringify(existing));
    return json({ success: true, contact: { name: contact.name, id: contact.id } });
  } catch {
    return json({ error: 'Invalid request' }, 400);
  }
}

async function handleSendMessage(request, env, deviceId) {
  try {
    const body = await request.json();
    const { from, text } = body;
    if (!from || !text || !text.trim()) {
      return json({ error: 'From and text are required' }, 400);
    }
    const message = {
      id: crypto.randomUUID(),
      from: from.trim(),
      text: text.trim(),
      sentAt: new Date().toISOString(),
      read: false,
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
    return json({ error: 'Invalid request' }, 400);
  }
}

function json(data, status = 200) {
  // Default CORS headers for helper functions called outside of fetch context
  const defaultCors = {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
  };
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...defaultCors },
  });
}

function html(body) {
  return new Response(body, {
    headers: { 'Content-Type': 'text/html' },
  });
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
  </style>
</head>
<body>
  <h1>Feedback</h1>
  <div class="subtitle">Device: ${deviceId}</div>
  <div id="feedbackList"><div class="empty">Loading...</div></div>
  <script>
    async function load() {
      try {
        const resp = await fetch('/api/feedback/${deviceId}');
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
              '<div class="item-audio"><audio controls src="' + f.audio + '"></audio></div>';
          } else if (f.text) {
            content = '<div class="item-text">' + f.text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
          } else if (f.rating) {
            content = '<div class="item-text">Rating: ' + f.rating + '</div>';
          }
          return '<div class="item">' +
            '<div class="item-from">' + (f.from || 'Unknown') + '</div>' +
            content +
            '<div class="item-time">' + timeStr + '</div>' +
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

    <!-- Photos -->
    <div style="margin-bottom:24px;">
      <div style="font-weight:500;font-size:16px;color:#C4A962;margin-bottom:12px;">Photo Carousel</div>
      <div style="font-size:13px;color:#6B6459;margin-bottom:12px;">Upload photos for The Ken to display as a slideshow when idle.</div>
      <div id="photosList" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;"></div>
      <input type="file" id="photoUpload" accept="image/*" onchange="uploadPhoto(event)" style="display:none;" />
      <button onclick="document.getElementById('photoUpload').click()" style="width:100%;font-family:'Jost',sans-serif;font-weight:500;font-size:15px;color:#FDFAF5;background:#C4A962;border:none;border-radius:10px;padding:12px;cursor:pointer;">Upload Photo</button>
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
        loadPhotos();
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
          headers: { 'Content-Type': 'application/json' },
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
      fetch('/api/calls/' + DEVICE_ID + '/end', { method: 'POST' }).catch(() => {});
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
            headers: { 'Content-Type': 'application/json' },
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
          headers: { 'Content-Type': 'application/json' },
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
          headers: { 'Content-Type': 'application/json' },
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
          headers: { 'Content-Type': 'application/json' },
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
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ time, text, repeat: 'daily' })
        });
        document.getElementById('reminderText').value = '';
        loadReminders();
      } catch { alert('Could not add reminder.'); }
    }

    async function deleteReminder(id) {
      try {
        await fetch('/api/reminders/' + DEVICE_ID + '/' + id, { method: 'DELETE' });
        loadReminders();
      } catch {}
    }

    // ===== PHOTOS =====
    async function loadPhotos() {
      try {
        const resp = await fetch('/api/photos/' + DEVICE_ID);
        const data = await resp.json();
        const list = document.getElementById('photosList');
        if (!data.photos || data.photos.length === 0) {
          list.innerHTML = '<span style="font-size:14px;color:#6B6459;">No photos uploaded yet.</span>';
          return;
        }
        list.innerHTML = data.photos.map(p =>
          '<div style="position:relative;width:72px;height:72px;border-radius:8px;overflow:hidden;border:2px solid rgba(196,169,98,0.3);">' +
          '<img src="' + p.photo + '" style="width:100%;height:100%;object-fit:cover;" />' +
          '<button onclick="deletePhoto(\\'' + p.id + '\\')" style="position:absolute;top:2px;right:2px;width:20px;height:20px;background:rgba(0,0,0,0.5);color:#fff;border:none;border-radius:50%;font-size:12px;cursor:pointer;line-height:1;">x</button>' +
          '</div>'
        ).join('');
      } catch {}
    }

    function uploadPhoto(event) {
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async (ev) => {
        // Resize to max 800px
        const img = new Image();
        img.onload = async () => {
          const canvas = document.createElement('canvas');
          const maxDim = 800;
          let w = img.width, h = img.height;
          if (w > maxDim || h > maxDim) {
            if (w > h) { h = Math.round(h * maxDim / w); w = maxDim; }
            else { w = Math.round(w * maxDim / h); h = maxDim; }
          }
          canvas.width = w; canvas.height = h;
          canvas.getContext('2d').drawImage(img, 0, 0, w, h);
          const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
          try {
            await fetch('/api/photos/' + DEVICE_ID, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ photo: dataUrl })
            });
            loadPhotos();
          } catch { alert('Could not upload photo.'); }
        };
        img.src = ev.target.result;
      };
      reader.readAsDataURL(file);
    }

    async function deletePhoto(id) {
      try {
        await fetch('/api/photos/' + DEVICE_ID + '/' + id, { method: 'DELETE' });
        loadPhotos();
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

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'ken-salt-2026');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
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
  const user = await env.KEN_KV.get(`user:${session.email}`, 'json');
  if (!user) return { error: true, response: json({ error: 'User not found' }, 401) };
  return { error: false, user, session };
}

async function requireAdmin(request, env, deviceId) {
  const auth = await requireAuth(request, env);
  if (auth.error) return auth;
  const role = auth.user.devices && auth.user.devices[deviceId] && auth.user.devices[deviceId].role;
  if (role !== 'admin') return { error: true, response: json({ error: 'Admin access required' }, 403) };
  return auth;
}

// ===== TOTP (RFC 6238) =====

function generateTOTPSecret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  let secret = '';
  for (let i = 0; i < 32; i++) {
    secret += chars[bytes[i % 20] % 32];
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
  // Check current window and ±1 window (90 second tolerance)
  const now = Date.now() / 1000;
  for (const offset of [-30, 0, 30]) {
    const expected = await generateTOTPCode(secret, now + offset);
    if (expected === code) return true;
  }
  return false;
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
    // Keep max 500 entries
    while (audit.length > 500) audit.shift();
    await env.KEN_KV.put(`audit:${deviceId}`, JSON.stringify(audit));
  } catch {
    // Audit logging should never break the main flow
  }
}
