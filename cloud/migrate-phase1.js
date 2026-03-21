// The Ken — KV → D1 Migration Script (Phase 1: Users, Devices, Device Keys, Invites)
// Run via: wrangler d1 execute ken-db --remote --command="SELECT count(*) FROM users"
// Then: node migrate-phase1.js (or run as a one-off Worker endpoint)
//
// This script is designed to be run as a temporary Worker endpoint.
// Add it to worker.js fetch handler temporarily:
//   if (path === '/api/admin/migrate-phase1') { return await migratePhase1(env); }

async function migratePhase1(env) {
  const results = { users: 0, devices: 0, userDevices: 0, deviceKeys: 0, invites: 0, errors: [] };

  try {
    // ===== MIGRATE DEVICES =====
    const devicesAll = await env.KEN_KV.get('devices:all', 'json') || [];
    for (const deviceId of devicesAll) {
      try {
        const deviceInfo = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
        await env.KEN_DB.prepare(
          'INSERT OR IGNORE INTO devices (device_id, user_name, created_at, extra) VALUES (?, ?, ?, ?)'
        ).bind(
          deviceId,
          deviceInfo.userName || 'The Ken',
          deviceInfo.createdAt || new Date().toISOString(),
          JSON.stringify(deviceInfo)
        ).run();
        results.devices++;
      } catch (e) { results.errors.push(`device:${deviceId}: ${e.message}`); }
    }

    // ===== MIGRATE DEVICE KEYS =====
    for (const deviceId of devicesAll) {
      try {
        const keyHash = await env.KEN_KV.get(`device-key:${deviceId}`);
        if (keyHash) {
          await env.KEN_DB.prepare(
            'INSERT OR IGNORE INTO device_keys (device_id, key_hash) VALUES (?, ?)'
          ).bind(deviceId, keyHash).run();
          results.deviceKeys++;
        }
      } catch (e) { results.errors.push(`device-key:${deviceId}: ${e.message}`); }
    }

    // ===== MIGRATE USERS =====
    const userList = await env.KEN_KV.list({ prefix: 'user:' });
    for (const key of userList.keys) {
      try {
        const user = await env.KEN_KV.get(key.name, 'json');
        if (!user || !user.email) continue;

        // Insert user
        await env.KEN_DB.prepare(`
          INSERT OR IGNORE INTO users (
            email, name, phone, password_hash, password_salt, photo,
            global_role, poa, mfa_enabled, mfa_secret, mfa_backup_codes,
            consent_accepted, consent_policy_version, consent_at,
            subscriptions, last_login, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          user.email.toLowerCase(),
          user.name || '',
          user.phone || '',
          user.passwordHash || '',
          user.passwordSalt || '',
          user.photo || '',
          user.globalRole || null,
          user.poa ? 1 : 0,
          user.mfaEnabled ? 1 : 0,
          user.mfaSecret || null,
          user.mfaBackupCodes ? JSON.stringify(user.mfaBackupCodes) : null,
          user.consent ? 1 : 0,
          user.consentPolicyVersion || null,
          user.consentAt || null,
          user.subscriptions ? JSON.stringify(user.subscriptions) : '{}',
          user.lastLogin || null,
          user.createdAt || new Date().toISOString()
        ).run();
        results.users++;

        // Insert user-device relationships
        if (user.devices) {
          for (const [deviceId, deviceData] of Object.entries(user.devices)) {
            try {
              // Ensure device exists first
              await env.KEN_DB.prepare(
                'INSERT OR IGNORE INTO devices (device_id, user_name, created_at) VALUES (?, ?, ?)'
              ).bind(deviceId, 'The Ken', new Date().toISOString()).run();

              const role = typeof deviceData === 'object' ? (deviceData.role || 'standard') : 'standard';
              await env.KEN_DB.prepare(
                'INSERT OR IGNORE INTO user_devices (email, device_id, role) VALUES (?, ?, ?)'
              ).bind(user.email.toLowerCase(), deviceId, role).run();
              results.userDevices++;
            } catch (e) { results.errors.push(`user-device:${user.email}:${deviceId}: ${e.message}`); }
          }
        }
      } catch (e) { results.errors.push(`user:${key.name}: ${e.message}`); }
    }

    // ===== MIGRATE INVITES =====
    const inviteList = await env.KEN_KV.list({ prefix: 'invite:' });
    for (const key of inviteList.keys) {
      try {
        const invite = await env.KEN_KV.get(key.name, 'json');
        if (!invite) continue;
        // Key format: invite:{deviceId}:{email}
        const parts = key.name.replace('invite:', '').split(':');
        const deviceId = parts[0];
        const email = parts.slice(1).join(':'); // email may contain colons (unlikely but safe)
        await env.KEN_DB.prepare(
          'INSERT OR IGNORE INTO invites (device_id, email, role, invited_by, created_at) VALUES (?, ?, ?, ?, ?)'
        ).bind(deviceId, email, invite.role || 'standard', invite.invitedBy || null, invite.createdAt || new Date().toISOString()).run();
        results.invites++;
      } catch (e) { results.errors.push(`invite:${key.name}: ${e.message}`); }
    }

  } catch (e) {
    results.errors.push(`Fatal: ${e.message}`);
  }

  return new Response(JSON.stringify(results, null, 2), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// Export for use in worker
if (typeof module !== 'undefined') module.exports = { migratePhase1 };
