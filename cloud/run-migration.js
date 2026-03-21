// Temporary migration worker — run with: npx wrangler dev run-migration.js --remote
// Then visit http://localhost:8787 to trigger migration

export default {
  async fetch(request, env) {
    if (!env.KEN_DB || !env.KEN_KV) {
      return new Response('Missing bindings', { status: 500 });
    }

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

          const keyHash = await env.KEN_KV.get(`device-key:${deviceId}`);
          if (keyHash) {
            await env.KEN_DB.prepare('INSERT OR IGNORE INTO device_keys (device_id, key_hash) VALUES (?, ?)').bind(deviceId, keyHash).run();
            results.deviceKeys++;
          }
        } catch (e) { results.errors.push(`device:${deviceId}: ${e.message}`); }
      }

      // Migrate users
      let cursor = undefined;
      let allUserKeys = [];
      do {
        const list = await env.KEN_KV.list({ prefix: 'user:', cursor, limit: 100 });
        allUserKeys = allUserKeys.concat(list.keys);
        cursor = list.list_complete ? undefined : list.cursor;
      } while (cursor);

      for (const key of allUserKeys) {
        try {
          const user = await env.KEN_KV.get(key.name, 'json');
          if (!user || !user.email) continue;

          await env.KEN_DB.prepare(`
            INSERT INTO users (email, name, phone, password_hash, password_salt, photo,
              global_role, poa, mfa_enabled, mfa_secret, mfa_backup_codes,
              consent_accepted, consent_policy_version, consent_at,
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
            user.email.toLowerCase(),
            user.name || '', user.phone || '',
            user.passwordHash || '', user.passwordSalt || '',
            user.photo || '', user.globalRole || null,
            user.poa ? 1 : 0, user.mfaEnabled ? 1 : 0,
            user.mfaSecret || null,
            user.mfaBackupCodes ? JSON.stringify(user.mfaBackupCodes) : null,
            user.consent ? 1 : 0, user.consentPolicyVersion || null, user.consentAt || null,
            user.subscriptions ? JSON.stringify(user.subscriptions) : '{}',
            user.lastLogin || null, user.createdAt || new Date().toISOString()
          ).run();
          results.users++;

          if (user.devices) {
            for (const [deviceId, data] of Object.entries(user.devices)) {
              try {
                await env.KEN_DB.prepare('INSERT OR IGNORE INTO devices (device_id, user_name, created_at) VALUES (?, ?, ?)')
                  .bind(deviceId, 'The Ken', new Date().toISOString()).run();
                const role = typeof data === 'object' ? (data.role || 'standard') : 'standard';
                await env.KEN_DB.prepare('INSERT INTO user_devices (email, device_id, role) VALUES (?, ?, ?) ON CONFLICT(email, device_id) DO UPDATE SET role=excluded.role')
                  .bind(user.email.toLowerCase(), deviceId, role).run();
                results.userDevices++;
              } catch (e) { results.errors.push(`user-device:${user.email}:${deviceId}: ${e.message}`); }
            }
          }
        } catch (e) { results.errors.push(`${key.name}: ${e.message}`); }
      }

      // Migrate invites
      let invCursor = undefined;
      let allInviteKeys = [];
      do {
        const list = await env.KEN_KV.list({ prefix: 'invite:', cursor: invCursor, limit: 100 });
        allInviteKeys = allInviteKeys.concat(list.keys);
        invCursor = list.list_complete ? undefined : list.cursor;
      } while (invCursor);

      for (const key of allInviteKeys) {
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

    } catch (e) {
      results.errors.push(`Fatal: ${e.message}`);
    }

    return new Response(JSON.stringify(results, null, 2), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
};
