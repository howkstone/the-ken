// The Ken — KV → D1 Migration Script (All Phases)
// Run via: npx wrangler dev migrate-all.js --remote --port 8799
// Then: curl http://localhost:8799/

export default {
  async fetch(request, env) {
    if (!env.KEN_DB || !env.KEN_KV) {
      return new Response('Missing bindings', { status: 500 });
    }

    const results = {
      phase1: { users: 0, devices: 0, userDevices: 0, deviceKeys: 0 },
      phase2: { messages: 0, scheduledMsgs: 0 },
      phase3: { contacts: 0, callHistory: 0, voicemails: 0 },
      phase4: { audit: 0, medical: 0, reminders: 0, medAlerts: 0, feedback: 0 },
      phase5: { settings: 0, groups: 0, carerAlerts: 0, checkIns: 0, offlineAlerts: 0, escalation: 0, notifPrefs: 0, birthdayPrefs: 0 },
      errors: []
    };

    const devicesAll = await env.KEN_KV.get('devices:all', 'json') || [];

    // ===== PHASE 1: Users & Devices (re-run is safe — uses INSERT OR IGNORE / ON CONFLICT) =====
    for (const deviceId of devicesAll) {
      try {
        const info = await env.KEN_KV.get(`device:${deviceId}`, 'json') || {};
        await env.KEN_DB.prepare('INSERT OR IGNORE INTO devices (device_id, user_name, created_at, extra) VALUES (?, ?, ?, ?)')
          .bind(deviceId, info.userName || 'The Ken', info.createdAt || new Date().toISOString(), JSON.stringify(info)).run();
        results.phase1.devices++;
        const keyHash = await env.KEN_KV.get(`device-key:${deviceId}`);
        if (keyHash) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO device_keys (device_id, key_hash) VALUES (?, ?)').bind(deviceId, keyHash).run();
          results.phase1.deviceKeys++;
        }
      } catch (e) { results.errors.push(`P1 device:${deviceId}`); }
    }

    // Users
    const userKeys = await listAllKeys(env.KEN_KV, 'user:');
    for (const key of userKeys) {
      try {
        const user = await env.KEN_KV.get(key, 'json');
        if (!user || !user.email) continue;
        await env.KEN_DB.prepare(`INSERT INTO users (email, name, phone, password_hash, password_salt, photo, global_role, poa, mfa_enabled, mfa_secret, mfa_backup_codes, consent_accepted, consent_policy_version, consent_at, subscriptions, last_login, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET name=excluded.name, phone=excluded.phone, password_hash=excluded.password_hash, password_salt=excluded.password_salt, photo=excluded.photo, global_role=excluded.global_role, poa=excluded.poa, mfa_enabled=excluded.mfa_enabled, mfa_secret=excluded.mfa_secret, mfa_backup_codes=excluded.mfa_backup_codes, last_login=excluded.last_login`)
          .bind(user.email.toLowerCase(), user.name||'', user.phone||'', user.passwordHash||'', user.passwordSalt||'', user.photo||'', user.globalRole||null, user.poa?1:0, user.mfaEnabled?1:0, user.mfaSecret||null, user.mfaBackupCodes?JSON.stringify(user.mfaBackupCodes):null, user.consent?1:0, user.consentPolicyVersion||null, user.consentAt||null, user.subscriptions?JSON.stringify(user.subscriptions):'{}', user.lastLogin||null, user.createdAt||new Date().toISOString()).run();
        results.phase1.users++;
        if (user.devices) {
          for (const [did, data] of Object.entries(user.devices)) {
            await env.KEN_DB.prepare('INSERT OR IGNORE INTO devices (device_id, user_name, created_at) VALUES (?,?,?)').bind(did, 'The Ken', new Date().toISOString()).run();
            const role = typeof data === 'object' ? (data.role||'standard') : 'standard';
            await env.KEN_DB.prepare('INSERT INTO user_devices (email, device_id, role) VALUES (?,?,?) ON CONFLICT(email,device_id) DO UPDATE SET role=excluded.role').bind(user.email.toLowerCase(), did, role).run();
            results.phase1.userDevices++;
          }
        }
      } catch (e) { results.errors.push(`P1 user:${key}`); }
    }

    // ===== PHASE 2: Messages =====
    for (const deviceId of devicesAll) {
      try {
        const history = await env.KEN_KV.get(`history:${deviceId}`, 'json') || [];
        for (const msg of history) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO messages (id, device_id, from_name, from_email, text, sent_at, delivered_at, read_at, is_reply, is_system_alert, is_system_broadcast, alert_to, group_id, group_name, was_scheduled, deleted_by_sender, deleted_by_recipient, deleted_for_everyone, email_notification_sent) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(msg.id, deviceId, msg.from||'', msg.fromEmail||null, msg.text||'', msg.sentAt||'', msg.deliveredAt||null, msg.readAt||null, msg.isReply?1:0, msg.isSystemAlert?1:0, msg.isSystemBroadcast?1:0, msg.alertTo||null, msg.groupId||null, msg.groupName||null, msg.wasScheduled?1:0, msg.deletedBySender?1:0, msg.deletedByRecipient?1:0, msg.deletedForEveryone?1:0, msg.emailNotificationSent?1:0).run();
          results.phase2.messages++;
        }
        const scheduled = await env.KEN_KV.get(`scheduled-msgs:${deviceId}`, 'json') || [];
        for (const s of scheduled) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO scheduled_messages (id, device_id, from_name, from_email, text, scheduled_for, status, created_at) VALUES (?,?,?,?,?,?,?,?)')
            .bind(s.id, deviceId, s.from||'', s.fromEmail||'', s.text||'', s.scheduledFor||'', s.status||'scheduled', s.createdAt||new Date().toISOString()).run();
          results.phase2.scheduledMsgs++;
        }
      } catch (e) { results.errors.push(`P2 msgs:${deviceId}`); }
    }

    // ===== PHASE 3: Contacts, Calls, Voicemails =====
    for (const deviceId of devicesAll) {
      try {
        const contacts = await env.KEN_KV.get(`contactlist:${deviceId}`, 'json') || [];
        for (const c of contacts) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO contacts (id, device_id, name, relationship, phone_number, photo, birthday, is_emergency_contact, has_poa, position) VALUES (?,?,?,?,?,?,?,?,?,?)')
            .bind(c.id, deviceId, c.name||'', c.relationship||'', c.phoneNumber||'', c.photo||'', c.birthday||null, c.isEmergencyContact?1:0, c.hasPOA?1:0, c.position||0).run();
          results.phase3.contacts++;
        }
      } catch (e) { results.errors.push(`P3 contacts:${deviceId}`); }

      try {
        const callData = await env.KEN_KV.get(`callhistory:${deviceId}`, 'json') || {};
        for (const c of (callData.calls||[])) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO call_history (id, device_id, from_name, status, duration, timestamp, email_notification_sent) VALUES (?,?,?,?,?,?,?)')
            .bind(c.id||crypto.randomUUID(), deviceId, c.from||c.contactName||'', c.status||'', c.duration||0, c.timestamp||'', c.emailNotificationSent?1:0).run();
          results.phase3.callHistory++;
        }
      } catch (e) { results.errors.push(`P3 calls:${deviceId}`); }

      try {
        const vms = await env.KEN_KV.get(`voicemails:${deviceId}`, 'json') || [];
        for (const v of vms) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO voicemails (id, device_id, from_name, type, r2_key, duration, timestamp, played, played_at, delivered, delivered_at, email_notification_sent) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(v.id, deviceId, v.from||'', v.type||'video', v.r2Key||null, v.duration||0, v.timestamp||'', v.played?1:0, v.playedAt||null, v.delivered?1:0, v.deliveredAt||null, v.emailNotificationSent?1:0).run();
          results.phase3.voicemails++;
        }
      } catch (e) { results.errors.push(`P3 vms:${deviceId}`); }
    }

    // ===== PHASE 4: Audit, Medical, Reminders, Feedback =====
    for (const deviceId of devicesAll) {
      try {
        const audit = await env.KEN_KV.get(`audit:${deviceId}`, 'json') || [];
        for (const a of audit) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO audit_logs (id, device_id, user_id, action, details, timestamp) VALUES (?,?,?,?,?,?)')
            .bind(a.id, deviceId, a.userId||'', a.action||'', JSON.stringify(a.details||{}), a.timestamp||'').run();
          results.phase4.audit++;
        }
      } catch (e) { results.errors.push(`P4 audit:${deviceId}`); }

      try {
        const med = await env.KEN_KV.get(`medical:${deviceId}`, 'json');
        if (med) {
          await env.KEN_DB.prepare('INSERT INTO medical_info (device_id, gp, medications, allergies, conditions, care_notes, care_notes_log, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET gp=excluded.gp, medications=excluded.medications, allergies=excluded.allergies, conditions=excluded.conditions, care_notes=excluded.care_notes, care_notes_log=excluded.care_notes_log, updated_at=excluded.updated_at, updated_by=excluded.updated_by')
            .bind(deviceId, JSON.stringify(med.gp||{}), JSON.stringify(med.medications||[]), JSON.stringify(med.allergies||[]), JSON.stringify(med.conditions||[]), med.careNotes||'', JSON.stringify(med.careNotesLog||[]), med.updatedAt||null, med.updatedBy||'').run();
          results.phase4.medical++;
        }
      } catch (e) { results.errors.push(`P4 medical:${deviceId}`); }

      try {
        const reminders = await env.KEN_KV.get(`reminders:${deviceId}`, 'json') || [];
        for (const r of reminders) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO reminders (id, device_id, label, medication_name, dosage, instructions, time, days, frequency, enabled, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(r.id, deviceId, r.label||'', r.medicationName||'', r.dosage||'', r.instructions||'', r.time||'', JSON.stringify(r.days||[]), r.frequency||'daily', r.enabled!==false?1:0, r.createdBy||'', r.createdAt||new Date().toISOString()).run();
          results.phase4.reminders++;
        }
      } catch (e) { results.errors.push(`P4 reminders:${deviceId}`); }

      try {
        const alerts = await env.KEN_KV.get(`med-alerts:${deviceId}`, 'json') || [];
        for (const a of alerts) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO med_alerts (id, device_id, reminder_id, label, action, timestamp, resolved, resolved_by, resolved_at) VALUES (?,?,?,?,?,?,?,?,?)')
            .bind(a.id, deviceId, a.reminderId||null, a.label||'', a.action||'', a.timestamp||'', a.resolved?1:0, a.resolvedBy||null, a.resolvedAt||null).run();
          results.phase4.medAlerts++;
        }
      } catch (e) { results.errors.push(`P4 medAlerts:${deviceId}`); }

      try {
        const feedback = await env.KEN_KV.get(`feedback:${deviceId}`, 'json') || [];
        for (const t of feedback) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO feedback_tickets (id, device_id, text, from_name, from_email, category, type, status, submitted_by_email, submitted_by_name, timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
            .bind(t.id, deviceId, t.text||'', t.from||'', t.fromEmail||'', t.category||'', t.type||'', t.status||'open', t.submittedBy?.email||'', t.submittedBy?.name||'', t.timestamp||'').run();
          for (const r of (t.replies||[])) {
            await env.KEN_DB.prepare('INSERT OR IGNORE INTO feedback_replies (id, ticket_id, from_name, from_email, role, text, image, timestamp) VALUES (?,?,?,?,?,?,?,?)')
              .bind(r.id, t.id, r.from||'', r.fromEmail||'', r.role||'', r.text||'', r.image||null, r.timestamp||'').run();
          }
          results.phase4.feedback++;
        }
      } catch (e) { results.errors.push(`P4 feedback:${deviceId}`); }
    }

    // ===== PHASE 5: Settings, Groups, Carer Config =====
    for (const deviceId of devicesAll) {
      try {
        const settings = await env.KEN_KV.get(`settings:${deviceId}`, 'json');
        if (settings) {
          await env.KEN_DB.prepare('INSERT INTO device_settings (device_id, settings) VALUES (?,?) ON CONFLICT(device_id) DO UPDATE SET settings=excluded.settings')
            .bind(deviceId, JSON.stringify(settings)).run();
          results.phase5.settings++;
        }
      } catch (e) { results.errors.push(`P5 settings:${deviceId}`); }

      try {
        const groups = await env.KEN_KV.get(`groups:${deviceId}`, 'json') || [];
        for (const g of groups) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO groups (id, device_id, name, cover_photo, created_by, created_at) VALUES (?,?,?,?,?,?)')
            .bind(g.id, deviceId, g.name||'', g.coverPhoto||'', g.createdBy||'', g.createdAt||new Date().toISOString()).run();
          for (const m of (g.members||[])) {
            await env.KEN_DB.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id, name, role) VALUES (?,?,?,?)')
              .bind(g.id, m.userId||'', m.name||'', m.role||'member').run();
          }
          results.phase5.groups++;
        }
      } catch (e) { results.errors.push(`P5 groups:${deviceId}`); }

      try {
        const offline = await env.KEN_KV.get(`offline-alerts:${deviceId}`, 'json');
        if (offline) {
          await env.KEN_DB.prepare('INSERT INTO offline_alert_config (device_id, enabled, delay_minutes, contact_names, last_alert_sent) VALUES (?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET enabled=excluded.enabled, delay_minutes=excluded.delay_minutes, contact_names=excluded.contact_names')
            .bind(deviceId, offline.enabled?1:0, offline.delayMinutes||10, JSON.stringify(offline.contactNames||[]), offline.lastAlertSent||null).run();
          results.phase5.offlineAlerts++;
        }
      } catch (e) { results.errors.push(`P5 offline:${deviceId}`); }

      try {
        const esc = await env.KEN_KV.get(`escalation-config:${deviceId}`, 'json');
        if (esc) {
          await env.KEN_DB.prepare('INSERT INTO escalation_config (device_id, enabled, triggers, tiers) VALUES (?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET enabled=excluded.enabled, triggers=excluded.triggers, tiers=excluded.tiers')
            .bind(deviceId, esc.enabled!==false?1:0, JSON.stringify(esc.triggers||{}), JSON.stringify(esc.tiers||[])).run();
          results.phase5.escalation++;
        }
      } catch (e) { results.errors.push(`P5 escalation:${deviceId}`); }

      try {
        const bp = await env.KEN_KV.get(`birthday-prefs:${deviceId}`, 'json');
        if (bp) {
          await env.KEN_DB.prepare('INSERT INTO birthday_prefs (device_id, enabled, notify_time, days_before) VALUES (?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET enabled=excluded.enabled, notify_time=excluded.notify_time, days_before=excluded.days_before')
            .bind(deviceId, bp.enabled!==false?1:0, bp.notifyTime||'09:00', JSON.stringify(bp.daysBefore||[0,1,7])).run();
          results.phase5.birthdayPrefs++;
        }
      } catch (e) { results.errors.push(`P5 birthday:${deviceId}`); }
    }

    // Carer alerts and check-ins (keyed per user per device)
    const carerAlertKeys = await listAllKeys(env.KEN_KV, 'carer-alerts:');
    for (const key of carerAlertKeys) {
      try {
        const alert = await env.KEN_KV.get(key, 'json');
        if (!alert) continue;
        const parts = key.replace('carer-alerts:', '').split(':');
        const did = parts[0]; const email = parts.slice(1).join(':');
        await env.KEN_DB.prepare('INSERT INTO carer_alerts (device_id, email, enabled, threshold_minutes, outside_nightlight_only, method, updated_at, updated_by) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(device_id, email) DO UPDATE SET enabled=excluded.enabled, threshold_minutes=excluded.threshold_minutes')
          .bind(did, email, alert.enabled?1:0, alert.thresholdMinutes||60, alert.outsideNightlightOnly?1:0, JSON.stringify(alert.method||['email']), alert.updatedAt||null, alert.updatedBy||null).run();
        results.phase5.carerAlerts++;
      } catch (e) { results.errors.push(`P5 carer-alert:${key}`); }
    }

    const checkInKeys = await listAllKeys(env.KEN_KV, 'check-ins:');
    for (const key of checkInKeys) {
      try {
        const items = await env.KEN_KV.get(key, 'json') || [];
        for (const ci of items) {
          await env.KEN_DB.prepare('INSERT OR IGNORE INTO check_ins (id, device_id, carer_email, carer_name, frequency, preferred_time, type, notes, next_due, last_completed, reminder_sent, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
            .bind(ci.id, ci.deviceId||'', ci.carerId||ci.carerEmail||'', ci.carerName||'', ci.frequency||'daily', ci.preferredTime||'', ci.type||'visit', ci.notes||'', ci.nextDue||null, ci.lastCompleted||null, ci.reminderSent?1:0, ci.createdAt||new Date().toISOString()).run();
          results.phase5.checkIns++;
        }
      } catch (e) { results.errors.push(`P5 checkin:${key}`); }
    }

    // Notification prefs (per user)
    const notifKeys = await listAllKeys(env.KEN_KV, 'notif-prefs:');
    for (const key of notifKeys) {
      try {
        const prefs = await env.KEN_KV.get(key, 'json');
        if (!prefs) continue;
        const email = key.replace('notif-prefs:', '');
        await env.KEN_DB.prepare('INSERT INTO notification_prefs (email, timing, messages, voicemails, missed_calls, medication_alerts) VALUES (?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET timing=excluded.timing, messages=excluded.messages, voicemails=excluded.voicemails, missed_calls=excluded.missed_calls, medication_alerts=excluded.medication_alerts')
          .bind(email, prefs.timing||'2min', prefs.messages!==false?1:0, prefs.voicemails!==false?1:0, prefs.missedCalls!==false?1:0, prefs.medicationAlerts!==false?1:0).run();
        results.phase5.notifPrefs++;
      } catch (e) { results.errors.push(`P5 notif:${key}`); }
    }

    return new Response(JSON.stringify(results, null, 2), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

async function listAllKeys(kv, prefix) {
  let cursor = undefined;
  const keys = [];
  do {
    const list = await kv.list({ prefix, cursor, limit: 100 });
    keys.push(...list.keys.map(k => k.name));
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
  return keys;
}
