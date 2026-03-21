-- The Ken — D1 Database Schema
-- Migration from KV to D1 (SQLite)
-- Phase 1-5 implementation plan

-- ============================
-- PHASE 1: FOUNDATION
-- ============================

CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT DEFAULT '',
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    photo TEXT DEFAULT '',
    global_role TEXT,
    poa INTEGER DEFAULT 0,
    mfa_enabled INTEGER DEFAULT 0,
    mfa_secret TEXT,
    mfa_backup_codes TEXT,
    consent_accepted INTEGER DEFAULT 0,
    consent_policy_version TEXT,
    consent_at TEXT,
    subscriptions TEXT DEFAULT '{}',
    last_login TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    user_name TEXT DEFAULT 'The Ken',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    extra TEXT
);

CREATE TABLE IF NOT EXISTS user_devices (
    email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'standard',
    PRIMARY KEY (email, device_id)
);
CREATE INDEX IF NOT EXISTS idx_user_devices_device ON user_devices(device_id);

CREATE TABLE IF NOT EXISTS device_keys (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    device_id TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL,
    invited_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    PRIMARY KEY (device_id, email)
);

-- ============================
-- PHASE 2: MESSAGING
-- ============================

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    from_name TEXT NOT NULL,
    from_email TEXT,
    text TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    delivered_at TEXT,
    read_at TEXT,
    is_reply INTEGER DEFAULT 0,
    is_system_alert INTEGER DEFAULT 0,
    is_system_broadcast INTEGER DEFAULT 0,
    alert_to TEXT,
    group_id TEXT,
    group_name TEXT,
    was_scheduled INTEGER DEFAULT 0,
    deleted_by_sender INTEGER DEFAULT 0,
    deleted_by_sender_at TEXT,
    deleted_by_recipient INTEGER DEFAULT 0,
    deleted_by_recipient_at TEXT,
    deleted_for_everyone INTEGER DEFAULT 0,
    deleted_for_everyone_by TEXT,
    deleted_for_everyone_at TEXT,
    email_notification_sent INTEGER DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_messages_device ON messages(device_id, sent_at DESC);

CREATE TABLE IF NOT EXISTS message_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    emoji TEXT NOT NULL,
    reactor_name TEXT NOT NULL,
    reactor_id TEXT NOT NULL,
    reacted_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reactions_unique ON message_reactions(message_id, reactor_id);

CREATE TABLE IF NOT EXISTS scheduled_messages (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    from_name TEXT NOT NULL,
    from_email TEXT NOT NULL,
    text TEXT NOT NULL,
    scheduled_for TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sched_msgs_device ON scheduled_messages(device_id, status);

-- ============================
-- PHASE 3: CONTACTS, CALLS, VOICEMAILS
-- ============================

CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    name TEXT NOT NULL,
    relationship TEXT DEFAULT '',
    phone_number TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    birthday TEXT,
    is_emergency_contact INTEGER DEFAULT 0,
    has_poa INTEGER DEFAULT 0,
    position INTEGER DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_contacts_device ON contacts(device_id, position);

CREATE TABLE IF NOT EXISTS call_history (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    device_id TEXT NOT NULL,
    from_name TEXT,
    to_name TEXT,
    status TEXT,
    duration INTEGER DEFAULT 0,
    timestamp TEXT NOT NULL,
    email_notification_sent INTEGER DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_calls_device ON call_history(device_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS voicemails (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    from_name TEXT NOT NULL,
    type TEXT DEFAULT 'video',
    r2_key TEXT,
    media TEXT,
    duration INTEGER DEFAULT 0,
    timestamp TEXT NOT NULL,
    played INTEGER DEFAULT 0,
    played_at TEXT,
    delivered INTEGER DEFAULT 0,
    delivered_at TEXT,
    email_notification_sent INTEGER DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_voicemails_device ON voicemails(device_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS scheduled_voicemails (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    voicemail_id TEXT,
    from_name TEXT NOT NULL,
    from_email TEXT NOT NULL,
    scheduled_for TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

-- ============================
-- PHASE 4: MEDICAL, AUDIT, FEEDBACK
-- ============================

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_device ON audit_logs(device_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS pii_access_log (
    id TEXT PRIMARY KEY,
    type TEXT,
    severity TEXT,
    description TEXT,
    token TEXT,
    email TEXT,
    accessed_by TEXT,
    reason TEXT,
    users TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_pii_access_ts ON pii_access_log(timestamp DESC);

CREATE TABLE IF NOT EXISTS medical_info (
    device_id TEXT PRIMARY KEY,
    gp TEXT DEFAULT '{}',
    medications TEXT DEFAULT '[]',
    allergies TEXT DEFAULT '[]',
    conditions TEXT DEFAULT '[]',
    care_notes TEXT DEFAULT '',
    care_notes_log TEXT DEFAULT '[]',
    updated_at TEXT,
    updated_by TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS patient_info (
    device_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reminders (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    label TEXT NOT NULL,
    medication_name TEXT DEFAULT '',
    dosage TEXT DEFAULT '',
    instructions TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    time TEXT NOT NULL,
    days TEXT DEFAULT '["mon","tue","wed","thu","fri","sat","sun"]',
    frequency TEXT DEFAULT 'daily',
    start_date TEXT,
    end_date TEXT,
    enabled INTEGER DEFAULT 1,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_reminders_device ON reminders(device_id);

CREATE TABLE IF NOT EXISTS med_alerts (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    reminder_id TEXT,
    label TEXT,
    action TEXT,
    timestamp TEXT NOT NULL,
    resolved INTEGER DEFAULT 0,
    resolved_by TEXT,
    resolved_at TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_med_alerts_device ON med_alerts(device_id, resolved);

CREATE TABLE IF NOT EXISTS feedback_tickets (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    text TEXT,
    from_name TEXT,
    from_email TEXT,
    category TEXT,
    type TEXT,
    status TEXT DEFAULT 'open',
    submitted_by_email TEXT,
    submitted_by_name TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_feedback_device ON feedback_tickets(device_id, status);

CREATE TABLE IF NOT EXISTS feedback_replies (
    id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL REFERENCES feedback_tickets(id) ON DELETE CASCADE,
    from_name TEXT NOT NULL,
    from_email TEXT NOT NULL,
    role TEXT,
    text TEXT NOT NULL,
    image TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_replies_ticket ON feedback_replies(ticket_id);

-- ============================
-- PHASE 5: CONFIG, WORKFLOWS, SETTINGS
-- ============================

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cover_photo TEXT DEFAULT '',
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_groups_device ON groups(device_id);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS carer_alerts (
    device_id TEXT NOT NULL,
    email TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    threshold_minutes INTEGER DEFAULT 60,
    outside_nightlight_only INTEGER DEFAULT 1,
    method TEXT DEFAULT '["email"]',
    updated_at TEXT,
    updated_by TEXT,
    PRIMARY KEY (device_id, email)
);

CREATE TABLE IF NOT EXISTS check_ins (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    carer_email TEXT NOT NULL,
    carer_name TEXT,
    frequency TEXT NOT NULL,
    preferred_time TEXT NOT NULL,
    type TEXT NOT NULL,
    notes TEXT DEFAULT '',
    next_due TEXT,
    last_completed TEXT,
    reminder_sent INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_checkins_carer ON check_ins(device_id, carer_email);

CREATE TABLE IF NOT EXISTS hq_access_requests (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    hq_email TEXT NOT NULL,
    hq_name TEXT,
    content_type TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    approved_by TEXT,
    approved_at TEXT,
    expires_at TEXT,
    duration_hours INTEGER
);
CREATE INDEX IF NOT EXISTS idx_hq_requests_device ON hq_access_requests(device_id, status);

CREATE TABLE IF NOT EXISTS hq_access_grants (
    device_id TEXT NOT NULL,
    hq_email TEXT NOT NULL,
    content_type TEXT NOT NULL,
    approved INTEGER DEFAULT 1,
    expires_at TEXT,
    approved_by TEXT,
    approved_at TEXT,
    PRIMARY KEY (device_id, hq_email, content_type)
);

CREATE TABLE IF NOT EXISTS device_settings (
    device_id TEXT PRIMARY KEY,
    settings TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS offline_alert_config (
    device_id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 0,
    delay_minutes INTEGER DEFAULT 10,
    contact_names TEXT DEFAULT '[]',
    last_alert_sent TEXT,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS escalation_config (
    device_id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 1,
    triggers TEXT NOT NULL DEFAULT '{}',
    tiers TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_prefs (
    email TEXT PRIMARY KEY,
    timing TEXT DEFAULT '2min',
    messages INTEGER DEFAULT 1,
    voicemails INTEGER DEFAULT 1,
    missed_calls INTEGER DEFAULT 1,
    medication_alerts INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS birthday_prefs (
    device_id TEXT PRIMARY KEY,
    enabled INTEGER DEFAULT 1,
    notify_time TEXT DEFAULT '09:00',
    days_before TEXT DEFAULT '[0, 1, 7]',
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS device_feature_toggles (
    device_id TEXT NOT NULL,
    feature TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    PRIMARY KEY (device_id, feature)
);
