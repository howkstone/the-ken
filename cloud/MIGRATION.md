# KV → D1 Migration Plan

## Overview
40+ KV key patterns identified. 27 migrate to D1, 22 stay in KV (ephemeral), 3 stay in PII namespace.

## Keep in KV (ephemeral/cache data)
- `heartbeat:`, `heartbeat-time:` — TTL-based, high frequency polling
- `call:`, `outbound:` — 120s TTL, call signaling
- `typing:` — 15s TTL, typing indicators
- `screen:active:`, `screen:frame:` — screen viewing sessions
- `voicemail-req:` — 120s signal
- `messages:` (pending queue) — transient delivery queue
- `pending:` (contacts queue) — transient queue
- `queue:` (settings queue) — transient queue
- `session:` — 30-day TTL, auth sessions
- `ratelimit:`, `lockout:`, `mfa-setup:`, `reset:`, `activity:` — ephemeral counters/tokens
- `birthday-sent:`, `breach-alert:`, `retention-purge-last` — dedup flags
- `provision-token:` — one-time tokens
- `escalation-active:` — 24h TTL active state
- `room:` — video room URLs

## Migration Phases

### Phase 1 — Foundation (lowest risk, highest value)
- `user:{email}` → `users` + `user_devices` tables
- `device:{deviceId}` + `devices:all` → `devices` table
- `device-key:{deviceId}` → `device_keys` table
- `invite:{deviceId}:{email}` → `invites` table
- Eliminates `list(prefix:'user:')` anti-pattern (~20 occurrences)

### Phase 2 — Messaging (biggest KV pain point)
- `history:{deviceId}` → `messages` + `message_reactions` tables
- `scheduled-msgs:{deviceId}` → `scheduled_messages` table
- Keep `messages:{deviceId}` pending queue in KV

### Phase 3 — Contacts, Calls, Voicemails
- `contactlist:{deviceId}` → `contacts`
- `callhistory:{deviceId}` → `call_history`
- `voicemails:{deviceId}` → `voicemails`
- `scheduled-vm:{deviceId}` → `scheduled_voicemails`

### Phase 4 — Medical, Audit, Feedback
- `audit:{deviceId}` + archives → `audit_logs` (no more archiving needed)
- `medical:{deviceId}` → `medical_info` (encrypted fields preserved)
- `reminders:{deviceId}` → `reminders`
- `med-alerts:{deviceId}` → `med_alerts`
- `feedback:{deviceId}` → `feedback_tickets` + `feedback_replies`

### Phase 5 — Config, Workflows, Settings
- All remaining config/settings tables

## Implementation Steps (per phase)
1. Apply schema: `wrangler d1 execute ken-db --file=schema.sql`
2. Write migration script to backfill KV → D1
3. Update Worker to read from D1 (with KV fallback)
4. Verify, then switch writes to D1-only
5. Remove KV reads for migrated data

## Key Challenges
- ~200+ KV call sites need refactoring to D1 prepared statements
- `user.devices` embedded object → `user_devices` junction table
- Array read-modify-write → individual SQL INSERT/UPDATE/DELETE
- Encrypted medical fields must be preserved
- Photos in base64 may exceed 1MB D1 row limit → move to R2 references
