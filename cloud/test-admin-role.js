const https = require('https');

const API_BASE = 'ken-api.the-ken.workers.dev';
const DEVICE_ID = '195875dd-672c-4c43-bbd3-b841ca0ba9ec';
const TEST_EMAIL = 'test-admin-check-' + Date.now() + '@test.com';
const TEST_PASS = 'TestPass2026!';

function request(method, path, body, cookie) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: API_BASE,
      path: path,
      method: method,
      headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
    };
    if (cookie) options.headers['Cookie'] = cookie;

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: parsed,
        });
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function main() {
  console.log('=== ADMIN ROLE PERMISSION TESTING ===\n');
  console.log(`Test email: ${TEST_EMAIL}\n`);

  // Step 1: Register
  console.log('--- Registering test user ---');
  const reg = await request('POST', '/api/auth/register', {
    email: TEST_EMAIL,
    password: TEST_PASS,
    name: 'Admin Check User',
    deviceId: DEVICE_ID,
  });
  console.log(`Register: ${reg.status}`, typeof reg.body === 'object' ? JSON.stringify(reg.body).substring(0, 200) : reg.body);

  // Step 2: Login
  console.log('\n--- Logging in ---');
  const login = await request('POST', '/api/auth/login', {
    email: TEST_EMAIL,
    password: TEST_PASS,
  });
  console.log(`Login: ${login.status}`, typeof login.body === 'object' ? JSON.stringify(login.body).substring(0, 200) : login.body);

  const setCookie = login.headers['set-cookie'];
  let cookie = '';
  if (setCookie) {
    cookie = Array.isArray(setCookie)
      ? setCookie.map((c) => c.split(';')[0]).join('; ')
      : setCookie.split(';')[0];
  }
  console.log(`Cookie: ${cookie ? cookie.substring(0, 40) + '...' : 'NONE'}`);

  if (!cookie) {
    console.log('ERROR: No session cookie received. Cannot proceed.');
    return;
  }

  // Verify our role
  console.log('\n--- Checking our role ---');
  const me = await request('GET', '/api/auth/me', null, cookie);
  console.log(`Me: ${me.status}`, typeof me.body === 'object' ? JSON.stringify(me.body).substring(0, 300) : me.body);

  // Step 3: Test all admin-gated endpoints
  // Note: contacts endpoints use "id" not "contactId" in the API
  const tests = [
    // Contacts - these SHOULD require edit:contacts (admin/carer) but currently DON'T have checks
    { method: 'POST', path: `/api/contacts/${DEVICE_ID}/update`, body: { id: 'fake-id-123', name: 'test' }, expected: 403, label: 'contacts/update' },
    { method: 'POST', path: `/api/contacts/${DEVICE_ID}/delete`, body: { id: 'fake-id-123' }, expected: 403, label: 'contacts/delete' },
    { method: 'POST', path: `/api/contacts/${DEVICE_ID}/emergency`, body: { id: 'fake-id-123', isEmergencyContact: true }, expected: 403, label: 'contacts/emergency' },
    // Contacts POA - has HQ check
    { method: 'POST', path: `/api/contacts/${DEVICE_ID}/poa`, body: { id: 'fake-id-123', hasPOA: true }, expected: 403, label: 'contacts/poa' },
    // Medical - has permission checks
    { method: 'POST', path: `/api/medical/${DEVICE_ID}`, body: { gp: 'test' }, expected: 403, label: 'medical/update' },
    { method: 'POST', path: `/api/medical/${DEVICE_ID}/care-notes`, body: { notes: 'test' }, expected: 403, label: 'medical/care-notes' },
    // Settings - SHOULD require edit:settings but currently DOESN'T
    { method: 'POST', path: `/api/settings/${DEVICE_ID}`, body: { dnd: true }, expected: 403, label: 'settings/update' },
    // Reminders - has permission checks
    { method: 'POST', path: `/api/reminders/${DEVICE_ID}`, body: { text: 'test', time: '09:00', repeat: 'daily' }, expected: 403, label: 'reminders/create' },
    { method: 'DELETE', path: `/api/reminders/${DEVICE_ID}/fake-id`, body: null, expected: 403, label: 'reminders/delete' },
    // Photos - SHOULD require permission but currently DOESN'T
    { method: 'POST', path: `/api/photos/${DEVICE_ID}`, body: { photo: 'data:image/png;base64,iVBOR' }, expected: 403, label: 'photos/upload' },
    { method: 'DELETE', path: `/api/photos/${DEVICE_ID}/fake-id`, body: null, expected: 403, label: 'photos/delete' },
    // Auth invite - has admin check
    { method: 'POST', path: '/api/auth/invite', body: { email: 'fake@test.com', role: 'standard', deviceId: DEVICE_ID }, expected: 403, label: 'auth/invite' },
    // Audit - has permission check
    { method: 'GET', path: `/api/audit/${DEVICE_ID}`, body: null, expected: 403, label: 'audit/list' },
    // Feedback GET - admin/hq only
    { method: 'GET', path: `/api/feedback/${DEVICE_ID}`, body: null, expected: 403, label: 'feedback/list' },
    // Offline alerts - SHOULD require edit:settings but currently DOESN'T
    { method: 'POST', path: `/api/settings/${DEVICE_ID}/offline-alerts`, body: { enabled: false, delayMinutes: 10 }, expected: 403, label: 'settings/offline-alerts' },
    // Screen viewing - HQ only
    { method: 'POST', path: `/api/screen/${DEVICE_ID}/start`, body: {}, expected: 403, label: 'screen/start' },
    // HQ endpoints
    { method: 'POST', path: `/api/hq/request-access/${DEVICE_ID}`, body: {}, expected: 403, label: 'hq/request-access' },
    { method: 'GET', path: '/api/hq/devices', body: null, expected: 403, label: 'hq/devices' },
  ];

  console.log('\n--- Testing admin-gated endpoints with STANDARD role ---\n');

  const results = [];
  for (const t of tests) {
    try {
      const res = await request(t.method, t.path, t.body, cookie);
      const pass = res.status === t.expected;
      results.push({
        endpoint: `${t.method} ${t.label}`,
        expected: t.expected,
        actual: res.status,
        pass: pass ? 'PASS' : 'FAIL',
        detail: typeof res.body === 'object' ? (res.body.error || res.body.message || JSON.stringify(res.body).substring(0, 80)) : String(res.body).substring(0, 80),
      });
    } catch (err) {
      results.push({
        endpoint: `${t.method} ${t.label}`,
        expected: t.expected,
        actual: 'ERR',
        pass: 'FAIL',
        detail: err.message,
      });
    }
  }

  // Print table
  console.log('Endpoint'.padEnd(35) + 'Expected'.padEnd(10) + 'Actual'.padEnd(10) + 'Result'.padEnd(8) + 'Detail');
  console.log('-'.repeat(130));
  let passCount = 0;
  let failCount = 0;
  for (const r of results) {
    console.log(
      r.endpoint.padEnd(35) +
      String(r.expected).padEnd(10) +
      String(r.actual).padEnd(10) +
      r.pass.padEnd(8) +
      r.detail
    );
    if (r.pass === 'PASS') passCount++;
    else failCount++;
  }

  console.log('\n' + '='.repeat(60));
  console.log(`TOTAL: ${results.length} tests | PASS: ${passCount} | FAIL: ${failCount}`);
  console.log('='.repeat(60));

  // Summary of security issues
  const failures = results.filter(r => r.pass === 'FAIL');
  if (failures.length > 0) {
    console.log('\n=== SECURITY ISSUES FOUND ===');
    for (const f of failures) {
      console.log(`  [!] ${f.endpoint} - returned ${f.actual} instead of ${f.expected} (${f.detail})`);
    }
    console.log('\nThese endpoints are accessible to STANDARD role users but should be restricted to admin/carer/hq.');
  }

  // Cleanup
  console.log('\n--- Cleanup ---');
  const del = await request('POST', '/api/auth/delete-account', { confirm: true }, cookie);
  console.log(`Delete account: ${del.status}`, typeof del.body === 'object' ? JSON.stringify(del.body) : del.body);
}

main().catch(console.error);
