const https = require('https');

const BASE = 'ken-api.the-ken.workers.dev';
const DEVICE_ID = '195875dd-672c-4c43-bbd3-b841ca0ba9ec';

function request(method, path, body, cookie) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: BASE,
      path,
      method,
      headers: { 'Content-Type': 'application/json', 'X-Ken-CSRF': '1' },
    };
    if (cookie) opts.headers['Cookie'] = cookie;

    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        const setCookie = res.headers['set-cookie'];
        let session = null;
        if (setCookie) {
          for (const c of setCookie) {
            const m = c.match(/ken_session=([^;]+)/);
            if (m) session = `ken_session=${m[1]}`;
          }
        }
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, body: parsed, session });
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function run() {
  console.log('=== STEP 1: Register test accounts ===\n');

  const reg1 = await request('POST', '/api/auth/register', {
    email: 'test-user-role@test.com',
    password: 'TestPass2026!',
    name: 'Test User Role',
    deviceId: DEVICE_ID,
  });
  console.log(`Register standard account: ${reg1.status}`, typeof reg1.body === 'object' ? JSON.stringify(reg1.body).slice(0, 200) : reg1.body);

  const reg2 = await request('POST', '/api/auth/register', {
    email: 'test-user-basic@test.com',
    password: 'TestPass2026!',
    name: 'Test Basic User',
    deviceId: DEVICE_ID,
  });
  console.log(`Register basic account:    ${reg2.status}`, typeof reg2.body === 'object' ? JSON.stringify(reg2.body).slice(0, 200) : reg2.body);

  console.log('\n=== STEP 2: Login ===\n');

  const login = await request('POST', '/api/auth/login', {
    email: 'test-user-role@test.com',
    password: 'TestPass2026!',
  });
  console.log(`Login status: ${login.status}`, typeof login.body === 'object' ? JSON.stringify(login.body).slice(0, 200) : login.body);
  console.log(`Session cookie: ${login.session ? 'CAPTURED' : 'MISSING'}`);

  if (!login.session) {
    console.error('FATAL: No session cookie received. Cannot continue.');
    return;
  }

  const cookie = login.session;

  console.log('\n=== STEP 3: Test ALL endpoints with standard role ===\n');

  const tests = [
    // [method, path, body, expectedOutcome, description, permission]
    ['GET',  `/api/contacts/${DEVICE_ID}/list`,   null, 'PASS', 'List contacts',        'view:contacts YES'],
    ['POST', `/api/contacts/${DEVICE_ID}/update`,  { name: 'x', phone: '0' }, 'FAIL', 'Update contact',  'edit:contacts NO'],
    ['POST', `/api/contacts/${DEVICE_ID}/delete`,  { contactId: 'fake-id' },  'FAIL', 'Delete contact',  'edit:contacts NO'],
    ['GET',  `/api/messages/${DEVICE_ID}/history`, null, 'PASS', 'Message history',      'view:messages YES'],
    ['POST', `/api/messages/${DEVICE_ID}`,         { type: 'text', content: 'test msg', from: 'Test' }, 'PASS', 'Send message', 'send:messages YES'],
    ['GET',  `/api/calls/${DEVICE_ID}/room`,       null, 'PASS', 'Get call room',        'implicit YES'],
    ['GET',  `/api/medical/${DEVICE_ID}`,          null, 'FAIL', 'View medical',         'view:medical NO'],
    ['POST', `/api/medical/${DEVICE_ID}`,          { data: 'test' },          'FAIL', 'Edit medical',    'edit:medical NO'],
    ['GET',  `/api/settings/${DEVICE_ID}`,         null, 'TEST', 'View settings',        'unclear'],
    ['POST', `/api/settings/${DEVICE_ID}`,         { brightness: 50 },        'FAIL', 'Edit settings',   'edit:settings NO'],
    ['GET',  `/api/reminders/${DEVICE_ID}`,        null, 'TEST', 'View reminders',       'unclear'],
    ['POST', `/api/reminders/${DEVICE_ID}`,        { text: 'test', time: '09:00' }, 'FAIL', 'Edit reminders', 'edit:reminders NO'],
    ['GET',  `/api/audit/${DEVICE_ID}`,            null, 'FAIL', 'View audit log',       'view:audit NO'],
    ['GET',  `/api/carer/devices`,                 null, 'FAIL', 'Carer devices list',   'manage:multiple_devices NO'],
    ['GET',  `/api/hq/devices`,                    null, 'FAIL', 'HQ devices list',      'view:all_devices NO'],
    ['POST', `/api/screen/${DEVICE_ID}/start`,     null, 'FAIL', 'Screen viewer start',  'remote:view_pi NO'],
    ['GET',  `/api/photos/${DEVICE_ID}`,           null, 'TEST', 'View photos',          'unclear'],
    ['POST', `/api/auth/invite`,                   { email: 'invite@test.com', deviceId: DEVICE_ID, role: 'user' }, 'FAIL', 'Send invite', 'manage:invites NO'],
  ];

  const results = [];

  for (const [method, path, body, expected, desc, perm] of tests) {
    try {
      const res = await request(method, path, body, cookie);
      const is2xx = res.status >= 200 && res.status < 300;
      let match;
      if (expected === 'PASS') {
        match = is2xx ? 'CORRECT' : 'UNEXPECTED';
      } else if (expected === 'FAIL') {
        match = !is2xx ? 'CORRECT' : 'UNEXPECTED';
      } else {
        match = is2xx ? 'ALLOWED' : 'DENIED';
      }

      const bodyStr = typeof res.body === 'object' ? JSON.stringify(res.body).slice(0, 120) : String(res.body).slice(0, 120);
      results.push({ desc, method, path: path.replace(DEVICE_ID, '{deviceId}'), status: res.status, expected, match, perm, bodyStr });
    } catch (err) {
      results.push({ desc, method, path: path.replace(DEVICE_ID, '{deviceId}'), status: 'ERR', expected, match: 'ERROR', perm, bodyStr: err.message });
    }
  }

  // Print results table
  console.log('TEST RESULTS:');
  console.log('─'.repeat(160));
  console.log(
    'Description'.padEnd(22) +
    'Method'.padEnd(7) +
    'Endpoint'.padEnd(40) +
    'Status'.padEnd(8) +
    'Expected'.padEnd(10) +
    'Result'.padEnd(13) +
    'Permission'.padEnd(30) +
    'Response'
  );
  console.log('─'.repeat(160));

  let pass = 0, fail = 0, info = 0;
  for (const r of results) {
    const line =
      r.desc.padEnd(22) +
      r.method.padEnd(7) +
      r.path.padEnd(40) +
      String(r.status).padEnd(8) +
      r.expected.padEnd(10) +
      r.match.padEnd(13) +
      r.perm.padEnd(30) +
      r.bodyStr;
    console.log(line);
    if (r.match === 'CORRECT') pass++;
    else if (r.match === 'UNEXPECTED' || r.match === 'ERROR') fail++;
    else info++;
  }

  console.log('─'.repeat(160));
  console.log(`\nSUMMARY: ${pass} correct, ${fail} unexpected, ${info} informational (unclear expected) out of ${results.length} tests`);

  // Detail unexpected results
  const unexpected = results.filter(r => r.match === 'UNEXPECTED' || r.match === 'ERROR');
  if (unexpected.length > 0) {
    console.log('\n=== UNEXPECTED RESULTS (need investigation) ===\n');
    for (const r of unexpected) {
      console.log(`  ${r.desc}: got ${r.status}, expected ${r.expected}`);
      console.log(`    Response: ${r.bodyStr}`);
    }
  }
}

run().catch(console.error);
