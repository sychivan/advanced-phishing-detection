const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'phishguard-frontend.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

class TestElement {
  constructor() {
    this.children = new Map();
    this.matches = new Map();
    this.isConnected = true;
    const classes = new Set();
    this.classList = {
      contains: value => classes.has(value),
      add: value => classes.add(value),
      remove: value => classes.delete(value),
    };
  }

  set innerHTML(markup) {
    for (const child of this.children.values()) child.detach();
    for (const elements of this.matches.values()) elements.forEach(element => element.detach());
    this.children.clear();
    this.matches.clear();
    for (const match of markup.matchAll(/\bid="([^"]+)"/g)) {
      this.children.set('#' + match[1], new TestElement());
    }
    const chips = [...markup.matchAll(/<button class="chip" data-f="([^"]+)"/g)].map(match => {
      const chip = new TestElement();
      chip.dataset = { f: match[1] };
      return chip;
    });
    if (chips.length) this.matches.set('.chip', chips);
    this.markup = markup;
  }

  get innerHTML() { return this.markup || ''; }

  detach() {
    this.isConnected = false;
    for (const child of this.children.values()) child.detach();
    for (const elements of this.matches.values()) elements.forEach(element => element.detach());
  }

  querySelector(selector) {
    if (this.children.has(selector)) return this.children.get(selector);
    for (const child of this.children.values()) {
      const match = child.querySelector(selector);
      if (match) return match;
    }
    return null;
  }

  focus() {}
  remove() { this.detach(); }
  showModal() { this.open = true; }
  close() { this.open = false; }
  querySelectorAll(selector) {
    return [...(this.matches.get(selector) || []),
      ...[...this.children.values()].flatMap(child => child.querySelectorAll(selector))];
  }
  appendChild() {}
  setAttribute() {}
}

const gmailEmail = 'gmail-demo@example.test';

function scoredMessage(index) {
  return {
    sender: 'Synthetic Sender <sender@example.test>',
    subject: 'Synthetic sample ' + index,
    classification: 'Phishing',
    risk_score: 51 + index,
    model_status: 'connected',
    reasons: [`Synthetic reason ${index} <sample>`],
  };
}

async function openDashboard({ messages = [], demoSignedIn = false, demoData, initialHash } = {}) {
  const document = new TestElement();
  document.innerHTML = '<div id="app"></div><div id="drawer"></div><div id="overlay"></div><div id="toasts"></div>'
    + '<dialog id="confirm"></dialog><h2 id="confirm-title"></h2><p id="confirm-msg"></p>'
    + '<button id="confirm-yes"></button><button id="confirm-no"></button>';
  document.addEventListener = () => {};
  document.createElement = () => new TestElement();
  const location = new URL('http://127.0.0.1:5000/gmail/app' + (initialHash || (demoData ? '#/overview' : '#/mail')));
  const session = {
    connection: demoData ? { connected: false } : { connected: true, email: gmailEmail, csrf: 'synthetic-session-one' },
    scanStatus: 200,
    scanDelay: null,
  };
  const calls = [];
  const storage = new Map();
  if (demoSignedIn) {
    storage.set('pg_session', JSON.stringify({
      token: 'synthetic-demo-bearer', user: { email: 'local-demo@example.test' },
    }));
  }
  const events = new Map();
  const context = vm.createContext({
    document, location, URL, URLSearchParams,
    // The production mock adapter has artificial delays, not real network I/O.
    setTimeout: callback => setImmediate(callback),
    history: { replaceState: (_data, _unused, hash) => { location.hash = hash; } },
    sessionStorage: {
      getItem: key => storage.get(key),
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key),
    },
    window: {
      addEventListener: (name, callback) => events.set(name, callback),
      scrollTo: () => {},
    },
    fetch: async (url, options = {}) => {
      const method = options.method || 'GET';
      const csrf = options.body?.get('csrf');
      calls.push({ url, method, csrf });
      const response = (status, body) => ({
        ok: status >= 200 && status < 300, status, json: async () => body,
      });
      if (url === '/gmail/session') return response(200, session.connection);
      if (demoData && url.startsWith(location.origin + '/api/')) {
        assert.equal(options.headers.Authorization, 'Bearer synthetic-demo-bearer');
        const resource = url.slice(location.origin.length);
        assert.ok(Object.hasOwn(demoData, resource), 'Unexpected demo resource');
        if (typeof demoData[resource] === 'function') {
          const result = await demoData[resource]({ method, options });
          return response(result.status, result.body);
        }
        assert.equal(method, 'GET');
        return response(200, demoData[resource]);
      }
      assert.equal(method, 'POST');
      if (url === '/gmail/scan') {
        if (session.scanStatus === 401) {
          session.connection = { connected: false };
          return response(401, { error: 'Synthetic connection expired.' });
        }
        assert.equal(csrf, session.connection.csrf);
        await session.scanDelay;
        return response(200, { messages });
      }
      assert.equal(url, '/gmail/disconnect', 'Unexpected frontend network request');
      assert.equal(csrf, session.connection.csrf);
      session.connection = { connected: false };
      return response(200, session.connection);
    },
  });
  await vm.runInContext(script, context, { filename: 'phishguard-frontend-inline.js' });
  if (demoData) await new Promise(resolve => setImmediate(resolve));
  const element = selector => document.querySelector(selector);
  return {
    element, location, calls, session,
    mock: vm.runInContext('MockAdapter', context),
    localSession: vm.runInContext('Session', context),
    scan: () => element('#gmail-scan').onclick(),
    signOut: () => element('#logout').onclick({ currentTarget: element('#logout') }),
    navigate: async hash => {
      if (hash) location.hash = hash;
      await events.get('hashchange')();
      if (demoData) await new Promise(resolve => setImmediate(resolve));
    },
  };
}

test('stored-message Overview describes score bands and their denominator', async () => {
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': {
        total: 3, safe: 1, suspicious: 1, phishing: 1, quarantined: 0,
        daily: [{ date: '2026-11-22', safe: 2, phishing: 1 }],
      },
      '/api/messages?status=quarantine': [],
    },
  });
  const markup = dashboard.element('#main').innerHTML;
  assert.match(markup, /cutoff of 50/);
  assert.match(markup, /Below 40 · 33% of stored messages/);
  assert.match(markup, /40 to below 70 · 33% of stored messages/);
  assert.match(markup, /70 or above · 33% of stored messages/);
  assert.match(markup, /2 below 70, 1 at 70 or above/);
  assert.doesNotMatch(markup, /Phishing detected|Safe emails|model accuracy/i);
});

test('Quarantine fetches detail and separates a moderate score from a Phishing prediction', async () => {
  const row = {
    id: 'synthetic-1',
    subject: 'Synthetic sample',
    from: { name: 'Synthetic Sender', email: 'sender@example.test' },
    receivedAt: '2026-11-22T00:00:00Z',
    score: 69.99,
    status: 'quarantine',
    body: 'Synthetic message body',
  };
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': { total: 1, safe: 0, suspicious: 1, phishing: 0, quarantined: 1, daily: [] },
      '/api/messages?status=quarantine': [row],
      '/api/messages/synthetic-1': { ...row, classification: 'Phishing', signals: ['Synthetic explanation'] },
    },
  });
  await dashboard.navigate('#/quarantine?open=synthetic-1');
  assert.match(dashboard.element('#q-body').innerHTML, /Moderate score &middot; 69\.99/);
  assert.match(dashboard.element('#drawer').innerHTML, /<dt>Model prediction<\/dt><dd>Phishing<\/dd>/);
  assert.match(dashboard.element('#drawer').innerHTML, /Synthetic explanation/);
  assert.match(dashboard.calls.at(-1).url, /\/api\/messages\/synthetic-1$/);
});

test('renders a safe, expandable score explanation for each scanned message', async () => {
  const messages = Array.from({ length: 5 }, (_, index) => scoredMessage(index + 1));
  messages[0].subject += ' <subject>';
  const dashboard = await openDashboard({ messages });
  await dashboard.scan();
  const markup = dashboard.element('#main').innerHTML;
  const rows = markup.match(/<li class="item nocheck">[\s\S]*?(?=<li class="item nocheck">|$)/g);
  assert.equal(rows.length, 5);
  assert.match(markup, /Legitimate messages can be flagged/i);
  for (const [index, row] of rows.entries()) {
    assert.match(row, /<details[^>]*>\s*<summary>Why this score\?<\/summary>/);
    assert.match(row, new RegExp(`Synthetic reason ${index + 1} &lt;sample&gt;`));
    assert.match(row, new RegExp(`class="pill phishing">Prediction: Phishing · ${52 + index}/100`));
  }
  assert.match(rows[0], /Synthetic sample 1 &lt;subject&gt;/);
  assert.doesNotMatch(markup, /<subject>|<sample>/);
  await dashboard.navigate('#/overview');
  assert.match(dashboard.element('#main').innerHTML, /Predicted phishing/i);
});

test('keeps an explanation affordance for an unavailable result or an empty reason list', async () => {
  const available = { ...scoredMessage(1), reasons: [] };
  const unavailable = {
    ...scoredMessage(2), classification: 'Unavailable', risk_score: null,
    model_status: 'unreadable_message', reasons: ['Synthetic mail body unavailable.'],
  };
  const dashboard = await openDashboard({ messages: [available, unavailable] });
  await dashboard.scan();
  const markup = dashboard.element('#main').innerHTML;
  assert.match(markup, /Why this score\?/);
  assert.match(markup, /Why no score\?/);
  assert.match(markup, /V1 did not provide an explanation/);
  assert.match(markup, /Synthetic mail body unavailable\./);
  assert.match(markup, /Unavailable · No score/);
});

test('Gmail sign-out clears results and returns to sign-in even if demo login is still active', async () => {
  const dashboard = await openDashboard({ messages: [scoredMessage(1)], demoSignedIn: true });
  await dashboard.scan();
  await dashboard.signOut();
  assert.equal(dashboard.location.hash, '#/login');
  assert.deepEqual(dashboard.calls.at(-1), {
    url: '/gmail/disconnect', method: 'POST', csrf: 'synthetic-session-one',
  });
  await dashboard.navigate();
  assert.match(dashboard.element('#app').innerHTML, /Sign in with Google/);
  dashboard.session.connection = { connected: true, email: gmailEmail, csrf: 'synthetic-session-two' };
  await dashboard.navigate('#/mail');
  assert.doesNotMatch(dashboard.element('#main').innerHTML, /Synthetic reason/);
});

test('a 401 on scan returns to sign-in and asks the user to reconnect', async () => {
  const dashboard = await openDashboard({ messages: [scoredMessage(1)] });
  await dashboard.scan();
  dashboard.session.scanStatus = 401;
  await dashboard.scan();
  assert.equal(dashboard.location.hash, '#/login');
  await dashboard.navigate();
  assert.match(dashboard.element('#app').innerHTML, /Sign in with Google/);
  assert.doesNotMatch(dashboard.element('#app').innerHTML, /Synthetic sample/);
});

test('a new Gmail connection for the same address never inherits old scan results', async () => {
  const dashboard = await openDashboard({ messages: [scoredMessage(1)] });
  await dashboard.scan();
  assert.match(dashboard.element('#main').innerHTML, /Synthetic sample 1/);
  dashboard.session.connection = { connected: true, email: gmailEmail, csrf: 'synthetic-session-two' };
  await dashboard.navigate('#/overview');
  assert.doesNotMatch(dashboard.element('#main').innerHTML, /Synthetic sample/);
});

test('a scan that finishes while signing out cannot render mailbox results', async () => {
  const dashboard = await openDashboard({ messages: [scoredMessage(1)] });
  let finishScan;
  dashboard.session.scanDelay = new Promise(resolve => { finishScan = resolve; });
  const scanning = dashboard.scan();
  await dashboard.signOut();
  finishScan();
  await scanning;
  assert.doesNotMatch(dashboard.element('#main').innerHTML, /Synthetic sample/);
  await dashboard.navigate();
  assert.match(dashboard.element('#app').innerHTML, /Sign in with Google/);
});

test('a delayed local message detail cannot reopen the drawer on the sign-in page', async () => {
  const row = {
    id: 'delayed-message', subject: 'Synthetic delayed detail',
    from: { name: 'Synthetic Sender', email: 'sender@example.test' },
    receivedAt: '2026-11-22T00:00:00Z', score: 69.99, status: 'quarantine',
  };
  let finishDetail;
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': { total: 1, safe: 0, suspicious: 1, phishing: 0, quarantined: 1, daily: [] },
      '/api/messages?status=quarantine': [row],
      '/api/messages/delayed-message': new Promise(resolve => { finishDetail = resolve; }),
    },
  });
  await dashboard.navigate('#/quarantine?open=delayed-message');
  await dashboard.navigate('#/login');
  finishDetail({ ...row, body: 'Synthetic private body', classification: 'Phishing' });
  await new Promise(resolve => setImmediate(resolve));
  assert.match(dashboard.element('#app').innerHTML, /Sign in with Google/);
  assert.equal(dashboard.element('#drawer').classList.contains('open'), false);
  assert.doesNotMatch(dashboard.element('#drawer').innerHTML, /Synthetic private body/);
});

test('an old Overview response cannot change the current quarantine badge', async () => {
  let finishStats;
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': new Promise(resolve => { finishStats = resolve; }),
      '/api/messages?status=quarantine': [],
    },
  });
  await dashboard.navigate('#/quarantine');
  assert.equal(dashboard.element('#q-count').textContent, '');
  finishStats({ total: 3, safe: 0, suspicious: 0, phishing: 3, quarantined: 3, daily: [] });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(dashboard.element('#q-count').textContent, '');
  assert.match(dashboard.element('#q-body').innerHTML, /Quarantine is empty/);
});

test('leaving a local message removes its body from the closed drawer', async () => {
  const row = {
    id: 'shown-message', subject: 'Synthetic shown detail',
    from: { name: 'Synthetic Sender', email: 'sender@example.test' },
    receivedAt: '2026-11-22T00:00:00Z', score: 40.24, status: 'quarantine',
    body: 'Synthetic private body', classification: 'Safe',
  };
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': { total: 1, safe: 0, suspicious: 1, phishing: 0, quarantined: 1, daily: [] },
      '/api/messages?status=quarantine': [row],
      '/api/messages/shown-message': row,
    },
  });
  await dashboard.navigate('#/quarantine?open=shown-message');
  assert.match(dashboard.element('#drawer').innerHTML, /Synthetic private body/);
  await dashboard.navigate('#/login');
  assert.equal(dashboard.element('#drawer').classList.contains('open'), false);
  assert.doesNotMatch(dashboard.element('#drawer').innerHTML, /Synthetic private body/);
});

test('mock quarantine and restore preserve the existing scores', async () => {
  const { mock } = await openDashboard();
  const low = await mock.getMessage('m3');
  const high = await mock.getMessage('m1');
  const quarantined = await mock.quarantine(low.id);
  const restored = await mock.restore(high.id);
  assert.equal(quarantined.status, 'quarantine');
  assert.equal(quarantined.score, low.score);
  assert.equal(restored.status, 'inbox');
  assert.equal(restored.score, high.score);
});

test('unscored stored messages have a separate Overview category and daily segment', async () => {
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': {
        total: 4, safe: 1, suspicious: 1, phishing: 1, unscored: 1, quarantined: 0,
        daily: [{ date: '2026-11-22', safe: 2, phishing: 1, unscored: 1 }],
      },
      '/api/messages?status=quarantine': [],
    },
  });
  const markup = dashboard.element('#main').innerHTML;
  assert.match(markup, /No score/);
  assert.match(markup, /25% of stored messages/);
  assert.match(markup, /2 below 70, 1 at 70 or above, 1 without a score/);
  assert.match(markup, /class="seg-unscored"/);
  assert.match(markup, /Breakdown of 4 emails/);
});

test('No score filtering keeps missing analysis separate from a genuine zero and sorts it last', async () => {
  const rows = [
    { id: 'missing', subject: 'Missing analysis', score: null },
    { id: 'zero', subject: 'Actual zero', score: 0 },
    { id: 'high', subject: 'High score sample', score: 85.92 },
  ].map(row => ({
    ...row, from: { name: 'Synthetic Sender', email: 'sender@example.test' },
    receivedAt: '2026-11-22T00:00:00Z', status: 'inbox', preview: 'Synthetic text',
  }));
  const dashboard = await openDashboard({
    demoSignedIn: true, initialHash: '#/mail',
    demoData: {
      '/api/messages?status=inbox': rows,
      '/api/messages?status=quarantine': [],
    },
  });
  const selectFilter = filter => dashboard.element('#main').querySelectorAll('.chip')
    .find(chip => chip.dataset.f === filter).onclick();
  selectFilter('safe');
  assert.match(dashboard.element('#mail-list').innerHTML, /Actual zero/);
  assert.doesNotMatch(dashboard.element('#mail-list').innerHTML, /Missing analysis/);
  selectFilter('unscored');
  assert.match(dashboard.element('#mail-list').innerHTML, /Missing analysis/);
  assert.doesNotMatch(dashboard.element('#mail-list').innerHTML, /Actual zero/);
  selectFilter('all');
  dashboard.element('#sort').onchange({ target: { value: 'score' } });
  const order = [...dashboard.element('#mail-list').innerHTML.matchAll(/data-id="([^"]+)"/g)]
    .map(match => match[1]);
  assert.deepEqual(order, ['high', 'zero', 'missing']);
});

for (const action of ['restore', 'delete']) {
  test(`partial bulk ${action} removes successful rows and keeps failed rows available to retry`, async () => {
    const rows = ['succeeds', 'fails'].map(id => ({
      id, subject: `Synthetic ${id}`, score: 40.24, status: 'quarantine',
      from: { name: 'Synthetic Sender', email: 'sender@example.test' },
      receivedAt: '2026-11-22T00:00:00Z',
    }));
    const resource = id => '/api/messages/' + id + (action === 'restore' ? '/restore' : '');
    const dashboard = await openDashboard({
      demoSignedIn: true, initialHash: '#/quarantine',
      demoData: {
        '/api/messages?status=quarantine': rows,
        [resource('succeeds')]: ({ method }) => {
          assert.equal(method, action === 'restore' ? 'POST' : 'DELETE');
          return { status: 200, body: {} };
        },
        [resource('fails')]: () => ({ status: 503, body: { message: 'Synthetic service failure' } }),
      },
    });
    dashboard.element('#sel-all').onchange({ target: { checked: true } });
    const changing = dashboard.element('#bulk-' + action).onclick();
    dashboard.element('#confirm-yes').onclick();
    await changing;
    const markup = dashboard.element('#q-body').innerHTML;
    assert.doesNotMatch(markup, /data-id="succeeds"/);
    assert.match(markup, /data-id="fails"/);
    assert.match(markup, /1 selected/);
    assert.equal(dashboard.element('#q-count').textContent, 1);
  });
}

test('a stale local 401 cannot clear a newer demo session', async () => {
  let finishOldRequest;
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': () => new Promise(resolve => { finishOldRequest = resolve; }),
      '/api/messages?status=quarantine': [],
    },
  });
  dashboard.localSession.set({ token: 'synthetic-new-session', user: { email: 'new@example.test' } });
  await dashboard.navigate('#/login');
  finishOldRequest({ status: 401, body: { message: 'Old session expired' } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(dashboard.localSession.get()?.token, 'synthetic-new-session');
});

test('a delayed local sign-out cannot clear a session established after it started', async () => {
  let finishLogout;
  const dashboard = await openDashboard({
    demoSignedIn: true,
    demoData: {
      '/api/stats': { total: 0, safe: 0, suspicious: 0, phishing: 0, quarantined: 0, daily: [] },
      '/api/messages?status=quarantine': [],
      '/api/auth/logout': ({ method }) => {
        assert.equal(method, 'POST');
        return new Promise(resolve => { finishLogout = resolve; });
      },
    },
  });
  const signingOut = dashboard.signOut();
  dashboard.localSession.set({ token: 'synthetic-new-session', user: { email: 'new@example.test' } });
  await dashboard.navigate('#/login');
  finishLogout({ status: 200, body: {} });
  await signingOut;
  assert.equal(dashboard.localSession.get()?.token, 'synthetic-new-session');
});
