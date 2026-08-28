// Drives the real page and breaks it on purpose at the one moment something
// is actually being held: step 5 defers /api/site, so failing the /api/pr that
// follows leaves the site response in the queue. It must be discarded, never
// flushed into the panel.
//
// (Failing earlier proves nothing: by then the run response has already been
// flushed on purpose, at the verdict it produced.)
//
// Run: node tests/browser/error_cleanup.js <base-url> <token>
// Prints one JSON object. Exits non-zero if the page cannot be driven.
const WebSocket = require(process.env.WS_MODULE);
const { launch, close } = require('./chrome.js');

const [URL_BASE, TOKEN] = process.argv.slice(2);
const CHROME = process.env.CHROME_PATH;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let id = 0;
const pending = new Map();
const send = (ws, method, params = {}) => {
  const i = ++id;
  ws.send(JSON.stringify({ id: i, method, params }));
  return new Promise((res, rej) => pending.set(i, { res, rej }));
};
const ev = (ws, expression) =>
  send(ws, 'Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
    .then((r) => r.result?.value);

(async () => {
  const { chrome, port } = await launch(CHROME, ['--window-size=1400,1200']);
  const targets = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json());
  const ws = new WebSocket(targets[0].webSocketDebuggerUrl, { maxPayload: 64 * 1024 * 1024 });
  await new Promise((r) => ws.on('open', r));
  ws.on('message', (raw) => {
    const msg = JSON.parse(raw);
    if (msg.id && pending.has(msg.id)) {
      const { res, rej } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? rej(new Error(JSON.stringify(msg.error))) : res(msg.result);
    }
  });
  await send(ws, 'Runtime.enable');
  await send(ws, 'Page.enable');

  await send(ws, 'Page.navigate', { url: `${URL_BASE}/login` });
  await sleep(2500);
  await ev(ws, `document.querySelector('input[name=token]').value = ${JSON.stringify(TOKEN)};
                document.querySelector('form').submit();`);
  await sleep(3500);

  // Fail the first request made after the run response has been held.
  await ev(ws, `const real = window.fetch;
    window.fetch = async (...a) => {
      if (String(a[0]).includes('/api/pr')) throw new Error('injected failure');
      return real(...a);
    };`);

  await ev(ws, `document.getElementById('go').click()`);
  await sleep(9000);

  console.log(JSON.stringify(await ev(ws, `({
    held: HELD.length,
    wirePaths: [...document.querySelectorAll('.w-entry .w-path')].map(n => n.textContent),
    steps: document.querySelectorAll('.step').length,
    errorShown: document.body.textContent.includes('injected failure'),
    buttonsEnabled: !document.getElementById('go').disabled && !document.getElementById('go2').disabled,
  })`)));
  await close(chrome);
  process.exit(0);
})().catch((e) => { console.error('driver failed:', e.message); process.exit(2); });
