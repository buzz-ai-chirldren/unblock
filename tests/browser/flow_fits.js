// UI Gate item 6, mechanically: on a desktop viewport the whole chain must be
// on screen, not merely reachable by scrolling.
//
// The five-node chain measures 871px. At max-width:1180px the left column was
// 816px, so the moment the last node landed the row auto-scrolled and sheared
// ~55px off the first node - the finished state, the one a screenshot or a
// video ends on, no longer showed what the agent had started from. Every
// assertion in the suite passed while that was true; it took measuring the
// element to see it.
//
// So this samples scrollWidth against clientWidth THROUGHOUT the run, not just
// at the end: the widest moment is not always the last one.
//
// Run: node tests/browser/flow_fits.js <base-url> <token> <width> go|go2 [reject|approve]
// LANG_CHOICE=en|ja picks the copy under test: the labels differ in width, so
// measuring one language says nothing about the other.
// Prints one JSON object. Exit 1 if the flow ever overflowed its column.
const WebSocket = require(process.env.WS_MODULE);
const { spawn } = require('child_process');

const [URL_BASE, TOKEN, WIDTH, BUTTON, DECIDE] = process.argv.slice(2);
const CHROME = process.env.CHROME_PATH;
const PORT = Number(process.env.CDP_PORT || 9614);
const LANG = process.env.LANG_CHOICE || '';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn(CHROME, ['--headless', '--no-sandbox', '--disable-gpu',
  `--remote-debugging-port=${PORT}`, `--window-size=${WIDTH},1000`, 'about:blank'], { stdio: 'ignore' });

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
  await sleep(2500);
  const targets = await fetch(`http://127.0.0.1:${PORT}/json/list`).then((r) => r.json());
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
  await send(ws, 'Emulation.setDeviceMetricsOverride',
    { width: Number(WIDTH), height: 1000, deviceScaleFactor: 1, mobile: false });

  await send(ws, 'Page.navigate', { url: `${URL_BASE}/login` });
  await sleep(2500);
  await ev(ws, `document.querySelector('input[name=token]').value = ${JSON.stringify(TOKEN)};
                document.querySelector('form').submit();`);
  await sleep(3500);

  if (LANG) {
    await ev(ws, `localStorage.setItem('lang', ${JSON.stringify(LANG)})`);
    await send(ws, 'Page.navigate', { url: URL_BASE });
    await sleep(2500);
  }

  const probe = `(() => {
    const flow = document.querySelector('.flow');
    if (!flow) return null;
    const first = document.querySelector('.step[data-n="1"] .node');
    const box = first && first.getBoundingClientRect();
    const col = flow.getBoundingClientRect();
    const kids = flow.children;
    // scrollWidth clamps to clientWidth once the content fits, so it cannot
    // report headroom. Measure the row itself to see how close it is.
    const row = kids.length
      ? Math.round(kids[kids.length - 1].getBoundingClientRect().right
                   - kids[0].getBoundingClientRect().left)
      : 0;
    return {
      steps: document.querySelectorAll('.step').length,
      rowWidth: row, headroom: flow.clientWidth - row,
      scrollWidth: flow.scrollWidth, clientWidth: flow.clientWidth,
      scrollLeft: Math.round(flow.scrollLeft),
      // the symptom a viewer actually sees: node 1 sheared by the left edge
      firstClipped: box ? Math.round(Math.max(0, col.left - box.left)) : 0,
    };
  })()`;

  await ev(ws, `document.getElementById('${BUTTON}').click()`);
  const overflow = [];
  let widest = 0, decided = false;
  for (let i = 0; i < 80; i++) {
    const f = await ev(ws, probe);
    if (f) {
      widest = Math.max(widest, f.rowWidth);
      if (f.scrollWidth > f.clientWidth || f.firstClipped > 0) overflow.push({ frame: i, ...f });
    }
    if (DECIDE && !decided && await ev(ws, `!!document.querySelector('.${DECIDE}')`)) {
      decided = true;
      await ev(ws, `document.querySelector('.${DECIDE}').click()`);
    }
    await sleep(200);
  }
  const final = await ev(ws, probe);
  console.log(JSON.stringify({ width: Number(WIDTH), lang: LANG || 'default',
                              decide: DECIDE || 'none', widestRow: widest,
                              headroom: final ? final.clientWidth - widest : null, final, overflow }));
  chrome.kill();
  process.exit(overflow.length ? 1 : 0);
})().catch((e) => { console.error('driver failed:', e.message); chrome.kill(); process.exit(2); });
