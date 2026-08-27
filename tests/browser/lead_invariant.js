// UI Gate item 4, mechanically: the wire panel must never show an outcome the
// story has not reached.
//
// The first version of this compared step TAGS - max tag on the right against
// steps drawn on the left - and a mutation proved it worthless: the run
// response is tagged 3 because step 3's verdict reads it first, so flushing it
// immediately still satisfied "3 <= 3" while the panel visibly displayed
// done-paid two steps early. The tag says where the data is used; it says
// nothing about what is legible in the panel.
//
// So the check reads the panel's TEXT instead:
//
//     done-paid visible  =>  step 4 drawn
//     done-free visible  =>  step 5 drawn
//
// sampled while the story runs, because frames are what a viewer and a camera
// see - a panel that ends up correct can still have shown the ending early.
//
// Run: node tests/browser/lead_invariant.js <base-url> <token> go|go2 [reject|approve]
// Prints one JSON object. Exit 1 if the panel ever ran ahead.
const WebSocket = require(process.env.WS_MODULE);
const { spawn } = require('child_process');

const [URL_BASE, TOKEN, BUTTON, DECIDE] = process.argv.slice(2);
const CHROME = process.env.CHROME_PATH;
const PORT = Number(process.env.CDP_PORT || 9612);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn(CHROME, ['--headless', '--no-sandbox', '--disable-gpu',
  `--remote-debugging-port=${PORT}`, '--window-size=1440,1700', 'about:blank'], { stdio: 'ignore' });

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

  await send(ws, 'Page.navigate', { url: `${URL_BASE}/login` });
  await sleep(2500);
  await ev(ws, `document.querySelector('input[name=token]').value = ${JSON.stringify(TOKEN)};
                document.querySelector('form').submit();`);
  await sleep(3500);

  const probe = `(() => {
    const panel = document.getElementById('wirelog').textContent;
    return {
      // the highest node drawn, not how many: the rejected path skips node 4,
      // so counting cards called the story a step behind where it really was
      left: Math.max(0, ...[...document.querySelectorAll('.step')]
              .map(n => Number(n.dataset.n)).filter(Number.isFinite)),
      paid: panel.includes('done-paid'),
      free: panel.includes('done-free'),
      tag: Math.max(0, ...[...document.querySelectorAll('.w-step')]
             .map(n => parseInt(n.textContent, 10)).filter(Number.isFinite)),
    };
  })()`;

  await ev(ws, `document.getElementById('${BUTTON}').click()`);
  const ahead = [];
  const transitions = [];
  let decided = false;
  for (let i = 0; i < 80; i++) {
    const frame = await ev(ws, probe);
    const key = `${frame.left}<-${frame.tag}${frame.paid ? '+paid' : ''}${frame.free ? '+free' : ''}`;
    if (transitions[transitions.length - 1] !== key) transitions.push(key);
    // The outcome is legible in the panel before the step that announces it.
    if ((frame.paid && frame.left < 4) || (frame.free && frame.left < 5))
      ahead.push({ frame: i, ...frame });
    if (DECIDE && !decided && await ev(ws, `!!document.querySelector('.${DECIDE}')`)) {
      decided = true;
      await ev(ws, `document.querySelector('.${DECIDE}').click()`);
    }
    await sleep(200);
  }

  console.log(JSON.stringify({ transitions, ahead, reachedEnd: String(transitions.at(-1)).startsWith('5<-') }));
  chrome.kill();
  process.exit(ahead.length ? 1 : 0);
})().catch((e) => { console.error('driver failed:', e.message); chrome.kill(); process.exit(2); });
