// Launching a headless Chrome for a browser gate, without the gates fighting
// each other for a port.
//
// Every driver used to take a fixed CDP port from the environment, and pytest
// runs them parametrized: three lead_invariant cases on 9612, ten flow_fits
// cases on 9613. `chrome.kill()` returns as soon as the signal is sent, so the
// next case could spawn while the previous Chrome still held the port. The new
// Chrome then failed to bind, /json/list answered from the OLD one on its way
// out, and the first Runtime.evaluate came back undefined - surfacing as
// "Cannot read properties of undefined (reading 'left')" from deep inside a
// probe, which looks like a product bug and is not one.
//
// So nobody picks a port. Chrome picks its own (--remote-debugging-port=0) and
// writes it into DevToolsActivePort inside a private user-data-dir, which also
// stops two instances sharing a profile. The port is read back from the file
// that the process we started wrote, so it cannot be another run's.
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function launch(chromePath, extraArgs = []) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-chrome-'));
  const chrome = spawn(chromePath, [
    '--headless', '--no-sandbox', '--disable-gpu',
    '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    ...extraArgs, 'about:blank',
  ], { stdio: 'ignore' });
  chrome._profile = profile;

  const portFile = path.join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 200; i++) {
    if (chrome.exitCode !== null) {
      throw new Error(`chrome exited with ${chrome.exitCode} before opening a debug port`);
    }
    if (fs.existsSync(portFile)) {
      const port = Number(fs.readFileSync(portFile, 'utf8').split('\n')[0]);
      if (port > 0) return { chrome, port };
    }
    await sleep(50);
  }
  throw new Error('chrome never wrote DevToolsActivePort');
}

// Wait for the process to actually be gone. Returning while it is still
// shutting down is what let the next case connect to a dying target.
async function close(chrome) {
  if (!chrome || chrome.exitCode !== null) return;
  const ended = new Promise((r) => chrome.once('exit', r));
  chrome.kill();
  await Promise.race([ended, sleep(5000)]);
  if (chrome.exitCode === null) chrome.kill('SIGKILL');
  try { fs.rmSync(chrome._profile, { recursive: true, force: true }); } catch {}
}

module.exports = { launch, close, sleep };
