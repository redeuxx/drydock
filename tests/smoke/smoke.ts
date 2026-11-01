// CSP SMOKE TEST
//
// Drives headless Chromium through every page of a fresh drydock and fails on any
// securitypolicyviolation event, uncaught page error, or htmx/CSP console error.
// It also checks that htmx 4 and the hx-csp extension are live, that the htmx plumbing
// behaves as the templates assume (inherited CSRF header, 4xx swaps into #main,
// HX-Redirect, redirect to /login on 401), that PID 1 is uvicorn, and that rclone runs
// with nothing secret on its command line and no TCP listener.
//
// Run through compose.test.yaml; see the comment at the top of that file.
import { readdirSync, readFileSync } from "node:fs";
import { chromium, type Page, type Request } from "playwright";

const BASE = process.env.SMOKE_BASE_URL ?? "http://localhost:8000";
const USERNAME = "smoke-admin";
const PASSWORD = "smoke test password 1";
const PAGES = [
  "/",
  "/account",
  "/account/password",
  "/users",
  "/users/new",
  "/audit",
  "/hosts",
  "/hosts/new?kind=ssh",
  "/hosts/new?kind=local",
  "/storage",
  "/storage/new",
  "/storage/new?type=sftp",
  "/storage/new?type=smb",
  "/storage/new?type=webdav",
  "/storage/new?type=drive",
  "/notifications",
  "/notifications/new",
  "/jobs",
  "/jobs/new",
  "/hooks",
  "/hooks/new",
  "/runs",
  "/backups",
  "/restore",
  "/reauth",
  "/does-not-exist",
];

const failures: string[] = [];
const violations: string[] = [];
const expectedConsole: RegExp[] = [];

function check(condition: unknown, message: string): void {
  if (!condition) {
    failures.push(message);
    console.error(`FAIL ${message}`);
  } else {
    console.log(`ok   ${message}`);
  }
}

function path(page: Page): string {
  return new URL(page.url()).pathname;
}

// PID 1

if (process.env.SMOKE_CHECK_PID1 === "1") {
  const argv = readFileSync("/proc/1/cmdline", "utf8").split("\0").filter(Boolean);
  // Exec-form CMD: the kernel runs the uvicorn script through its python shebang.
  const uvicornIndex = argv.findIndex((arg) => arg.split("/").pop() === "uvicorn");
  check(
    uvicornIndex >= 0 && uvicornIndex <= 1 && argv.includes("drydock.main:app"),
    `PID 1 is uvicorn (${argv.join(" ")})`,
  );
}

// RCLONE

// SMOKE_CHECK_PID1 also means the smoke container shares the app's network namespace.
const RCLONE_ARGV =
  "/opt/rclone/rclone rcd --rc-addr unix:///run/drydock/rclone.sock --rc-serve --config /dev/null --log-level INFO";

function rclonePids(): Map<string, string> {
  const found = new Map<string, string>();
  for (const pid of readdirSync("/proc").filter((name) => /^\d+$/.test(name))) {
    try {
      const argv = readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean);
      if (argv[0] === "/opt/rclone/rclone") {
        found.set(pid, argv.join(" "));
      }
    } catch {
      // the process exited while listing
    }
  }
  return found;
}

const rcloneAtStart = process.env.SMOKE_CHECK_PID1 === "1" ? rclonePids() : new Map();
if (process.env.SMOKE_CHECK_PID1 === "1") {
  const commands = [...rcloneAtStart.values()];
  check(
    commands.length === 1 && commands[0] === RCLONE_ARGV,
    `one rclone rcd, nothing secret on its command line (${commands.join("; ")})`,
  );
  // Only uvicorn may listen on TCP. 127.0.0.11 is Docker's embedded DNS resolver.
  const ports = new Set<number>();
  for (const name of ["tcp", "tcp6"]) {
    for (const line of readFileSync(`/proc/net/${name}`, "utf8").trim().split("\n").slice(1)) {
      const [, local = "", , state] = line.trim().split(/\s+/);
      const port = local.split(":")[1];
      if (state === "0A" && !local.startsWith("0B00007F:") && port !== undefined) {
        ports.add(Number.parseInt(port, 16));
      }
    }
  }
  check([...ports].join() === "8000", `only port 8000 listens on TCP (${[...ports].join(", ")})`);
}

// STATIC ASSETS

const css = await fetch(`${BASE}/static/css/app.css`);
const cssText = await css.text();
check(css.status === 200, "compiled stylesheet is served");
check(css.headers.get("content-type")?.startsWith("text/css"), "stylesheet has a CSS type");
check(
  cssText.includes("--color-base-100") && cssText.includes(".btn") && cssText.length > 10_000,
  "stylesheet contains the daisyUI themes and components",
);
check(!/url\(\s*["']?data:/i.test(cssText), "stylesheet has no data: URLs");
check(css.headers.get("cache-control") === "no-cache", "static assets are revalidated");
const htmxSource = await (await fetch(`${BASE}/static/vendor/htmx/htmx.min.js`)).text();
check(htmxSource.includes("4.0.0"), "vendored htmx is 4.0.0");

// BROWSER

const browser = await chromium.launch();
const context = await browser.newContext({ baseURL: BASE });
await context.exposeBinding("__reportViolation", (_source, detail: string) => {
  violations.push(detail);
});
await context.addInitScript(() => {
  document.addEventListener("securitypolicyviolation", (event) => {
    const report = (window as unknown as { __reportViolation: (d: string) => void })
      .__reportViolation;
    report(
      `${location.pathname}: ${event.effectiveDirective} blocked ${event.blockedURI || "inline"}` +
        ` at ${event.sourceFile}:${event.lineNumber} ${event.sample}`,
    );
  });
});

const page = await context.newPage();
page.on("pageerror", (error) => failures.push(`page error on ${path(page)}: ${error.message}`));
page.on("console", (message) => {
  const text = message.text();
  if (message.type() !== "error" || expectedConsole.some((pattern) => pattern.test(text))) {
    return;
  }
  // Chromium logs every 4xx fetch; those are expected here. Anything about htmx,
  // CSP or Trusted Types is not.
  if (/htmx|content security policy|trusted type|refused/i.test(text)) {
    failures.push(`console error on ${path(page)}: ${text}`);
  }
});
page.on("dialog", (dialog) => void dialog.accept());

const htmxPosts: Request[] = [];
page.on("request", (request) => {
  if (request.method() === "POST" && request.headers()["hx-request"] === "true") {
    htmxPosts.push(request);
  }
});

async function login(): Promise<void> {
  await page.goto("/login");
  await page.fill("#login-username", USERNAME);
  await page.fill("#login-password", PASSWORD);
  await Promise.all([page.waitForURL(`${BASE}/`), page.click("button[type=submit]")]);
}

async function expectMainAlert(text: string, stayOn: string, label: string): Promise<void> {
  const alert = page.locator("#main [role=alert]");
  await alert.waitFor({ timeout: 5000 });
  check((await alert.innerText()).includes(text) && path(page) === stayOn, label);
  const focused = await page
    .waitForFunction(() => document.activeElement?.matches("#main [role=alert]"), null, {
      timeout: 2000,
    })
    .then(() => true)
    .catch(() => false);
  check(focused, `${label}: focus moves to the error alert`);
}

// SETUP WITH A PLAIN FORM AND THE PRE-SESSION CSRF TOKEN

await page.goto("/");
check(path(page) === "/setup", "a fresh install redirects to /setup");
await page.fill("#setup-username", USERNAME);
await page.fill("#setup-password", PASSWORD);
await page.fill("#setup-password-confirm", PASSWORD);
await Promise.all([page.waitForURL(`${BASE}/`), page.click("button[type=submit]")]);
check(path(page) === "/", "setup signs the superadmin in");

// CANARY: THE VIOLATION DETECTOR WORKS

const canaryConsole = /inline style/i;
expectedConsole.push(canaryConsole);
const canaryLogged = page.waitForEvent("console", {
  predicate: (message) => canaryConsole.test(message.text()),
  timeout: 5000,
});
await page.evaluate(() => document.body.setAttribute("style", "outline: 1px solid red"));
await canaryLogged;
await page.waitForTimeout(300);
check(
  violations.length === 1 && violations[0]?.includes("style-src"),
  "the detector reports a deliberate inline style violation",
);
violations.length = 0;
expectedConsole.pop();

// HTMX AND STYLES ARE LIVE

const state = await page.evaluate(() => {
  const w = window as unknown as { htmx?: { version: string; config: Record<string, unknown> } };
  const button = document.querySelector("header button[type=submit]");
  return {
    version: w.htmx?.version,
    extensions: w.htmx?.config.extensions,
    adopted: document.adoptedStyleSheets.length,
    sheets: [...document.styleSheets].map((sheet) => sheet.href),
    rules: document.styleSheets[0]?.cssRules.length ?? 0,
    buttonPadding: button ? getComputedStyle(button).paddingLeft : "",
  };
});
check(state.version === "4.0.0", `htmx 4 is running (version ${state.version})`);
check(state.extensions === "hx-csp", "htmx extension allowlist is hx-csp only");
check(state.adopted === 0, "htmx injected no constructed stylesheet");
check(
  state.sheets.length === 1 && state.sheets[0] === `${BASE}/static/css/app.css`,
  `the only stylesheet is /static/css/app.css (${state.sheets.join(", ")})`,
);
check(state.rules > 0 && state.buttonPadding !== "0px", "daisyUI styles are applied");

// EVERY PAGE

for (const target of PAGES) {
  const response = await page.goto(target);
  await page.waitForLoadState("networkidle");
  const status = response?.status() ?? 0;
  const expected = target === "/does-not-exist" ? 404 : 200;
  check(status === expected, `GET ${target} renders (${status})`);
}

// 422 SWAPS INTO MAIN AND THE CSRF HEADER IS INHERITED

await page.goto("/users/new");
const token = await page.inputValue("input[name=csrf_token]");
await page.fill("#new-username", "has space");
await page.fill("#new-user-password", PASSWORD);
await page.click("main button[type=submit]");
await expectMainAlert("Username must be", "/users/new", "a 422 response swaps its #main in place");
const sent = htmxPosts.at(-1)?.headers()["x-csrf-token"];
check(sent !== undefined && sent === token, "htmx POSTs carry the inherited X-CSRF-Token");

// HX-REDIRECT AFTER SUCCESS

await page.fill("#new-username", "smoke-operator");
await page.fill("#new-user-password", PASSWORD);
await page.selectOption("#new-user-role", "operator");
await Promise.all([page.waitForURL(/\/users\/\d+$/), page.click("main button[type=submit]")]);
const operatorPath = path(page);
check(/^\/users\/\d+$/.test(operatorPath), "HX-Redirect navigates to the new user");

// 409 SWAPS INTO MAIN

await page.goto("/users/1");
await page.selectOption("#edit-role", "viewer");
await page.click("form[action='/users/1/role'] button[type=submit]");
await expectMainAlert("last active superadmin", "/users/1", "a 409 response swaps its #main");

// HOSTS: A LOCAL HOST THROUGH THE SOCKET PROXY

await page.goto("/hosts/new?kind=local");
check(
  (await page.inputValue("#new-docker-url")) === "tcp://socket-proxy:2375",
  "the local host form suggests the socket proxy",
);
await page.fill("#new-name", "local");
await Promise.all([page.waitForURL(/\/hosts\/\d+$/), page.click("main button[type=submit]")]);
const localPath = path(page);
check(/^\/hosts\/\d+$/.test(localPath), "HX-Redirect navigates to the new host");

// The placeholder loads the inventory fragment with hx-get and swaps only #inventory.
await page.locator("#inventory table").first().waitFor({ timeout: 15000 });
check(
  (await page.locator("#main").count()) === 1 &&
    (await page.locator("#inventory").count()) === 1 &&
    (await page.locator("#inventory").innerText()).includes("drydock-test"),
  "the inventory fragment swaps into the host page and lists the compose project",
);
check(
  (await page.title()).startsWith("Host local ") &&
    (await page.getAttribute("#inventory-region", "aria-busy")) === "false",
  "the inventory swap keeps the page title and clears aria-busy",
);

await page.click("form[action$='/test'] button[type=submit]");
const tested = await page
  .locator("#main [role=status]", { hasText: "negotiated" })
  .waitFor({ timeout: 15000 })
  .then(() => true)
  .catch(() => false);
check(tested && path(page) === localPath, "the connection test result swaps into the host page");
const resultFocused = await page
  .waitForFunction(() => document.activeElement?.matches("#main [data-focus-result]"), null, {
    timeout: 2000,
  })
  .then(() => true)
  .catch(() => false);
check(resultFocused, "focus moves to the connection test result");
// The new #main loads the inventory again; that swap must not move focus.
await page.locator("#inventory table").first().waitFor({ timeout: 15000 });
check(
  await page.evaluate(() => document.activeElement?.matches("#main [data-focus-result]") ?? false),
  "the inventory loading leaves focus on the result",
);

const inventoryPage = await page.goto(`${localPath}/containers`);
await page.waitForLoadState("networkidle");
check(inventoryPage?.status() === 200, `GET ${localPath}/containers renders`);

// STORAGE, A JOB AND A RUN WITH ITS LIVE LOG

await page.goto("/storage/new");
check((await page.inputValue("#new-path")) === "/backups", "the storage form suggests the allowed root");
await page.fill("#new-name", "local");
await Promise.all([page.waitForURL(/\/storage\/\d+$/), page.click("main button[type=submit]")]);
await page.click("form[action$='/test'] button[type=submit]");
const storageTested = await page
  .locator("#main [role=status]", { hasText: "writable" })
  .waitFor({ timeout: 10000 })
  .then(() => true)
  .catch(() => false);
check(storageTested, "the storage write test result swaps into the page");

// The SFTP form fetches the server's host key into its own field. Nothing listens on port
// 9, so the error swaps in, and the password typed before stays.
await page.goto("/storage/new?type=sftp");
await page.fill("#new-host", "127.0.0.1");
await page.fill("#new-port", "9");
await page.fill("#new-pass", "typed-before-fetching");
await page.click("#new-host_keys-field button");
const fetchFailed = await page
  .locator("#new-host_keys-field [role=alert]", { hasText: "host key" })
  .waitFor({ timeout: 20000 })
  .then(() => true)
  .catch(() => false);
check(fetchFailed, "a failed host key fetch swaps into its field");
check(
  (await page.inputValue("#new-pass")) === "typed-before-fetching",
  "fetching the host key keeps the rest of the form",
);

await page.goto("/jobs/new");
await page.fill("#new-name", "smoke job");
await page.selectOption("#new-host", { label: "local" });
await page.selectOption("#new-target-type", "container");
await page.fill("#new-target", "drydock-test-smoke-target-1");
await page.selectOption("#new-storage", { label: "local" });
await page.selectOption("#new-scope", "data");
await page.selectOption("#new-mode", "stop");
check(await page.isChecked("input[name=encrypted]"), "new jobs encrypt by default");
// The schedule preview loads #cron-preview with hx-get as the cron and time zone change.
async function previewShows(text: string): Promise<boolean> {
  return page
    .locator("#new-cron-preview", { hasText: text })
    .waitFor({ timeout: 10000 })
    .then(() => true)
    .catch(() => false);
}
check(await previewShows("Next runs"), "a new job's nightly schedule preview loads with the form");
check(!(await page.isVisible("#new-cron")), "the cron field stays hidden for a preset");
await page.selectOption("#new-timezone", "America/New_York");
await page.selectOption("#new-cron-preset", "0 3 * * 0");
check(await previewShows("Sun "), "the preview follows the weekly preset");
check(
  (await page.getAttribute("#new-cron-preview", "aria-busy")) === "false" &&
    (await page.title()).startsWith("Add job"),
  "the preview swap keeps the page title and clears aria-busy",
);
await page.selectOption("#new-cron-preset", "custom");
check(
  (await page.isVisible("#new-cron")) && (await page.inputValue("#new-cron")) === "0 3 * * 0",
  "Custom shows the cron field, filled from the preset",
);
await page.fill("#new-cron", "0 3 1 * 1");
check(await previewShows("not both"), "the preview explains a refused expression");
await page.selectOption("#new-cron-preset", "manual");
check(await previewShows("started by hand"), "the preview says a manual job has no schedule");
await page.selectOption("#new-timezone", "");
// Enter in a field saves (the form's hidden default button), not "Add another".
await Promise.all([page.waitForURL(/\/jobs\/\d+$/), page.press("#new-name", "Enter")]);
const jobPath = path(page);
check(/^\/jobs\/\d+$/.test(jobPath), "HX-Redirect navigates to the new job");

// A poll answers 200 with new lines, 204 with nothing new (no swap), or 204 with
// HX-Refresh once the run has ended.
const logPolls = { lines: 0, empty: 0 };
page.on("response", (response) => {
  if (!/\/runs\/\d+\/log\?offset=\d+$/.test(response.url())) {
    return;
  }
  if (response.status() === 200) {
    logPolls.lines += 1;
  } else if (response.status() === 204 && !response.headers()["hx-refresh"]) {
    logPolls.empty += 1;
  }
});
await Promise.all([
  page.waitForURL(/\/runs\/\d+$/),
  page.click(`form[action='${jobPath}/run'] button[type=submit]`),
]);
const runPath = path(page);
check((await page.locator("#log-poller").count()) === 1, "an active run's page polls its log");
check((await page.locator("#run-log[role=log]").count()) === 1, "the run log is a live region");
// While the run is active the poller appends lines; when it ends, HX-Refresh reloads the page.
const finished = await page
  .locator("#main .badge", { hasText: /^done$/ })
  .waitFor({ timeout: 120000 })
  .then(() => true)
  .catch(() => false);
check(finished && path(page) === runPath, "the run finishes and its page reloads to show it");
check(
  logPolls.lines + logPolls.empty > 0,
  `the poller polled while the run was active (${logPolls.lines} with new lines, ${logPolls.empty} without)`,
);
const runLog = await page.locator("#run-log").innerText();
check(runLog.includes("Backup of drydock-test-smoke-target-1") && runLog.includes("Run done."), "the run log is shown");
check((await page.locator("#log-poller").count()) === 0, "a finished run has no poller");
check((await page.title()).includes("(done)"), "the reloaded page's title announces the outcome");

await page.goto("/backups");
check(
  (await page.locator("main table", { hasText: "drydock-smoke-job-" }).count()) === 1 &&
    (await page.locator("main .badge", { hasText: /^encrypted$/ }).count()) >= 1,
  "the backup is catalogued as encrypted",
);

await page.goto(jobPath);
check(
  !(await page.content()).includes("Treat this like the secret key") &&
    (await page.locator(`a[href='${jobPath}/edit']`).count()) === 1 &&
    (await page.locator("form[action$='/passphrase']").count()) === 0,
  "the job page shows the summary and an Edit link, never the passphrase",
);
const editPath = `${jobPath}/edit`;
await page.goto(editPath);
await page.click(`form[action='${jobPath}/passphrase'] button[type=submit]`);
await page.locator("#main [role=status], #main #reauth-password").first().waitFor({ timeout: 5000 });
if ((await page.locator("#reauth-password").count()) > 0) {
  await page.fill("#reauth-password", PASSWORD);
  await Promise.all([page.waitForEvent("load"), page.click("main button[type=submit]")]);
  await page.click(`form[action='${jobPath}/passphrase'] button[type=submit]`);
}
const revealed = await page
  .locator("#main [data-focus-result]", { hasText: "Treat this like the secret key" })
  .waitFor({ timeout: 5000 })
  .then(() => true)
  .catch(() => false);
check(revealed && path(page) === editPath, "the superadmin reveals the passphrase in place");

// A HOOK IN THE LIBRARY (NOT ATTACHED, SO THE RUN ABOVE STAYS AS IT WAS)

async function addHook(): Promise<void> {
  await page.goto("/hooks/new");
  await page.fill("#new-name", "smoke hook");
  await page.selectOption("#new-host", { label: "local" });
  await page.fill("#new-container", "drydock-test-smoke-target-1");
  await page.fill("#new-argv", '["echo", "$(id)"]');
  await page.fill("#new-timeout", "30");
  await page.click("main button[type=submit]");
  await page
    .waitForURL(/\/hooks\/\d+$/, { timeout: 5000 })
    .catch(() => page.locator("#reauth-password").waitFor({ timeout: 5000 }));
}
await addHook();
if ((await page.locator("#reauth-password").count()) > 0) {
  await page.fill("#reauth-password", PASSWORD);
  await Promise.all([page.waitForEvent("load"), page.click("main button[type=submit]")]);
  await addHook();
}
const hookPath = path(page);
check(/^\/hooks\/\d+$/.test(hookPath), "HX-Redirect navigates to the new hook");
const hookPage = await page.goto(hookPath);
await page.waitForLoadState("networkidle");
check(
  hookPage?.status() === 200 &&
    (await page.locator("#main pre", { hasText: '["echo", "$(id)"]' }).count()) === 1,
  "the hook page shows its command as written",
);

// HOSTS: AN SSH HOST SHOWS ONLY ITS PUBLIC KEY; A FAILED SCAN SWAPS INTO MAIN

await page.goto("/hosts/new?kind=ssh");
await page.fill("#new-name", "remote");
await page.fill("#new-address", "127.0.0.1");
await page.fill("#new-port", "1"); // nothing listens there, so the scan fails at once
await page.fill("#new-username", "backup");
await Promise.all([page.waitForURL(/\/hosts\/\d+$/), page.click("main button[type=submit]")]);
const sshPath = path(page);
await page.waitForLoadState("networkidle");
const sshHtml = await page.content();
check(
  sshHtml.includes('restrict,port-forwarding,command="/bin/false" ssh-ed25519 ') &&
    !/PRIVATE KEY|openssh-key-v1|gAAAAA/.test(sshHtml),
  "the SSH host page shows the public key and no key material",
);
await page.click("form[action$='/scan-hostkey'] button[type=submit]");
await expectMainAlert("Could not read the host key", sshPath, "a failed host key scan swaps into #main");

await page.goto(sshPath);
await Promise.all([
  page.waitForURL(`${BASE}/hosts`),
  page.click("form[action$='/delete'] button[type=submit]"),
]);
check(!(await page.content()).includes(">remote<"), "an htmx delete returns to the host list");

// 401 SENDS THE BROWSER TO THE LOGIN PAGE

await page.goto(operatorPath);
await context.clearCookies();
await Promise.all([
  page.waitForURL(`${BASE}/login`),
  page.click(`form[action='${operatorPath}/sessions/revoke'] button[type=submit]`),
]);
check(path(page) === "/login", "an htmx request without a session redirects to /login");

// LOGOUT THROUGH HTMX

await login();
await page.click("#user-menu summary");
await Promise.all([page.waitForURL(`${BASE}/login`), page.click("#user-menu form[action='/logout'] button")]);
check(path(page) === "/login", "htmx logout lands on /login");
await page.goto("/account");
check(path(page) === "/login", "the session is gone after logout");

// INJECTED HTMX MARKUP IS NEUTRALISED BY HX-CSP

await login();
expectedConsole.push(/\[hx-csp\] blocked/);
const stripped = await page.evaluate(() => {
  const w = window as unknown as { htmx: { process: (elt: Element) => void } };
  const button = document.createElement("button");
  button.setAttribute("hx-post", "/logout");
  button.setAttribute("hx-trigger", "load");
  document.getElementById("main")?.append(button);
  w.htmx.process(button);
  return !button.hasAttribute("hx-post") && !button.hasAttribute("hx-trigger");
});
await page.waitForTimeout(500);
check(stripped && path(page) === "/", "an element without the page nonce loses its hx- attributes");

await browser.close();

if (process.env.SMOKE_CHECK_PID1 === "1") {
  // A crash loop under the image's constraints (read-only root, uid 10001) changes the PID.
  const pids = [...rclonePids().keys()];
  check(
    pids.length === 1 && rcloneAtStart.has(pids[0] ?? ""),
    `rclone kept running through the smoke test (${[...rcloneAtStart.keys()]} -> ${pids})`,
  );
}

// RESULT

check(violations.length === 0, `no securitypolicyviolation events (${violations.length})`);
for (const violation of violations) {
  console.error(`  violation ${violation}`);
}
if (failures.length > 0) {
  console.error(`\n${failures.length} smoke check(s) failed:`);
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  process.exit(1);
}
console.log("\nCSP smoke test passed.");
