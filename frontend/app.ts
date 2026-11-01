// DRYDOCK CLIENT
//
// Loaded with defer after htmx and the hx-csp extension. The CSP forbids inline
// scripts and eval, and templates never use hx-on, so all client behaviour lives here.
//
// Logged-in pages inherit hx-target="#main", hx-select="#main" and hx-swap="outerHTML"
// from <body>. htmx 4 swaps 4xx and 5xx responses by default, and every HTML error page
// the server renders has a #main, so validation errors (422), conflicts (409), the
// re-auth form (403) and other HTML error pages replace the main column safely.
// Responses that cannot be swapped are handled below instead.

const LOGIN_PATH = "/login";

function clientErrorBox(): HTMLElement | null {
  return document.getElementById("client-error");
}

function showClientError(message: string): void {
  const box = clientErrorBox();
  const text = box?.querySelector<HTMLElement>("[data-message]");
  if (!box || !text) {
    return;
  }
  text.textContent = message; // never innerHTML: the message may echo server text
  box.hidden = false;
}

function hideClientError(): void {
  const box = clientErrorBox();
  if (box) {
    box.hidden = true;
  }
}

// LIVE REGIONS LOADED IN PLACE
//
// A region such as the host page's container inventory (aria-live, aria-busy="true")
// loads its own content with hx-get. Failures are written into the region as text, since
// an error page has no fragment for its hx-select to pick.

function isRegion(target: unknown): target is HTMLElement {
  return target instanceof HTMLElement && target.hasAttribute("aria-live");
}

function regionFailed(region: HTMLElement, message: string): void {
  region.textContent = message;
  region.setAttribute("aria-busy", "false");
}

// FORM FIELDS FILLED IN PLACE
//
// A field such as the SFTP host key (data-field-region) can fill itself from the server
// (hx-select picks it from the whole page). A 422 page holds the field with its error; any
// other error page does not, and swapping it would delete the field, so it is shown in the
// client error box instead. After a swap, focus moves to the field's result.

function isFieldRegion(target: unknown): target is HTMLElement {
  return target instanceof HTMLElement && target.hasAttribute("data-field-region");
}

// THE RUN LOG POLLER
//
// The run page polls for new log lines every 2 seconds (routes/runs.py). Polls are
// background traffic: they never hide an error left by a user action, a failing poll
// shows its error once instead of re-announcing it every 2 seconds, and an error answer
// never replaces the poller, which keeps retrying. New lines scroll the log to the bottom
// only if the reader was already there.

const POLLER_ID = "log-poller";
let followLog = true;
let pollErrorShown = false;

function isPoller(element: unknown): boolean {
  return element instanceof Element && element.id === POLLER_ID;
}

function runLog(): HTMLElement | null {
  return document.getElementById("run-log");
}

function pollFailed(message: string): void {
  const box = clientErrorBox();
  if (box && !box.hidden && pollErrorShown) {
    return; // already showing; setting it again would re-announce it
  }
  showClientError(message);
  pollErrorShown = true;
}

const initialLog = runLog();
if (initialLog) {
  initialLog.scrollTop = initialLog.scrollHeight; // the newest lines, or the outcome
}

document.addEventListener("htmx:before:swap", (event) => {
  if (isPoller(event.detail.ctx.target)) {
    const log = runLog();
    followLog = !log || log.scrollHeight - log.scrollTop - log.clientHeight < 32;
  }
});

// RESPONSE ERRORS

document.addEventListener("htmx:response:error", (event) => {
  const ctx = event.detail.ctx;
  const status = ctx.response?.status ?? 0;
  if (status === 401) {
    // The session expired or was revoked. A full navigation shows the login form.
    ctx.swap = "none";
    window.location.assign(LOGIN_PATH);
    return;
  }
  if (isPoller(ctx.sourceElement)) {
    ctx.swap = "none";
    pollFailed(`Live log updates failed (HTTP ${status}). Drydock keeps trying; reload the page if this persists.`);
    return;
  }
  if (isRegion(ctx.target)) {
    ctx.swap = "none";
    regionFailed(ctx.target, `Could not load this section (HTTP ${status}). Reload the page.`);
    return;
  }
  if (isFieldRegion(ctx.target) && status !== 422) {
    ctx.swap = "none";
    showClientError(`The request failed (HTTP ${status}). Reload the page and try again.`);
    return;
  }
  const contentType = ctx.response?.headers.get("content-type") ?? "";
  if (!contentType.startsWith("text/html")) {
    // Plain-text errors (413, 500) have no #main to select; keep the page as it is.
    ctx.swap = "none";
    showClientError(`The request failed (HTTP ${status}). Reload the page and try again.`);
  }
});

// NETWORK AND CLIENT ERRORS

document.addEventListener("htmx:error", (event) => {
  if (isPoller(event.detail.ctx?.sourceElement)) {
    pollFailed("Live log updates failed. Check the connection; drydock keeps trying.");
    return;
  }
  const target = event.detail.ctx?.target;
  if (isRegion(target)) {
    regionFailed(target, "Could not load this section. Check the connection and reload the page.");
    return;
  }
  showClientError("The request could not be completed. Check the connection and try again.");
});

document.addEventListener("htmx:security:strip", () => {
  showClientError("An element on this page was blocked by the content security policy.");
});

document.addEventListener("htmx:before:request", (event) => {
  if (!isPoller(event.detail.ctx.sourceElement)) {
    hideClientError();
    pollErrorShown = false;
  }
});

// MENUS
//
// The header's dropdowns are <details data-menu> elements: they open without script, and
// this closes an open one when a click lands outside it.

document.addEventListener("click", (event) => {
  for (const menu of document.querySelectorAll<HTMLDetailsElement>("details[data-menu][open]")) {
    if (!(event.target instanceof Node) || !menu.contains(event.target)) menu.open = false;
  }
});

// SCHEDULE PRESETS
//
// The job form's schedule list (data-cron-preset) fills the cron field, so switching to
// Custom starts from the preset just chosen. The server applies the preset either way.

document.addEventListener("change", (event) => {
  const list = event.target;
  if (!(list instanceof HTMLSelectElement) || !list.hasAttribute("data-cron-preset")) return;
  const field = list.closest("[data-schedule]")?.querySelector<HTMLInputElement>('input[name="cron"]');
  if (field && list.value !== "custom") field.value = list.value === "manual" ? "" : list.value;
});

// FOCUS AFTER A SWAP OF #MAIN
//
// hx-disable disables the focused submit button, so focus falls to <body>. Move it to the
// swapped-in alert, or else to the result of the action (data-focus-result), so keyboard
// and screen-reader users land on what the submit produced. Pages with an autofocus field
// (the re-auth form) are left to htmx, which focuses it. Swaps inside #main, such as the
// inventory loading, never move focus.

document.addEventListener("htmx:after:swap", (event) => {
  const target = event.detail.ctx.target;
  if (isPoller(target)) {
    const log = runLog();
    if (log && followLog) {
      log.scrollTop = log.scrollHeight;
    }
    if (pollErrorShown) {
      hideClientError(); // the poll works again
      pollErrorShown = false;
    }
    return;
  }
  if (isRegion(target)) {
    target.setAttribute("aria-busy", "false");
    return;
  }
  if (isFieldRegion(target)) {
    // outerHTML: the target is detached, its replacement has the same id.
    const result = document
      .getElementById(target.id)
      ?.querySelector<HTMLElement>("[role=alert], [data-focus-result]");
    if (result) {
      result.tabIndex = -1;
      result.focus();
    }
    return;
  }
  if (!(target instanceof HTMLElement) || target.id !== "main") {
    return;
  }
  const main = document.getElementById("main");
  if (!main || main.querySelector("[autofocus]")) {
    return;
  }
  const landing =
    main.querySelector<HTMLElement>("[role=alert]") ??
    main.querySelector<HTMLElement>("[data-focus-result]");
  if (landing) {
    landing.tabIndex = -1;
    landing.focus();
  }
});

// BACK/FORWARD CACHE
//
// After HX-Redirect, htmx 4 keeps request indicators (keepIndicators), so a page restored
// from the back/forward cache would show disabled, spinning submit buttons. Reload it.

window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    window.location.reload();
  }
});
