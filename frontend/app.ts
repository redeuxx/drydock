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

// POLLERS
//
// Elements that refresh themselves with hx-trigger "every Ns": a log poller (new lines
// every 2 seconds: #log-poller for a run's log, routes/runs.py, and [data-log-poller] for
// containers' logs, routes/logs.py) and every [data-poller] region, such as
// the dashboard's environment cards, whose attribute names them in error messages. Polls
// are background traffic: they never hide an error left by a user action, a failing poll
// shows its error once instead of re-announcing it on every poll, and an error answer
// never replaces the poller, which keeps retrying. They carry X-Drydock-Poll, so they
// never keep an idle session alive (security/sessions.py), and they skip their turn
// while the tab is hidden. New log lines scroll the log (the poller's [role=log]) to the
// bottom only if the reader was already there, and a log with data-max-lines drops its
// oldest lines past that count. A failing container log names its reason
// (X-Drydock-Reason).

const POLLER_ID = "log-poller";
const POLL_HEADER = "X-Drydock-Poll";
let followLog = true;
let followed: HTMLElement | null = null; // the log a poller's swap appends to
let pollErrorShown = false;

function isLogPoller(element: unknown): boolean {
  return element instanceof Element && (element.id === POLLER_ID || element.hasAttribute("data-log-poller"));
}

function isPoller(element: unknown): boolean {
  return isLogPoller(element) || (element instanceof Element && element.hasAttribute("data-poller"));
}

function pollerName(element: unknown): string {
  return (element instanceof Element && element.getAttribute("data-poller")) || "Live log";
}

function runLog(): HTMLElement | null {
  return document.getElementById("run-log");
}

function logOf(element: unknown): HTMLElement | null {
  return element instanceof Element ? element.closest<HTMLElement>("[role=log]") : null;
}

document.addEventListener("htmx:config:request", (event) => {
  const ctx = event.detail.ctx;
  if (!isPoller(ctx.sourceElement)) return;
  // Nobody is looking, a dialog in the region is open (the swap would close it), or the
  // reader paused the log: skip this turn, the next tick polls.
  const paused = ctx.sourceElement.closest("[data-paused]") !== null;
  if (document.hidden || paused || ctx.sourceElement.querySelector("dialog[open]")) {
    event.preventDefault();
    return;
  }
  ctx.request.headers[POLL_HEADER] = "1";
});

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

// Rows selected in a polled table (data-select) stay selected across its swaps.
let selectedRows: string[] = [];

document.addEventListener("htmx:before:swap", (event) => {
  const target = event.detail.ctx.target;
  if (target instanceof Element && target.hasAttribute("data-poller")) {
    selectedRows = [...target.querySelectorAll<HTMLInputElement>("input[data-select]:checked")].map(
      (box) => box.value,
    );
  }
  if (isLogPoller(target)) {
    followed = logOf(target);
    followLog = !followed || followed.scrollHeight - followed.scrollTop - followed.clientHeight < 32;
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
    const reason = ctx.response?.headers.get("X-Drydock-Reason");
    pollFailed(
      reason
        ? `${pollerName(ctx.sourceElement)}: ${reason} Drydock keeps trying.`
        : `${pollerName(ctx.sourceElement)} updates failed (HTTP ${status}). Drydock keeps trying; reload the page if this persists.`,
    );
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
  const source = event.detail.ctx?.sourceElement;
  if (isPoller(source)) {
    pollFailed(`${pollerName(source)} updates failed. Check the connection; drydock keeps trying.`);
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

// SELECT ALL
//
// The containers table's header checkbox (data-select-all) checks or clears every row's
// (data-select).

document.addEventListener("change", (event) => {
  const all = event.target;
  if (!(all instanceof HTMLInputElement) || !all.hasAttribute("data-select-all")) return;
  for (const box of document.querySelectorAll<HTMLInputElement>("input[data-select]")) {
    box.checked = all.checked;
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

// THE CONTAINERS PAGE'S HOST
//
// The host picker (data-remember-host, on the containers, stacks, images and logs pages)
// remembers the last host chosen, and the menu's links to those pages open that host. A
// convenience only: storage may be unavailable, and the server falls back to its own
// choice for a host that no longer exists.

const HOST_KEY = "drydock.containers.host";

document.addEventListener("change", (event) => {
  const picker = event.target;
  if (!(picker instanceof HTMLSelectElement) || !picker.hasAttribute("data-remember-host")) return;
  try {
    localStorage.setItem(HOST_KEY, picker.value);
  } catch {
    // storage blocked
  }
});

try {
  const saved = localStorage.getItem(HOST_KEY);
  for (const path of ["/containers", "/stacks", "/images", "/logs"]) {
    const link = document.querySelector<HTMLAnchorElement>(`nav a[href="${path}"]`);
    if (saved && link) link.href = `${path}?host=${encodeURIComponent(saved)}`;
  }
} catch {
  // storage blocked
}

// THE LOGS PAGE
//
// Everything here works on what was read; nothing is read again. Pause stops the logs'
// polls (each poller keeps its place, so nothing is missed), Clear empties the view only.
// The options set data attributes on #log-view that the logs restyle by (timestamps, line
// wrap, text size). Search marks matches in the lines shown, new ones included, by
// rebuilding each line's text from text nodes (never markup). Copy takes the lines as
// shown. The filter box hides containers whose name lacks its text. A star marks a
// favourite, kept per host in this browser and listed first; like the host, a
// convenience only.

const FAVOURITES_KEY = "drydock.logs.favourites";

function favourites(): Record<string, string[]> {
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(FAVOURITES_KEY) ?? "{}");
    return saved && typeof saved === "object" && !Array.isArray(saved) ? (saved as Record<string, string[]>) : {};
  } catch {
    return {};
  }
}

function starredOn(host: string): string[] {
  const names = favourites()[host];
  return Array.isArray(names) ? names.filter((n) => typeof n === "string") : [];
}

function showFavourites(): void {
  const list = document.querySelector<HTMLElement>("[data-favourites]");
  if (!list) return;
  const names = starredOn(list.dataset.favourites ?? "");
  const items = [...list.querySelectorAll<HTMLElement>("li[data-name]")];
  for (const item of items) {
    item.querySelector("[data-star]")?.setAttribute("aria-pressed", String(names.includes(item.dataset.name ?? "")));
  }
  // Starred first, each group in the server's order (by name).
  const rank = (item: HTMLElement) =>
    (names.includes(item.dataset.name ?? "") ? 0 : 1e6) + Number(item.dataset.order ?? 0);
  list.append(...items.sort((a, b) => rank(a) - rank(b)));
}

function logView(): HTMLElement | null {
  return document.getElementById("log-view");
}

function searchText(): string {
  return document.querySelector<HTMLInputElement>("[data-log-search]")?.value.trim().toLowerCase() ?? "";
}

function markLine(line: Element, query: string): boolean {
  const span = line.querySelector<HTMLElement>("[data-text]");
  if (!span) return false;
  const text = span.textContent ?? "";
  const lower = text.toLowerCase();
  if (!query || !lower.includes(query)) {
    if (span.childElementCount) span.textContent = text;
    return false;
  }
  const parts: Node[] = [];
  let at = 0;
  for (let found = lower.indexOf(query); found !== -1; found = lower.indexOf(query, at)) {
    parts.push(document.createTextNode(text.slice(at, found)));
    const mark = document.createElement("mark");
    mark.textContent = text.slice(found, found + query.length);
    parts.push(mark);
    at = found + query.length;
  }
  parts.push(document.createTextNode(text.slice(at)));
  span.replaceChildren(...parts);
  return true;
}

// Each line is marked once for the search shown (data-marked), so a poll marks only the
// lines it brought.
function markLines(lines: Iterable<Element>): void {
  const query = searchText();
  for (const line of lines) {
    markLine(line, query);
    line.setAttribute("data-marked", "");
  }
}

function countMatches(): void {
  const query = searchText();
  const view = logView();
  const count = document.querySelector<HTMLElement>("[data-log-matches]");
  if (!view || !count) return;
  const matching = query ? view.querySelectorAll("[data-line] mark").length : 0;
  count.textContent = query ? `${matching} match${matching === 1 ? "" : "es"}` : "";
}

document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) return;
  const view = logView();
  const pause = event.target.closest<HTMLButtonElement>("[data-log-pause]");
  if (pause && view) {
    const paused = !view.hasAttribute("data-paused");
    view.toggleAttribute("data-paused", paused);
    pause.setAttribute("aria-pressed", String(paused));
    pause.textContent = paused ? "Resume" : "Pause";
    return;
  }
  if (event.target.closest("[data-log-clear]") && view) {
    for (const line of view.querySelectorAll("[data-line]")) line.remove();
    countMatches();
    return;
  }
  if (event.target.closest("[data-log-copy]") && view) {
    const text = [...view.querySelectorAll<HTMLElement>("[data-line]")].map((line) => line.innerText).join("\n");
    const refused = () => showClientError("Copying needs HTTPS. Select the lines and copy them instead.");
    // The clipboard needs HTTPS (or localhost); plain HTTP leaves selecting by hand.
    if (!window.isSecureContext || !navigator.clipboard) {
      refused();
    } else {
      navigator.clipboard.writeText(text).then(() => hideClientError(), refused);
    }
    return;
  }
  const star = event.target.closest<HTMLButtonElement>("[data-star]");
  const host = star?.closest<HTMLElement>("[data-favourites]")?.dataset.favourites;
  const name = star?.closest<HTMLElement>("li[data-name]")?.dataset.name;
  if (!star || !host || name === undefined) return;
  const names = starredOn(host).filter((n) => n !== name);
  if (star.getAttribute("aria-pressed") !== "true") names.push(name);
  const saved = favourites();
  saved[host] = names;
  try {
    localStorage.setItem(FAVOURITES_KEY, JSON.stringify(saved));
  } catch {
    // storage blocked: the star shows until the page changes
  }
  star.setAttribute("aria-pressed", String(names.includes(name)));
  showFavourites();
});

document.addEventListener("change", (event) => {
  const field = event.target;
  const view = logView();
  if (!view || !(field instanceof HTMLElement)) return;
  if (field instanceof HTMLInputElement && field.dataset.logOption) {
    view.toggleAttribute(`data-${field.dataset.logOption}`, !field.checked);
  } else if (field instanceof HTMLSelectElement && field.hasAttribute("data-log-size")) {
    view.dataset.size = field.value;
  }
});

document.addEventListener("input", (event) => {
  const box = event.target;
  if (box instanceof HTMLInputElement && box.hasAttribute("data-log-search")) {
    markLines(logView()?.querySelectorAll("[data-line]") ?? []);
    countMatches();
    return;
  }
  if (!(box instanceof HTMLInputElement) || !box.hasAttribute("data-log-filter")) return;
  const text = box.value.trim().toLowerCase();
  for (const item of document.querySelectorAll<HTMLElement>("[data-favourites] li[data-name]")) {
    item.hidden = !(item.dataset.name ?? "").toLowerCase().includes(text);
  }
});

// The container list folds away (details[data-remember-open]) and stays as it was left
// when the page changes, in this browser. A convenience only: storage may be unavailable.

const LIST_OPEN_KEY = "drydock.logs.list-open";

function restoreList(): void {
  const list = document.querySelector<HTMLDetailsElement>("details[data-remember-open]");
  try {
    if (list && localStorage.getItem(LIST_OPEN_KEY) === "0") list.open = false;
  } catch {
    // storage blocked
  }
}

// toggle does not bubble: listen in the capture phase.
document.addEventListener(
  "toggle",
  (event) => {
    const list = event.target;
    if (!(list instanceof HTMLDetailsElement) || !list.hasAttribute("data-remember-open")) return;
    try {
      localStorage.setItem(LIST_OPEN_KEY, list.open ? "1" : "0");
    } catch {
      // storage blocked
    }
  },
  true,
);

showFavourites();
restoreList();
document.addEventListener("htmx:after:swap", (event) => {
  const target = event.detail.ctx?.target;
  if (target instanceof HTMLElement && target.id === "main") {
    showFavourites();
    restoreList();
  }
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
    if (isLogPoller(target) && followed) {
      if (searchText()) markLines(followed.querySelectorAll("[data-line]:not([data-marked])"));
      const max = Number(followed.dataset.maxLines);
      const lines = followed.querySelectorAll("[data-line]");
      for (let i = 0; max > 0 && i < lines.length - max; i++) lines[i]?.remove();
      if (searchText()) countMatches(); // after the oldest lines went
      if (followLog) followed.scrollTop = followed.scrollHeight;
      followed = null;
    }
    for (const box of document.querySelectorAll<HTMLInputElement>("input[data-select]")) {
      if (selectedRows.includes(box.value)) box.checked = true;
    }
    selectedRows = [];
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
