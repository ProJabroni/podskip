/* Podskip — a podcast player that skips the ads.
 *
 * How it fits together:
 *  - This page runs on GitHub Pages and stores your settings on this phone.
 *  - Your shows and scan results live on the repo's `data` branch, encrypted
 *    with a key only this app and your PODSKIP_KEY secret know.
 *  - A GitHub Actions job (scan.yml) transcribes new episodes and marks the ads.
 *  - The phone streams each episode from the podcast's own server and jumps
 *    over the marked ads while you listen.
 */
"use strict";

// ------------------------------------------------------------------ helpers
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const LS = {
  get(k, d) { try { const v = localStorage.getItem("ps:" + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("ps:" + k, JSON.stringify(v)); } catch {} },
  del(k) { try { localStorage.removeItem("ps:" + k); } catch {} },
};

function clock(t) {
  if (!isFinite(t) || t < 0) t = 0;
  t = Math.floor(t);
  const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60), s = t % 60;
  return h ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}` : `${m}:${String(s).padStart(2, "0")}`;
}
function length(t) {
  if (!t) return "";
  const m = Math.round(t / 60);
  return m >= 60 ? `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, "0")} m` : `${m} min`;
}
function ago(ts) {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
function day(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000), now = new Date();
  const diff = Math.floor((now - d) / 86400000);
  if (diff < 1 && d.getDate() === now.getDate()) return "Today";
  if (diff < 2) return "Yesterday";
  if (diff < 7) return d.toLocaleDateString(undefined, { weekday: "long" });
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: d.getFullYear() === now.getFullYear() ? undefined : "numeric" });
}
function https(u) { return String(u || "").replace(/^http:\/\//i, "https://"); }
function initials(t) { return esc((t || "?").replace(/^the\s+/i, "").trim().slice(0, 2)); }
function artImg(src, title, cls = "art") {
  return src
    ? `<img class="${cls}" src="${esc(https(src))}" alt="" loading="lazy" data-fallback="${initials(title)}" onerror="artFail(this)">`
    : `<span class="${cls} art-fallback">${initials(title)}</span>`;
}
window.artFail = (img) => {
  const s = document.createElement("span");
  s.className = img.className + " art-fallback";
  s.textContent = img.dataset.fallback || "";
  img.replaceWith(s);
};

let toastTimer;
function toast(msg, action, ms) {
  const t = $("#toast");
  t.innerHTML = `<span>${esc(msg)}</span>` + (action ? `<button type="button">${esc(action.label)}</button>` : "");
  t.hidden = false;
  if (action) $("button", t).onclick = () => { t.hidden = true; action.run(); };
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), ms || (action ? 6000 : 3200));
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) { const old = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = old), 1600); }
  } catch {
    toast("Couldn't copy. Press and hold the text to copy it.");
  }
}

// ------------------------------------------------------------------ state
const where = (() => {
  const host = location.hostname;
  const m = host.match(/^([^.]+)\.github\.io$/i);
  const repo = location.pathname.split("/").filter(Boolean)[0];
  return m && repo ? { owner: m[1], repo } : { owner: "", repo: "" };
})();

let cfg = LS.get("cfg", null); // { owner, repo, token, key, gemini, ready }
let prefs = Object.assign({ skip: { sponsor: true, promo: true, self: false }, speed: 1, sound: "off", autoDl: true, cleanDl: true }, LS.get("prefs", {}));
let progress = LS.get("progress", {}); // epId -> { t, d, done, at }
let index = LS.get("index", null); // decrypted index from the scanner
let status = LS.get("status", null); // status.json
let subs = null; // decrypted subscriptions
let lastRun = null; // newest Actions run
let dispatchedAt = 0;
const episodes = new Map(); // epId -> analysis (decrypted)

const savePrefs = () => LS.set("prefs", prefs);
const saveProgress = () => LS.set("progress", progress);

// ------------------------------------------------------------------ crypto
let aesKey = null;
async function key() {
  if (!aesKey) {
    const d = await crypto.subtle.digest("SHA-256", enc.encode("podskip/v1/" + cfg.key));
    aesKey = await crypto.subtle.importKey("raw", d, "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  return aesKey;
}
const AAD = enc.encode("podskip");
class KeyMismatch extends Error {}
async function unseal(buf) {
  const u = new Uint8Array(buf);
  if (String.fromCharCode(u[0], u[1], u[2], u[3]) !== "PSK1") throw new Error("not a Podskip file");
  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(4, 16), additionalData: AAD }, await key(), u.slice(16));
  } catch {
    // AES-GCM only fails like this when the key is different from the one that saved the file.
    throw new KeyMismatch("This phone's key doesn't match the data saved on GitHub.");
  }
  const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(await new Response(stream).text());
}
async function seal(obj) {
  const gz = await new Response(new Blob([JSON.stringify(obj)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, await key(), gz));
  const out = new Uint8Array(16 + ct.length);
  out.set(enc.encode("PSK1"), 0); out.set(iv, 4); out.set(ct, 16);
  return out;
}
function b64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s.replace(/\s/g, ""));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
async function sha1hex(text, n) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-1", enc.encode(text)));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, n);
}
function newKey() {
  const b = crypto.getRandomValues(new Uint8Array(24));
  return b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const secretValue = () => `psk1.${cfg.key}.${cfg.gemini || ""}`;

// ------------------------------------------------------------------ GitHub
class AuthError extends Error {}
const repoPath = () => `/repos/${cfg.owner}/${cfg.repo}`;

async function gh(path, opts = {}) {
  const headers = { Authorization: "Bearer " + cfg.token, Accept: opts.accept || "application/vnd.github+json" };
  if (opts.body) headers["Content-Type"] = "application/json";
  let r;
  try {
    r = await fetch("https://api.github.com" + path, { method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined, cache: "no-store" });
  } catch (e) {
    throw new Error("Can't reach GitHub. Check your connection.");
  }
  if (r.status === 401) throw new AuthError("GitHub didn't accept your token.");
  return r;
}
async function ghJson(path, opts) {
  const r = await gh(path, opts);
  if (!r.ok) {
    let msg = "";
    try { msg = (await r.json()).message; } catch {}
    const e = new Error(msg || `GitHub error ${r.status}`);
    e.status = r.status;
    throw e;
  }
  return r.status === 204 ? null : r.json();
}
// Files on the data branch are read through Git's tree and blob APIs. GitHub's
// "contents" API guesses a text encoding for files it thinks are text and can
// re-encode them, which garbles encrypted bytes. Blobs come back exactly as saved.
let treeMemo = null;
async function dataTree(fresh) {
  if (!fresh && treeMemo && Date.now() - treeMemo.at < 4000) return treeMemo.map;
  const r = await gh(`${repoPath()}/git/trees/data?recursive=1`);
  if (r.status === 404 || r.status === 409) return new Map();
  if (!r.ok) throw new Error(`Couldn't list your data on GitHub (${r.status})`);
  const j = await r.json();
  const map = new Map((j.tree || []).filter((t) => t.type === "blob").map((t) => [t.path, t.sha]));
  treeMemo = { at: Date.now(), map };
  return map;
}
let blobStore;
async function blobBytes(sha) {
  const k = `/podskip-cache/blob/${sha}`;
  try {
    blobStore = blobStore || (await caches.open("podskip-blobs"));
    const hit = await blobStore.match(k);
    if (hit) return new Uint8Array(await hit.arrayBuffer());
  } catch {}
  const j = await ghJson(`${repoPath()}/git/blobs/${sha}`);
  const bytes = unb64(j.content || "");
  // Blobs never change for a given id, so they can be kept.
  try { await blobStore?.put(k, new Response(bytes.slice(0))); } catch {}
  return bytes;
}
async function rawFile(path, fresh) {
  const sha = (await dataTree(fresh)).get(path);
  if (!sha) return null;
  const b = await blobBytes(sha);
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

async function loadSubs() {
  const sha = (await dataTree(true)).get("subs.enc");
  if (!sha) return { obj: null, sha: null };
  return { obj: await unseal(await blobBytes(sha)), sha };
}

async function changeSubs(mutate, message) {
  const next = await changeEnc("subs.enc", () => ({ v: 1, feeds: [], want: [], perShow: 3 }), mutate, message);
  subs = next;
  return next;
}

// Read an encrypted file from the data branch, change it, and save it back.
async function changeEnc(path, fresh, mutate, message) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const sha = (await dataTree(true)).get(path) || null;
    const obj = sha ? await unseal(await blobBytes(sha)) : null;
    const next = obj || fresh();
    await mutate(next);
    const r = await gh(`${repoPath()}/contents/${path}`, {
      method: "PUT",
      body: { message, content: b64(await seal(next)), branch: "data", ...(sha ? { sha } : {}) },
    });
    if (r.ok) { treeMemo = null; return next; }
    if (r.status !== 409 && r.status !== 422) {
      let msg = ""; try { msg = (await r.json()).message; } catch {}
      throw new Error(msg || `Couldn't save (${r.status})`);
    }
    await sleep(600 + attempt * 600);
  }
  throw new Error("Someone else was saving at the same time. Try again.");
}

async function dataBranchExists() {
  const r = await gh(`${repoPath()}/git/ref/heads/data`);
  if (!r.ok) return false;
  // A blank data branch (marked unclaimed) can be set up from scratch.
  const blank = await gh(`${repoPath()}/contents/.podskip-unclaimed?ref=data`);
  return !blank.ok;
}

async function createDataBranch() {
  const files = [
    ["subs.enc", await seal({ v: 1, feeds: [], want: [], perShow: 3 })],
    ["README.md", enc.encode("This branch holds Podskip's encrypted shows and scan results. Change it from the app, not by hand.\n")],
  ];
  const tree = [];
  for (const [path, bytes] of files) {
    const blob = await ghJson(`${repoPath()}/git/blobs`, { method: "POST", body: { content: b64(bytes), encoding: "base64" } });
    tree.push({ path, mode: "100644", type: "blob", sha: blob.sha });
  }
  const t = await ghJson(`${repoPath()}/git/trees`, { method: "POST", body: { tree } });
  const c = await ghJson(`${repoPath()}/git/commits`, { method: "POST", body: { message: "Start Podskip data", tree: t.sha, parents: [] } });
  const existing = await gh(`${repoPath()}/git/ref/heads/data`);
  if (existing.ok) {
    await ghJson(`${repoPath()}/git/refs/heads/data`, { method: "PATCH", body: { sha: c.sha, force: true } });
  } else {
    await ghJson(`${repoPath()}/git/refs`, { method: "POST", body: { ref: "refs/heads/data", sha: c.sha } });
  }
  subs = { v: 1, feeds: [], want: [], perShow: 3 };
  treeMemo = null;
}

async function scanNow(quiet, testPush) {
  try {
    await ghJson(`${repoPath()}/actions/workflows/scan.yml/dispatches`, { method: "POST", body: { ref: "main", ...(testPush ? { inputs: { test_push: true } } : {}) } });
    lastRun = { status: "queued", created_at: new Date().toISOString() };
    dispatchedAt = Date.now();
    if (!quiet) toast("Scan started");
    paintPill();
    startPolling();
  } catch (e) {
    if (e instanceof AuthError) return authProblem();
    if (!quiet) toast(e.status === 403 || e.status === 404 ? "Your token can't start scans. It needs Actions: Read and write." : e.message);
  }
}

let lastJobs = null; // steps of the newest GitHub run
async function refreshJobs() {
  if (!lastRun?.id) { lastJobs = null; return; }
  try {
    const j = await ghJson(`${repoPath()}/actions/runs/${lastRun.id}/jobs`);
    lastJobs = { run: lastRun.id, steps: j.jobs?.[0]?.steps || [], started: j.jobs?.[0]?.started_at };
  } catch (e) {
    if (e instanceof AuthError) throw e;
  }
}

async function refreshRun() {
  try {
    const j = await ghJson(`${repoPath()}/actions/workflows/scan.yml/runs?per_page=1`);
    const run = j.workflow_runs?.[0] || null;
    // Right after starting a scan, GitHub may still list the previous run; keep showing "starting".
    const justAsked = Date.now() - dispatchedAt < 90000;
    if (justAsked && (!run || Date.parse(run.created_at) < dispatchedAt - 5000)) return;
    lastRun = run;
  } catch (e) {
    if (e instanceof AuthError) throw e;
  }
}

// ------------------------------------------------------------------ data
async function refreshIndex() {
  try {
    const s = await rawFile("status.json", true);
    if (s) { status = JSON.parse(new TextDecoder().decode(s)); LS.set("status", status); }
  } catch (e) {
    if (e instanceof AuthError) throw e;
  }
  const buf = await rawFile("index.enc");
  if (buf) {
    try {
      index = await unseal(buf);
      LS.set("index", index);
      announceSpots();
      if (Object.keys(dlBlobs).length) setTimeout(prematch, 500); // new scans of downloaded episodes
      setTimeout(autoDownload, 800); // new episodes of shows you follow
    } catch {
      showSecretProblem();
    }
  }
  if (status?.state === "error" && /PODSKIP_KEY/.test(status.error || "")) showSecretProblem();
}

// Tell you when the scanner finishes a spot check you asked for.
function announceSpots() {
  const res = index?.spot || {};
  let said = null;
  for (const rid of Object.keys(spots)) {
    const r = res[rid];
    if (!r) { if (Date.now() - spots[rid].at > 3 * 864e5) delete spots[rid]; continue; }
    delete spots[rid];
    const who = r.who?.length ? `: ${r.who.join(", ")}` : "";
    said = r.extra
      ? `Spot check done: found ${r.extra} more ad${r.extra > 1 ? "s" : ""} near ${clock(r.t)} (${clock(r.extraSec)}${who}). They'll be skipped from now on.`
      : r.n ? `Spot check done: pinned down the ad you reported at ${clock(r.t)} (${clock(r.sec)}${who}).`
      : r.kind === "gap" ? `Spot check done: no other ads near ${clock(r.t)}.`
      : `Spot check done: nothing new near ${clock(r.t)}. Podskip already had that ad marked.`;
  }
  LS.set("spots", spots);
  if (said) { toast(said, null, 7000); player.refreshAds?.(); }
}

async function refreshSubs() {
  const { obj } = await loadSubs();
  subs = obj;
}

async function loadEpisode(id) {
  const done = index?.scanned?.[id];
  if (!done) return null;
  const memo = `${id}-${done.at}-${done.env || 0}`;
  if (episodes.has(memo)) return episodes.get(memo);
  let a;
  try {
    const buf = await rawFile(`eps/${id}.enc`);
    if (!buf) return null;
    a = await unseal(buf);
  } catch (e) {
    // Offline: use the copy saved with a download.
    const saved = dlIndex[id] && (await idb.get("analysis", id).catch(() => null));
    if (!saved) throw e;
    a = saved;
  }
  episodes.set(memo, a);
  if (dlIndex[id]) idb.put("analysis", id, a).catch(() => {});
  return a;
}

function allEpisodes() {
  const out = [];
  for (const [fid, f] of Object.entries(index?.feeds || {})) {
    for (const ep of f.episodes || []) out.push({ ...ep, fid, show: f.title, showImg: f.image });
  }
  return out;
}
function findEpisode(id) {
  for (const [fid, f] of Object.entries(index?.feeds || {})) {
    const ep = (f.episodes || []).find((e) => e.id === id);
    if (ep) return { ...ep, fid, show: f.title, showImg: f.image };
  }
  return null;
}

function epState(ep) {
  const sc = index?.scanned?.[ep.id];
  const asked = subs?.rescan?.[ep.id] || 0;
  if (sc && sc.at >= asked) return { kind: sc.n ? "ads" : "clean", sc };
  if (status?.state === "running" && status.current === ep.id) return { kind: "scanning" };
  const failed = index?.failed?.[ep.id];
  if (failed && failed.tries >= 2 && failed.at >= asked) return { kind: "failed", err: failed.err };
  if (asked) return { kind: "queued" };
  const perShow = subs?.perShow || 3;
  const feed = index?.feeds?.[ep.fid];
  const pos = feed ? feed.episodes.findIndex((e) => e.id === ep.id) : -1;
  if ((pos > -1 && pos < perShow) || subs?.want?.includes(ep.id)) return { kind: "queued" };
  return { kind: "none" };
}
function stateChip(st) {
  switch (st.kind) {
    case "ads": return `<span class="chip tape">${st.sc.n} ad${st.sc.n > 1 ? "s" : ""} · ${clock(st.sc.sec)}</span>`;
    case "clean": return `<span class="chip clean">No ads found</span>`;
    case "scanning": return `<span class="chip busy">Scanning</span>`;
    case "queued": return `<span class="chip">Waiting to scan</span>`;
    case "failed": return `<span class="chip fail">Couldn't scan</span>`;
    default: return `<span class="chip">Not scanned</span>`;
  }
}

// ------------------------------------------------------------------ views
const view = $("#view");
const routes = { listen: viewHome, shows: viewLibrary, search: viewSearch, settings: viewSettings, downloaded: viewDownloaded, latest: viewLatest, scan: viewScan };
const TITLES = { listen: "Home", shows: "Library", search: "Search", settings: "Settings", downloaded: "Downloaded", latest: "Latest Episodes", scan: "Scans" };
const PARENT = { downloaded: "shows", latest: "shows", scan: "settings" };

function route() {
  if (!cfg?.ready) return viewSetup();
  const h = location.hash.replace(/^#/, "") || "listen";
  if (h.startsWith("ep-")) {
    // From a notification: show Home and open that episode's player.
    history.replaceState(null, "", "#listen");
    chrome("listen");
    viewHome();
    openFromLink(h.slice(3));
    return;
  }
  chrome(h);
  if (h.startsWith("show-")) return viewShow(h.slice(5));
  (routes[h] || viewHome)();
}
// Tab highlight, back button and the small title that shows once the big one scrolls away.
function chrome(h, smallTitle) {
  const isShow = h.startsWith("show-");
  const parent = isShow ? "shows" : PARENT[h];
  const tab = parent || (routes[h] ? h : "listen");
  $$("#tabs a").forEach((a) => a.toggleAttribute("aria-current", false));
  $(`#tabs a[data-tab="${tab}"]`)?.setAttribute("aria-current", "page");
  const back = $("#back");
  back.hidden = !parent;
  if (parent) { back.href = "#" + parent; $("span", back).textContent = TITLES[parent]; }
  $("#topbar-title").textContent = smallTitle ?? TITLES[h] ?? "";
  onScrollChrome();
}
function onScrollChrome() {
  $(".topbar").classList.toggle("scrolled", window.scrollY > 40);
}
addEventListener("scroll", onScrollChrome, { passive: true });
let pendingOpen = null;
function openFromLink(id) {
  if (findEpisode(id)) { pendingOpen = null; player.open(id, false); }
  else pendingOpen = id; // data still loading; boot() opens it
}
window.addEventListener("hashchange", () => { route(); window.scrollTo(0, 0); });

// ---- episode pieces
// "36 min", "1 hr 23 min"
function dur(sec) {
  if (!sec || !isFinite(sec)) return "";
  const m = Math.max(1, Math.round(sec / 60));
  return m >= 60 ? `${Math.floor(m / 60)} hr${m % 60 ? ` ${m % 60} min` : ""}` : `${m} min`;
}
const ICON_PLAY = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5.5v13l11-6.5z"/></svg>`;
const ICON_PAUSE = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 5h3.5v14H7zM13.5 5H17v14h-3.5z"/></svg>`;
const ICON_DL = `<svg class="dl-ico" viewBox="0 0 24 24" aria-label="Downloaded"><path d="M12 4v11m0 0-4.5-4.5M12 15l4.5-4.5M5 19h14"/></svg>`;
function playPill(ep) {
  const p = progress[ep.id];
  const playing = player.ep?.id === ep.id && !audio.paused;
  const left = p && !p.done && p.t > 10 && p.d ? p.d - p.t : null;
  const text = playing ? "Playing" : p?.done ? "Played" : left != null ? `${dur(left)} left` : dur(ep.dur) || "Play";
  const ring = left != null && !playing ? `<span class="pill-bar"><i style="width:${Math.round((p.t / p.d) * 100)}%"></i></span>` : "";
  return `<button class="playpill ${playing ? "on" : ""} ${p?.done && !playing ? "done" : ""}" type="button" data-play="${esc(ep.id)}" aria-label="${playing ? "Pause" : "Play"} ${esc(ep.title)}">${playing ? ICON_PAUSE : ICON_PLAY}<span>${text}</span>${ring}</button>`;
}
function adChip(ep) {
  const st = epState(ep);
  switch (st.kind) {
    case "ads": return `<span class="chip tape" title="${clock(st.sc.sec)} of ads">${st.sc.n} ad${st.sc.n > 1 ? "s" : ""} cut</span>`;
    case "clean": return `<span class="chip clean">No ads</span>`;
    case "scanning": return `<span class="chip busy">Scanning</span>`;
    case "queued": return `<span class="chip">Queued</span>`;
    case "failed": return `<button class="chip fail" type="button" data-scan="${esc(ep.id)}" data-again="1" aria-label="Scan this episode again">Retry</button>`;
    default: return `<button class="chip scanbtn" type="button" data-scan="${esc(ep.id)}" aria-label="Scan this episode for ads">Scan</button>`;
  }
}
function dlButton(ep) {
  const job = dlJobs[ep.id];
  if (job) {
    const pct = job.total ? Math.min(99, Math.floor((job.got / job.total) * 100)) : 0;
    return `<button class="iconbtn dlring busy" type="button" data-dl="${esc(ep.id)}" style="--p:${pct}" aria-label="Downloading ${pct}%. Tap to cancel"><i></i></button>`;
  }
  if (dlIndex[ep.id]) return `<span class="iconbtn done" title="Downloaded" aria-label="Downloaded">${ICON_DL}</span>`;
  return `<button class="iconbtn" type="button" data-dl="${esc(ep.id)}" aria-label="Download">${ICON_DL}</button>`;
}
const ICON_MORE = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="5.5" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="18.5" cy="12" r="1.6"/></svg>`;
function snippet(ep) {
  const d = (ep.desc || "").replace(/https?:\/\/\S+/g, "").replace(/\s+/g, " ").trim();
  return d.length > 160 ? d.slice(0, 157).trimEnd() + "…" : d;
}
// One episode in a list. withArt adds the show's artwork and name (for lists that mix shows).
function epRow(ep, withArt = true) {
  const p = progress[ep.id];
  const eyebrow = [day(ep.date), withArt ? ep.show : ""].filter(Boolean).join(" · ");
  const desc = snippet(ep);
  return `<div class="ep2 ${p?.done ? "played" : ""} ${withArt ? "with-art" : ""}" role="button" tabindex="0" data-ep="${esc(ep.id)}">
    ${withArt ? artImg(ep.img || ep.showImg, ep.show, "art ep2-art") : ""}
    <div class="ep2-main">
      <span class="ep2-eyebrow">${esc(eyebrow)}</span>
      <span class="ep2-title">${esc(ep.title)}</span>
      ${desc ? `<span class="ep2-desc">${esc(desc)}</span>` : ""}
      <span class="ep2-foot">${playPill(ep)}${adChip(ep)}<span class="ep2-tools">${dlButton(ep)}<button class="iconbtn" type="button" data-more="${esc(ep.id)}" aria-label="More options">${ICON_MORE}</button></span></span>
    </div>
  </div>`;
}
function bindEpRows(root = view) {
  $$("[data-ep]", root).forEach((el) => {
    el.onclick = (e) => {
      if (justHeld(el) || e.target.closest("button")) return;
      openEpisode(el.dataset.ep, true);
    };
    el.onkeydown = (e) => { if ((e.key === "Enter" || e.key === " ") && e.target === el) { e.preventDefault(); openEpisode(el.dataset.ep, true); } };
    onHold(el, () => episodeMenu(el.dataset.ep));
  });
  bindPills(root);
  bindRowTools(root);
}
function bindRowTools(root = view) {
  $$("[data-scan]", root).forEach((b) => (b.onclick = (e) => {
    e.stopPropagation();
    const ep = findEpisode(b.dataset.scan);
    if (ep) scanEpisode(ep, !!b.dataset.again);
  }));
  $$("[data-dl]", root).forEach((b) => (b.onclick = (e) => {
    e.stopPropagation();
    const ep = findEpisode(b.dataset.dl);
    if (!ep) return;
    if (dlJobs[ep.id]) dlJobs[ep.id].ctrl.abort();
    else startDownload(ep);
  }));
  $$("[data-more]", root).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); episodeMenu(b.dataset.more); }));
}

// ---- press and hold
// Hold a row or a show for half a second to open its menu (right-click on a computer).
function onHold(el, fn) {
  let timer = null, x = 0, y = 0;
  const cancel = () => { clearTimeout(timer); timer = null; el.classList.remove("holding"); };
  el.addEventListener("touchstart", (e) => {
    if (e.touches.length !== 1 || e.target.closest("button")) return;
    x = e.touches[0].clientX; y = e.touches[0].clientY;
    el.classList.add("holding");
    timer = setTimeout(() => { timer = null; el.classList.remove("holding"); el.dataset.held = Date.now(); fn(); }, 480);
  }, { passive: true });
  el.addEventListener("touchmove", (e) => { if (timer && Math.hypot(e.touches[0].clientX - x, e.touches[0].clientY - y) > 8) cancel(); }, { passive: true });
  el.addEventListener("touchend", cancel);
  el.addEventListener("touchcancel", cancel);
  el.addEventListener("contextmenu", (e) => { e.preventDefault(); if (!el.dataset.held || Date.now() - el.dataset.held > 800) { el.dataset.held = Date.now(); fn(); } });
}
// After a hold opens a menu, the finger lifting would also count as a tap. Ignore that one.
const justHeld = (el) => el.dataset.held && Date.now() - +el.dataset.held < 900;
function bindPills(root = view) {
  $$("[data-play]", root).forEach((b) => (b.onclick = (e) => {
    e.stopPropagation();
    const id = b.dataset.play;
    if (player.ep?.id === id && !audio.paused) audio.pause();
    else player.open(id, true, false); // play without covering the list
  }));
}
// Keep every play button on screen in step with what's playing.
function refreshPills() {
  $$("[data-play]", view).forEach((b) => {
    const ep = findEpisode(b.dataset.play);
    if (ep) b.outerHTML = playPill(ep);
  });
  bindPills();
}

// "Removing ads" card: what the scanner is doing right now.
function scanCard() {
  const fresh = status && Date.now() / 1000 - (status.at || 0) < 3 * 3600;
  const running = fresh && status.state === "running";
  const starting = !running && lastRun && lastRun.status !== "completed";
  if (!running && !starting) return "";
  let title = "Starting a scan", sub = "GitHub is getting a computer ready. This takes about a minute.", pct = null;
  if (running) {
    const ep = status.current && findEpisode(status.current);
    const waiting = Math.max(0, (status.queue || 1) - 1);
    const more = waiting ? ` · ${waiting} more waiting` : "";
    if (!ep) {
      title = "Checking your shows";
      sub = status.queue ? `${status.queue} episode${status.queue === 1 ? "" : "s"} to scan` : "Looking for new episodes";
    } else {
      title = ep.title;
      const st = status.stage;
      if (st === "transcribing") { pct = status.progress || 0; sub = `Transcribing · ${Math.round(pct * 100)}%${more}`; }
      else if (st === "finding ads") { sub = `Finding the ads${more}`; }
      else { sub = `Downloading${more}`; }
      sub = `${ep.show} · ${sub}`;
    }
  }
  return `<div class="section"><div class="sechead"><h2 class="h2x">Removing Ads</h2><a class="seeall" href="#scan">Details</a></div>
    <div class="card scancard" role="link" tabindex="0" onclick="location.hash='#scan'"><span class="scancard-title">${esc(title)}</span><span class="scancard-sub">${esc(sub)}</span>
    <span class="scanbar ${pct == null ? "busy" : ""}"><i style="width:${pct == null ? 100 : Math.max(3, pct * 100).toFixed(0)}%"></i></span></div></div>`;
}

// What's "new" for you: for each show, the newest episode when you followed it,
// plus everything published after that. The back catalog stays on the show's page.
function newEpisodes() {
  const added = new Map((subs?.feeds || []).map((f) => [f.url, f.added || 0]));
  const out = [];
  for (const [fid, f] of Object.entries(index?.feeds || {})) {
    const eps = [...(f.episodes || [])].sort((a, b) => b.date - a.date);
    if (!eps.length) continue;
    const since = added.get(f.url);
    // The newest episode out when you followed the show (or simply the newest one).
    const first = since ? eps.find((e) => e.date <= since) : eps[0];
    const cutoff = first ? first.date : eps[eps.length - 1].date;
    for (const e of eps) if (e.date >= cutoff) out.push({ ...e, fid, show: f.title, showImg: f.image });
  }
  return out.sort((a, b) => b.date - a.date);
}

// ---- Scans page
const STEP_LABELS = [
  ["Set up job", "Getting a computer"],
  ["Get your data", "Loading your shows"],
  ["Spot-check reported ads", "Spot-checking reported ads"],
  ["Install", "Installing the speech tools"],
  ["Scan", "Scanning episodes"],
  ["Keep the data branch small", "Tidying up"],
];
function nextAutoScan() {
  // The scan job runs at 17 minutes past every third hour, UTC.
  const now = Date.now();
  const d = new Date(now);
  d.setUTCMinutes(17, 0, 0);
  for (let i = 0; i < 30; i++) {
    if (d.getUTCHours() % 3 === 0 && d.getTime() > now) return d;
    d.setUTCHours(d.getUTCHours() + 1);
  }
  return null;
}
// "40 sec", "9 min", "1 hr 5 min"
const took = (sec) => (sec < 60 ? `${Math.max(1, Math.round(sec))} sec` : dur(sec));
const hhmm = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
function when(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000), today = new Date();
  return d.toDateString() === today.toDateString() ? hhmm(ts) : `${day(ts)} ${hhmm(ts)}`;
}
const epName = (id) => findEpisode(id)?.title || "an older episode";
const showName = (id) => findEpisode(id)?.show || "";
function eventText(e) {
  switch (e.ev) {
    case "start": return e.why === "schedule" ? "Automatic scan started" : e.why === "workflow_dispatch" ? "Scan started from the app" : "Scan started";
    case "feeds": return `Checked ${e.shows} show${e.shows === 1 ? "" : "s"}: ${e.queue ? `${e.queue} episode${e.queue === 1 ? "" : "s"} to scan` : "nothing new to scan"}${e.problems ? ` · ${e.problems} feed problem${e.problems === 1 ? "" : "s"}` : ""}`;
    case "downloaded": return `Downloaded “${epName(e.id)}” (${Math.round(e.mb)} MB in ${took(e.took)})`;
    case "transcribed": return `Transcribed ${dur(e.dur)} of audio in ${took(e.took)}${e.took ? ` (${Math.round(e.dur / e.took)}× real time)` : ""}`;
    case "ads": return `${e.n ? `Found ${e.n} ad${e.n === 1 ? "" : "s"} (${clock(e.sec)})` : "No ads found"} in “${epName(e.id)}” with ${e.det === "gemini" ? "Gemini" : "keyword rules"}`;
    case "failed": return `Couldn't scan “${epName(e.id)}”: ${e.err}`;
    case "reports": return `Spot-checked ${e.n} reported ad${e.n === 1 ? "" : "s"}`;
    case "finish": return `Finished: ${e.done} episode${e.done === 1 ? "" : "s"} scanned${e.failed ? `, ${e.failed} failed` : ""}${e.left ? `, ${e.left} left for next time` : ""}`;
    case "error": return `Stopped: ${e.err}`;
    default: return e.ev;
  }
}
const EV_ICON = { start: "▶", feeds: "↻", downloaded: "↓", transcribed: "≋", ads: "✂", failed: "!", reports: "⚑", finish: "✓", error: "!" };

function viewScan() {
  const fresh = status && Date.now() / 1000 - (status.at || 0) < 3 * 3600;
  const running = fresh && status.state === "running";
  const runActive = lastRun && lastRun.status !== "completed";
  const starting = !running && (runActive || Date.now() - dispatchedAt < 90000);
  const errored = status?.state === "error" || (!runActive && lastRun?.conclusion === "failure");
  const next = nextAutoScan();
  const lastRunInfo = (status?.runs || []).slice(-1)[0];

  // Headline
  let state = "idle", head = "Up to date", sub = status?.finished ? `Last scan finished ${ago(status.finished)}${lastRunInfo ? ` and took ${took(lastRunInfo.finished - lastRunInfo.started)}` : ""}.` : "No scans yet.";
  if (running) { state = "running"; head = "Scanning now"; sub = `Started ${ago(status.started)} · ${status.done || 0} done${status.queue ? ` · ${status.queue} to go` : ""}`; }
  else if (starting) { state = "queued"; head = "Starting a scan"; sub = "GitHub is getting a computer ready. This usually takes under a minute."; }
  else if (errored) { state = "error"; head = "The last scan had a problem"; sub = status?.error || "Open the GitHub log for details."; }
  let html = `<h1 class="largetitle">Scans</h1>
    <div class="card scanhero" data-state="${state}">
      <div class="scanhero-head"><span class="dot"></span><span class="scanhero-title">${esc(head)}</span></div>
      <p class="scanhero-sub">${esc(sub)}</p>
      ${next && !running ? `<p class="muted small">Next automatic scan around ${hhmm(next / 1000)}. GitHub sometimes starts these a little late.</p>` : ""}
      <div class="row"><button class="btn small" id="scan-now" type="button" ${running || starting ? "disabled" : ""}>${running || starting ? "Scanning…" : "Scan Now"}</button>
        <a class="btn ghost small" href="${lastRun?.html_url || `https://github.com/${esc(cfg.owner)}/${esc(cfg.repo)}/actions/workflows/scan.yml`}" target="_blank" rel="noopener">GitHub log</a></div>
    </div>`;

  // GitHub start-up steps
  if ((starting || running) && lastJobs?.run === lastRun?.id && lastJobs.steps.length) {
    const rows = STEP_LABELS.map(([name, label]) => {
      const st = lastJobs.steps.find((x) => x.name === name || x.name.startsWith(name));
      if (!st) return "";
      const secs = st.started_at && st.completed_at ? (Date.parse(st.completed_at) - Date.parse(st.started_at)) / 1000 : null;
      const mark = st.status === "completed" ? (st.conclusion === "success" ? "done" : st.conclusion === "skipped" ? "skip" : "bad") : st.status === "in_progress" ? "now" : "todo";
      return `<li class="jstep ${mark}"><span class="jmark"></span><span>${esc(label)}</span><span class="muted">${secs != null && mark !== "skip" ? took(secs) : mark === "now" ? "now" : ""}</span></li>`;
    }).join("");
    html += `<div class="section"><div class="sechead"><h2 class="h2x">On GitHub</h2></div><div class="card"><ol class="jsteps">${rows}</ol></div></div>`;
  } else if (starting) {
    html += `<div class="section"><div class="sechead"><h2 class="h2x">On GitHub</h2></div><div class="card"><ol class="jsteps"><li class="jstep now"><span class="jmark"></span><span>Waiting for a computer</span><span class="muted">now</span></li></ol></div></div>`;
  }

  // The episode being scanned
  if (running && status.current) {
    const ep = findEpisode(status.current);
    const steps = [["downloading", "Download"], ["transcribing", "Transcribe"], ["finding ads", "Find ads"]];
    const at = Math.max(0, steps.findIndex(([k]) => k === status.stage));
    const nowS = Date.now() / 1000;
    let pct = null, left = null;
    if (status.stage === "downloading" && status.total) pct = Math.min(1, (status.got || 0) / status.total);
    if (status.stage === "transcribing") {
      pct = status.progress || 0;
      const spent = (status.at || nowS) - (status.stage_at || status.at || nowS);
      if (pct > 0.03 && spent > 0) left = Math.max(0, (spent * (1 - pct)) / pct - (nowS - status.at));
      else if (status.audio && status.speed) left = status.audio / status.speed;
      else if (status.audio) left = status.audio / 20;
    }
    const kv = [
      ["Step", `${steps[at][1]} · for ${took(nowS - (status.stage_at || status.ep_started || nowS))}`],
      status.total || status.got ? ["Download", status.stage === "downloading" ? `${mb(status.got || 0)}${status.total ? ` of ${mb(status.total)}` : ""}` : mb(status.total || status.got)] : null,
      status.audio ? ["Length", dur(status.audio)] : null,
      status.speed && status.stage !== "downloading" ? ["Speed", `${Math.round(status.speed)}× real time`] : null,
      left != null ? ["Time left", left < 60 ? "under a minute" : `about ${dur(left)}`] : null,
      ["Started", ago(status.ep_started || status.stage_at)],
    ].filter(Boolean);
    html += `<div class="section"><div class="sechead"><h2 class="h2x">Now Scanning</h2></div>
      <div class="card nowcard">
        <div class="nowcard-top">${artImg(ep?.img || ep?.showImg, ep?.show, "art nowcard-art")}<div class="nowcard-titles"><span class="nowcard-show">${esc(ep?.show || "")}</span><span class="nowcard-title">${esc(ep?.title || "An episode")}</span></div></div>
        <ol class="tracker">${steps.map(([, label], i) => `<li class="${i < at ? "done" : i === at ? "now" : ""}"><span></span>${label}</li>`).join("")}<li class=""><span></span>Ready</li></ol>
        <span class="scanbar ${pct == null ? "busy" : ""}"><i style="width:${pct == null ? 100 : Math.max(3, pct * 100).toFixed(0)}%"></i></span>
        ${pct != null ? `<span class="nowcard-pct">${Math.round(pct * 100)}%</span>` : ""}
        <dl class="kv">${kv.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join("")}</dl>
      </div></div>`;
  }

  // What's queued in this run
  const queued = (status?.queue_ids || []).map(findEpisode).filter(Boolean);
  if (running && queued.length) {
    html += `<div class="section"><div class="sechead"><h2 class="h2x">Up Next in This Scan</h2><span class="muted small">${queued.length}</span></div>
      <div class="card qlist">${queued.slice(0, 8).map((e, i) => `<div class="qrow"><span class="qn">${i + 1}</span>${artImg(e.img || e.showImg, e.show, "art qart")}<span class="qtext"><span class="qtitle">${esc(e.title)}</span><span class="qsub">${esc(e.show)} · ${esc(dur(e.dur))} · about ${scanMinutes(e)} min</span></span></div>`).join("")}
      ${queued.length > 8 ? `<p class="muted small" style="margin:6px 0 0">and ${queued.length - 8} more</p>` : ""}</div></div>`;
  }

  // Requests waiting for the next scan
  const done = index?.reports_done || {};
  const waitingReports = (subs?.reports || []).filter((r) => !done[r.id]);
  const waitingEps = [...new Set([...(subs?.want || []), ...Object.keys(subs?.rescan || {})])]
    .map(findEpisode).filter(Boolean).filter((e) => !["ads", "clean"].includes(epState(e).kind) && !(status?.queue_ids || []).includes(e.id) && status?.current !== e.id);
  if (waitingReports.length || waitingEps.length) {
    html += `<div class="section"><div class="sechead"><h2 class="h2x">Waiting</h2></div><div class="card qlist">
      ${waitingEps.map((e) => `<div class="qrow"><span class="qn">•</span>${artImg(e.img || e.showImg, e.show, "art qart")}<span class="qtext"><span class="qtitle">${esc(e.title)}</span><span class="qsub">Scan requested · ${esc(e.show)}</span></span></div>`).join("")}
      ${waitingReports.map((r) => `<div class="qrow"><span class="qn">⚑</span><span class="qtext" style="grid-column: span 2"><span class="qtitle">Spot check at ${clock(r.t)}</span><span class="qsub">${esc(epName(r.ep))} · waiting for the next scan</span></span></div>`).join("")}
    </div></div>`;
  }

  // Timeline
  const log = [...(status?.log || [])].reverse().slice(0, 30);
  if (log.length) {
    html += `<div class="section"><div class="sechead"><h2 class="h2x">Activity</h2></div><div class="card"><ol class="timeline">
      ${log.map((e) => `<li class="ev ev-${esc(e.ev)}"><span class="ev-ico">${EV_ICON[e.ev] || "•"}</span><span class="ev-text">${esc(eventText(e))}</span><time>${esc(when(e.at))}</time></li>`).join("")}
    </ol></div></div>`;
  }

  // Recently scanned
  const recent = Object.entries(index?.scanned || {}).sort((a, b) => b[1].at - a[1].at).slice(0, 10).map(([id, sc]) => ({ ep: findEpisode(id), sc })).filter((x) => x.ep);
  if (recent.length) {
    html += `<div class="section"><div class="sechead"><h2 class="h2x">Recently Scanned</h2></div><div class="card qlist">
      ${recent.map(({ ep, sc }) => `<div class="qrow tap" data-open="${esc(ep.id)}">${artImg(ep.img || ep.showImg, ep.show, "art qart")}<span class="qtext"><span class="qtitle">${esc(ep.title)}</span><span class="qsub">${sc.n ? `${sc.n} ad${sc.n === 1 ? "" : "s"} cut (${clock(sc.sec)})` : "No ads found"} · ${sc.det === "keywords" ? "keyword rules" : "Gemini"} · ${esc(ago(sc.at))}</span></span></div>`).join("")}
    </div></div>`;
  }

  // Failures
  const failed = Object.entries(index?.failed || {}).map(([id, f]) => ({ ep: findEpisode(id), f })).filter((x) => x.ep);
  if (failed.length) {
    html += `<div class="section"><div class="sechead"><h2 class="h2x">Couldn't Scan</h2></div><div class="card qlist">
      ${failed.map(({ ep, f }) => `<div class="qrow"><span class="qn">!</span><span class="qtext"><span class="qtitle">${esc(ep.title)}</span><span class="qsub">${esc(f.err || "Unknown problem")} · tried ${f.tries}×</span></span><button class="chip fail" type="button" data-scan="${esc(ep.id)}" data-again="1">Retry</button></div>`).join("")}
    </div></div>`;
  }

  // History
  const runs = [...(status?.runs || [])].reverse();
  if (runs.length) {
    html += `<div class="section"><div class="sechead"><h2 class="h2x">Past Scans</h2></div><div class="card"><ol class="history">
      ${runs.map((r) => `<li><span>${esc(when(r.started))}</span><span class="muted">${took(r.finished - r.started)}</span><span>${r.done ? `${r.done} scanned` : "nothing new"}${r.failed ? ` · ${r.failed} failed` : ""}</span></li>`).join("")}
    </ol></div></div>`;
  }

  view.innerHTML = html;
  $("#scan-now").onclick = () => scanNow().then(() => { if (location.hash === "#scan") viewScan(); });
  $$("[data-open]").forEach((r) => (r.onclick = () => openEpisode(r.dataset.open, false)));
  bindRowTools();
  if (!lastJobs || lastJobs.run !== lastRun?.id) refreshJobs().then(() => { if (location.hash === "#scan" && lastJobs?.steps?.length && (starting || running)) viewScan(); });
  if (running || starting) startPolling();
}

function emptyHome() {
  const pending = (subs?.feeds || []).length;
  return pending
    ? `<div class="empty"><span class="splice"></span><h2 class="h1">Fetching your shows</h2><p class="lede">The first scan is getting your episodes. This page fills in when it's done, usually within a few minutes.</p></div>`
    : `<div class="empty"><span class="splice"></span><h2 class="h1">No shows yet</h2><p class="lede">Add a podcast and Podskip will scan its newest episodes for ads.</p><a class="btn" href="#search">Find a show</a></div>`;
}

// Up Next: what you're in the middle of, then each show's newest episode you haven't finished.
function upNext(eps, newer = eps) {
  const byId = new Map(eps.map((e) => [e.id, e]));
  const going = Object.entries(progress)
    .filter(([id, p]) => byId.has(id) && !p.done && p.t > 10)
    .sort((a, b) => (b[1].at || 0) - (a[1].at || 0))
    .map(([id]) => byId.get(id));
  const used = new Set(going.map((e) => e.id));
  const shows = new Set(going.map((e) => e.fid));
  const next = [];
  for (const e of [...newer].sort((a, b) => b.date - a.date)) {
    if (used.has(e.id) || shows.has(e.fid) || progress[e.id]?.done) continue;
    shows.add(e.fid);
    next.push(e);
  }
  return [...going, ...next].slice(0, 10);
}
function upCard(ep) {
  const p = progress[ep.id];
  const resuming = p && !p.done && p.t > 10;
  return `<div class="upcard" role="button" tabindex="0" data-ep="${esc(ep.id)}">
    <div class="upcard-top">${artImg(ep.img || ep.showImg, ep.show, "art upcard-art")}
      <div class="upcard-head"><span class="upcard-eyebrow">${resuming ? "Resume" : esc(day(ep.date) || "New")}</span><span class="upcard-show">${esc(ep.show)}</span></div></div>
    <span class="upcard-title">${esc(ep.title)}</span>
    <span class="upcard-foot">${playPill(ep)}${adChip(ep)}<span class="ep2-tools">${dlButton(ep)}</span></span>
  </div>`;
}

function viewHome() {
  const eps = allEpisodes();
  let html = `<h1 class="largetitle">Home</h1>` + scanCard();
  if (!eps.length) {
    view.innerHTML = html + emptyHome();
    return;
  }
  const fresh = newEpisodes();
  const up = upNext(eps, fresh);
  if (up.length) html += `<div class="section"><div class="sechead"><h2 class="h2x">Up Next</h2></div><div class="carousel" id="carousel">${up.map(upCard).join("")}</div></div>`;
  const latest = fresh;
  html += `<div class="section"><div class="sechead"><h2 class="h2x">Latest Episodes</h2>${latest.length > 6 ? `<a class="seeall" href="#latest">See All</a>` : ""}</div>
    <div class="list">${latest.slice(0, 6).map((e) => epRow(e)).join("")}</div></div>`;
  const keep = $("#carousel")?.scrollLeft || 0;
  view.innerHTML = html;
  const c = $("#carousel");
  if (c) c.scrollLeft = keep;
  bindEpRows();
}

function viewLatest() {
  const eps = newEpisodes();
  view.innerHTML = `<h1 class="largetitle">Latest Episodes</h1>` + (eps.length ? `<div class="list">${eps.slice(0, 80).map((e) => epRow(e)).join("")}</div>` : emptyHome());
  bindEpRows();
}

function viewDownloaded() {
  const eps = Object.keys(dlIndex).map(findEpisode).filter(Boolean).sort((a, b) => (dlIndex[b.id].at || 0) - (dlIndex[a.id].at || 0));
  const total = Object.values(dlIndex).reduce((s, d) => s + (d.bytes || 0), 0);
  view.innerHTML = `<h1 class="largetitle">Downloaded</h1>` + (eps.length
    ? `<p class="muted small" style="margin:0 0 4px">${eps.length} episode${eps.length === 1 ? "" : "s"} · ${mb(total)} on this phone. Remove them in Settings.</p><div class="list">${eps.map((e) => epRow(e)).join("")}</div>`
    : `<div class="empty"><h2 class="h1">Nothing downloaded</h2><p class="lede">Open an episode and tap Download to listen without a connection.</p></div>`);
  bindEpRows();
}

function viewLibrary() {
  const feeds = subs?.feeds || [];
  const dls = Object.keys(dlIndex).filter((id) => findEpisode(id)).length;
  const chev = `<svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>`;
  view.innerHTML = `<h1 class="largetitle">Library</h1>
    <nav class="menu" aria-label="Library">
      <a class="menu-row" href="#latest"><span class="menu-ico"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg></span><span class="menu-label">Latest Episodes</span>${chev}</a>
      <a class="menu-row" href="#downloaded"><span class="menu-ico"><svg viewBox="0 0 24 24"><path d="M12 4v11m0 0-4.5-4.5M12 15l4.5-4.5M5 19h14"/></svg></span><span class="menu-label">Downloaded</span><span class="menu-n">${dls || ""}</span>${chev}</a>
    </nav>
    <div class="section"><div class="sechead"><h2 class="h2x">Shows</h2><a class="seeall" href="#search">Add</a></div>
    ${feeds.length ? `<div class="grid2" id="tiles"></div>` : `<p class="muted">No shows yet. <a href="#search">Find one to add</a>.</p>`}</div>`;
  if (!feeds.length) return;
  Promise.all(feeds.map(async (f) => {
    const fid = await sha1hex(f.url, 12);
    const live = index?.feeds?.[fid];
    const title = live?.title || f.title;
    const newest = live?.episodes?.[0];
    const sub = !live ? `<span class="chip busy">Fetching</span>` : live.error ? `<span class="chip fail">Feed problem</span>` : newest ? `<span class="tile-sub">Updated ${esc(/^(Today|Yesterday)$/.test(day(newest.date)) ? day(newest.date).toLowerCase() : day(newest.date))}</span>` : "";
    return `<a class="tile" href="#show-${fid}">${artImg(live?.image || f.image, title)}<span class="tile-name">${esc(title)}</span>${sub}</a>`;
  })).then((t) => {
    const el = $("#tiles");
    if (!el) return;
    el.innerHTML = t.join("");
    $$(".tile", el).forEach((a) => {
      const fid = a.getAttribute("href").slice(6);
      a.addEventListener("click", (e) => { if (justHeld(a)) e.preventDefault(); });
      onHold(a, () => showMenu(fid));
    });
  });
}

async function viewShow(fid) {
  const f = index?.feeds?.[fid];
  let sub = null;
  for (const s of subs?.feeds || []) if ((await sha1hex(s.url, 12)) === fid) sub = s;
  if (!f && !sub) { location.hash = "#shows"; return; }
  const title = f?.title || sub.title;
  chrome("show-" + fid, title);
  const eps = (f?.episodes || []).map((e) => ({ ...e, fid, show: title, showImg: f.image }));
  const latest = eps[0];
  view.innerHTML = `<div class="showhero">
      ${artImg(f?.image || sub?.image, title, "art showhero-art")}
      <h1 class="showhero-title">${esc(title)}</h1>
      ${f?.author || sub?.author ? `<p class="showhero-by">${esc(f?.author || sub?.author)}</p>` : ""}
      <div class="showhero-actions">
        ${latest ? `<button class="btn bigplay" id="playlatest" type="button">${ICON_PLAY}<span>${progress[latest.id] && !progress[latest.id].done && progress[latest.id].t > 10 ? "Resume" : "Latest Episode"}</span></button>` : ""}
        <button class="iconbtn big" id="showmore" type="button" aria-label="More options for this show">${ICON_MORE}</button>
      </div>
      ${f?.desc ? `<p class="showhero-desc" id="sdesc">${esc(f.desc)}</p>` : ""}
    </div>
    ${f?.error ? `<div class="card"><p class="err">Podskip couldn't read this show's feed last time: ${esc(f.error)}</p></div>` : ""}
    <div class="section"><div class="sechead"><h2 class="h2x">Episodes</h2><span class="muted small">${eps.length || ""}</span></div>
      ${eps.length ? `<div class="list">${eps.map((e) => epRow(e, false)).join("")}</div>` : `<p class="muted">Episodes appear after the next scan.</p>`}
    </div>
    <div class="section"><button class="btn danger small" id="unsub" type="button" style="justify-self:start">Remove Show</button></div>`;
  bindEpRows();
  const pl = $("#playlatest");
  if (pl) pl.onclick = () => openEpisode(latest.id, true);
  const d = $("#sdesc");
  if (d) d.onclick = () => d.classList.toggle("open");
  $("#showmore").onclick = () => showMenu(fid);
  $("#unsub").onclick = async (ev) => {
    const b = ev.currentTarget;
    if (b.dataset.sure !== "1") { b.dataset.sure = "1"; b.textContent = "Tap again to remove"; return; }
    b.disabled = true;
    if (!(await removeShow(fid))) b.disabled = false;
  };
}

async function removeShow(fid) {
  try {
    let url = index?.feeds?.[fid]?.url;
    for (const s of subs?.feeds || []) if ((await sha1hex(s.url, 12)) === fid) url = s.url;
    await changeSubs((s) => { s.feeds = s.feeds.filter((x) => x.url !== url); }, "Remove a show");
    if (index?.feeds) delete index.feeds[fid];
    LS.set("index", index);
    toast("Show removed");
    if (location.hash === "#show-" + fid) location.hash = "#shows"; else rerenderIfList();
    return true;
  } catch (e) { handleErr(e); return false; }
}

// ---- actions shared by rows, menus and the player
async function scanEpisode(ep, again, quietToast) {
  try {
    const now = Math.floor(Date.now() / 1000);
    await changeSubs((s) => {
      s.want = [ep.id, ...(s.want || []).filter((x) => x !== ep.id)].slice(0, 20);
      if (again) {
        const r = { ...(s.rescan && typeof s.rescan === "object" ? s.rescan : {}), [ep.id]: now };
        s.rescan = Object.fromEntries(Object.entries(r).sort((a, b) => b[1] - a[1]).slice(0, 20));
      }
    }, again ? "Rescan an episode" : "Scan an episode");
    if (!quietToast) toast(`Scanning “${ep.title}”. It takes about ${scanMinutes(ep)} minutes.`);
    scanNow(true);
    rerenderIfList();
    return true;
  } catch (e) { handleErr(e); return false; }
}
const scanMinutes = (ep) => Math.ceil((ep?.dur || 3600) / 60 / 20) + 3;
function markPlayed(ep, done) {
  if (done) progress[ep.id] = { t: ep.dur || 1, d: ep.dur || 1, done: true, at: Date.now() };
  else delete progress[ep.id];
  saveProgress();
  rerenderIfList();
  if (done) cleanupPlayed(false, "Marked as played");
}

// ---- menus
const ICONS = {
  play: ICON_PLAY, pause: ICON_PAUSE, dl: ICON_DL,
  scan: `<svg viewBox="0 0 24 24"><path d="M4 7V5a1 1 0 0 1 1-1h2M17 4h2a1 1 0 0 1 1 1v2M20 17v2a1 1 0 0 1-1 1h-2M7 20H5a1 1 0 0 1-1-1v-2M7 12h10"/></svg>`,
  both: `<svg viewBox="0 0 24 24"><path d="M4 7V5a1 1 0 0 1 1-1h2M17 4h2a1 1 0 0 1 1 1v2M12 8v8m0 0-3-3m3 3 3-3"/></svg>`,
  check: `<svg viewBox="0 0 24 24"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>`,
  undo: `<svg viewBox="0 0 24 24"><path d="M9 7 4.5 11.5 9 16"/><path d="M5 11.5h9a5 5 0 0 1 0 10h-2"/></svg>`,
  show: `<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M10 9.5v5l4-2.5z"/></svg>`,
  trash: `<svg viewBox="0 0 24 24"><path d="M5 7h14M10 7V5h4v2M7 7l1 13h8l1-13"/></svg>`,
  stop: `<svg viewBox="0 0 24 24"><rect x="6.5" y="6.5" width="11" height="11" rx="2"/></svg>`,
};
function openSheet({ art, title, sub, actions }) {
  const sh = $("#sheet");
  $("#sheet-head").innerHTML = `${art || ""}<div class="sheet-titles"><span class="sheet-title" id="sheet-title">${esc(title)}</span>${sub ? `<span class="sheet-sub">${esc(sub)}</span>` : ""}</div>`;
  const box = $("#sheet-actions");
  box.innerHTML = actions.filter(Boolean).map((a, i) => `<button class="sheet-btn ${a.danger ? "danger" : ""}" type="button" data-i="${i}" ${a.disabled ? "disabled" : ""}>${ICONS[a.icon] || ""}<span>${esc(a.label)}</span></button>`).join("");
  const list = actions.filter(Boolean);
  $$(".sheet-btn", box).forEach((b) => (b.onclick = () => {
    const a = list[+b.dataset.i];
    if (a.confirm && b.dataset.sure !== "1") { b.dataset.sure = "1"; $("span", b).textContent = a.confirm; return; }
    closeSheet();
    a.run();
  }));
  sh.hidden = false;
  document.body.classList.add("sheet-open");
  setTimeout(() => $(".sheet-btn:not([disabled])", box)?.focus({ preventScroll: true }), 50);
}
function closeSheet() { $("#sheet").hidden = true; document.body.classList.remove("sheet-open"); }
$("#sheet").addEventListener("click", (e) => { if (e.target.id === "sheet") closeSheet(); });
$("#sheet-cancel").onclick = closeSheet;
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#sheet").hidden) closeSheet(); });

function episodeMenu(id) {
  const ep = findEpisode(id);
  if (!ep) return;
  const st = epState(ep);
  const playing = player.ep?.id === id && !audio.paused;
  const p = progress[id];
  const scanned = st.kind === "ads" || st.kind === "clean";
  const busy = st.kind === "scanning" || st.kind === "queued";
  const job = dlJobs[id], have = dlIndex[id];
  openSheet({
    art: artImg(ep.img || ep.showImg, ep.show, "art sheet-art"),
    title: ep.title,
    sub: [ep.show, day(ep.date), dur(ep.dur)].filter(Boolean).join(" · "),
    actions: [
      { icon: playing ? "pause" : "play", label: playing ? "Pause" : p && !p.done && p.t > 10 ? "Resume" : "Play", run: () => (playing ? audio.pause() : player.open(id, true, false)) },
      busy ? { icon: "scan", label: st.kind === "scanning" ? "Scanning now…" : "Waiting to be scanned", disabled: true }
        : { icon: "scan", label: scanned ? "Scan Again" : "Scan for Ads", run: () => scanEpisode(ep, scanned || st.kind === "failed") },
      job ? { icon: "stop", label: "Cancel Download", run: () => job.ctrl.abort() }
        : have ? { icon: "trash", label: "Remove Download", danger: true, confirm: "Tap again to remove", run: async () => { await removeDownload(id, true); toast("Download removed"); rerenderIfList(); player.paintDl(); } }
        : { icon: "dl", label: "Download", run: () => startDownload(ep) },
      !scanned && !busy && !have && !job ? { icon: "both", label: "Scan & Download", run: async () => { if (await scanEpisode(ep, st.kind === "failed", true)) toast(`Scanning and downloading “${ep.title}”.`); startDownload(ep); } } : null,
      p?.done ? { icon: "undo", label: "Mark as Unplayed", run: () => markPlayed(ep, false) } : { icon: "check", label: "Mark as Played", run: () => markPlayed(ep, true) },
      location.hash === "#show-" + ep.fid ? null : { icon: "show", label: "Go to Show", run: () => { closePlayerIfOpen(); location.hash = "#show-" + ep.fid; } },
    ],
  });
}

function showMenu(fid) {
  const f = index?.feeds?.[fid];
  const eps = (f?.episodes || []).map((e) => ({ ...e, fid, show: f.title, showImg: f.image }));
  const latest = eps[0];
  openSheet({
    art: artImg(f?.image, f?.title || "Show", "art sheet-art"),
    title: f?.title || "This show",
    sub: f?.author || "",
    actions: [
      latest ? { icon: "play", label: "Play Latest Episode", run: () => player.open(latest.id, true, false) } : null,
      latest ? { icon: "scan", label: "Scan Newest Episodes", run: async () => { for (const e of eps.slice(0, 3)) if (epState(e).kind === "none") await scanEpisode(e, false, true); scanNow(true); toast("Scanning this show's newest episodes."); } } : null,
      latest && !dlIndex[latest.id] && !dlJobs[latest.id] ? { icon: "dl", label: "Download Latest Episode", run: () => startDownload(latest) } : null,
      eps.length ? { icon: "check", label: "Mark All as Played", run: () => { eps.forEach((e) => { progress[e.id] = { t: e.dur || 1, d: e.dur || 1, done: true, at: Date.now() }; }); saveProgress(); rerenderIfList(); toast("Marked all as played"); cleanupPlayed(true); } } : null,
      location.hash === "#show-" + fid ? null : { icon: "show", label: "Go to Show", run: () => (location.hash = "#show-" + fid) },
      { icon: "trash", label: "Remove Show", danger: true, confirm: "Tap again to remove this show", run: () => removeShow(fid) },
    ],
  });
}
function closePlayerIfOpen() { if (!$("#player").hidden) $("#player-close").click(); }

// ---- search
let searchSeq = 0;
function itunes(params) {
  const qs = new URLSearchParams({ ...params }).toString();
  const url = `https://itunes.apple.com/${params.id ? "lookup" : "search"}?${qs}`;
  return fetch(url).then((r) => { if (!r.ok) throw new Error(); return r.json(); }).catch(() => jsonp(url));
}
function jsonp(url) {
  return new Promise((resolve, reject) => {
    const cb = "psjsonp" + Math.random().toString(36).slice(2);
    const s = document.createElement("script");
    const done = () => { delete window[cb]; s.remove(); };
    window[cb] = (data) => { done(); resolve(data); };
    s.onerror = () => { done(); reject(new Error("Search isn't reachable right now.")); };
    s.src = url + "&callback=" + cb;
    document.head.appendChild(s);
    setTimeout(() => { if (window[cb]) { done(); reject(new Error("Search took too long.")); } }, 12000);
  });
}

function viewSearch() {
  view.innerHTML = `<div class="section">
    <h1 class="largetitle">Search</h1>
    <form class="searchbar" id="sform" role="search">
      <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>
      <input class="input" id="q" type="search" placeholder="Search podcasts" autocomplete="off" enterkeyhint="search" aria-label="Search podcasts">
    </form>
    <p class="muted small">You can also paste an RSS feed link or an Apple Podcasts link.</p>
    <div id="results" class="list"></div>
  </div>`;
  const q = $("#q");
  let t;
  const run = () => search(q.value.trim());
  q.oninput = () => { clearTimeout(t); t = setTimeout(run, 350); };
  $("#sform").onsubmit = (e) => { e.preventDefault(); q.blur(); run(); };
  setTimeout(() => q.focus(), 50);
}

async function search(term) {
  const out = $("#results");
  if (!out) return;
  const seq = ++searchSeq;
  if (!term) { out.innerHTML = ""; return; }
  let items = [];
  try {
    const apple = term.match(/podcasts\.apple\.com\/.*\bid(\d+)/i);
    if (apple) {
      items = (await itunes({ id: apple[1], entity: "podcast" })).results || [];
    } else if (/^https?:\/\//i.test(term)) {
      items = [{ feedUrl: term, collectionName: "Podcast feed", artistName: term }];
    } else {
      out.innerHTML = `<div class="skeleton"></div><div class="skeleton"></div>`;
      items = (await itunes({ term, media: "podcast", entity: "podcast", limit: 25 })).results || [];
    }
  } catch (e) {
    if (seq === searchSeq) out.innerHTML = `<p class="err">${esc(e.message || "Search failed.")} Paste a feed link instead.</p>`;
    return;
  }
  if (seq !== searchSeq) return;
  items = items.filter((i) => i.feedUrl);
  if (!items.length) { out.innerHTML = `<p class="muted">No podcasts found for “${esc(term)}”.</p>`; return; }
  const have = new Set((subs?.feeds || []).map((f) => f.url));
  out.innerHTML = items.map((i, n) => `<div class="result">
      ${artImg(i.artworkUrl600 || i.artworkUrl100, i.collectionName)}
      <div class="result-text"><span class="result-name">${esc(i.collectionName)}</span><span class="result-by">${esc(i.artistName || "")}</span></div>
      <button class="btn small ${have.has(i.feedUrl) ? "secondary" : ""}" type="button" data-n="${n}" ${have.has(i.feedUrl) ? "disabled" : ""}>${have.has(i.feedUrl) ? "Added" : "Add"}</button>
    </div>`).join("");
  $$("[data-n]", out).forEach((b) => (b.onclick = async () => {
    const i = items[+b.dataset.n];
    b.disabled = true; b.textContent = "Adding…";
    try {
      await changeSubs((s) => {
        if (!s.feeds.some((f) => f.url === i.feedUrl)) s.feeds.push({ url: i.feedUrl, title: i.collectionName, author: i.artistName || "", image: i.artworkUrl600 || i.artworkUrl100 || "", added: Math.floor(Date.now() / 1000) });
      }, "Add a show");
      b.textContent = "Added"; b.classList.add("secondary");
      toast(`Added ${i.collectionName}. Scanning its newest episodes now.`);
      scanNow(true);
    } catch (e) { handleErr(e); b.disabled = false; b.textContent = "Add"; }
  }));
}

// ---- settings
function viewSettings() {
  const per = subs?.perShow || 3;
  const gem = index?.notes?.gemini;
  const usedKeywords = Object.values(index?.scanned || {}).some((s) => s.det === "keywords");
  view.innerHTML = `
  <h1 class="largetitle">Settings</h1>
  <div class="section"><h2 class="h2">What to skip</h2>
    <div class="card" style="gap:0;padding-block:6px">
      ${toggleRow("sponsor", "Ads and sponsor reads", "Ad breaks, host-read ads, “brought to you by”")}
      ${toggleRow("promo", "Promos for other shows", "Trailers and network plugs")}
      ${toggleRow("self", "The show's own plugs", "Patreon, merch, “leave a review”")}
    </div>
  </div>
  <div class="section"><h2 class="h2">While listening</h2>
    <div class="card" style="gap:10px">
      <div class="setting" style="padding:0;border:0;flex-wrap:wrap"><span class="setting-text">Sound when an ad is skipped<small>Tap one to hear it.</small></span>
        <span class="seg" id="sound">${[["off", "Off"], ...Object.entries(SOUNDS)].map(([k, v]) => `<button type="button" aria-pressed="${prefs.sound === k}" data-sound="${k}">${v}</button>`).join("")}</span></div>
    </div>
  </div>
  <div class="section"><h2 class="h2">Scanning</h2>
    <div class="card">
      <div class="setting" style="padding-top:0"><span class="setting-text">Episodes to scan per show<small>Newest episodes first. Older ones can be scanned one at a time from the player.</small></span>
        <span class="seg" id="perShow">${[1, 2, 3, 5].map((n) => `<button type="button" aria-pressed="${n === per}" data-n="${n}">${n}</button>`).join("")}</span></div>
      <dl class="kv">
        <dt>Last scan</dt><dd>${status?.finished ? ago(status.finished) : "not yet"}${status?.state === "running" ? " (running now)" : ""}</dd>
        <dt>Ad finder</dt><dd>${cfg.gemini ? "Gemini (free tier)" : "Keyword rules only"}</dd>
      </dl>
      ${status?.state === "error" ? `<p class="err">${esc(status.error)}</p>` : ""}
      ${gem ? `<p class="err">Gemini had a problem on the last scan, so keyword rules were used: ${esc(gem)}</p>` : ""}
      ${!cfg.gemini && usedKeywords ? `<p class="muted small">Keyword rules only catch obvious ads. Add a free Gemini key below for much better results.</p>` : ""}
      <div class="row"><button class="btn small" id="scan" type="button">Scan now</button>
      <a class="btn ghost small" href="#scan">Scan details</a></div>
    </div>
  </div>
  <div class="section"><h2 class="h2">Keys</h2>
    <div class="card">
      <div class="field"><label for="gem">Gemini API key</label>
        <input class="input" id="gem" type="password" autocomplete="off" placeholder="Paste a key from Google AI Studio" value="${esc(cfg.gemini || "")}"></div>
      <p class="muted small">Get one free at <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener">aistudio.google.com/apikey</a>. After changing it, update your GitHub secret.</p>
      <div class="row"><button class="btn small secondary" id="gemsave" type="button">Save key</button></div>
      <hr style="border:0;border-top:1px solid var(--line);width:100%;margin:4px 0">
      <p class="small">Your <b>PODSKIP_KEY</b> secret value. Paste it into GitHub whenever you change the Gemini key, or into the app on another device.</p>
      <div class="secretbox" id="secret">${esc(secretValue())}</div>
      <div class="row"><button class="btn small secondary" id="copysecret" type="button">Copy</button>
      <a class="btn ghost small" href="${secretsUrl()}" target="_blank" rel="noopener">Open GitHub secrets</a></div>
    </div>
  </div>
  <div class="section"><h2 class="h2">Downloads</h2>
    <div class="card" style="gap:10px">${prefRow("autoDl", "Download new episodes", "The newest episode of each show you follow, while Podskip is open")}
      ${prefRow("cleanDl", "Remove played downloads", "When you finish an episode or mark it played")}
      ${(() => {
      const ids = Object.keys(dlIndex);
      if (!ids.length) return `<p class="small muted">Nothing downloaded yet.</p>`;
      const total = ids.reduce((s, k) => s + (dlIndex[k].bytes || 0), 0);
      return `<p class="small">${ids.length} episode${ids.length === 1 ? "" : "s"} · ${mb(total)} on this phone</p>
        <div class="row"><button class="btn danger small" id="dl-clear" type="button">Remove all downloads</button></div>`;
    })()}</div>
  </div>
  <div class="section"><h2 class="h2">Notifications</h2>
    <div class="card" id="notif-card" style="gap:10px"><p class="muted small">Checking…</p></div>
  </div>
  <div class="section"><h2 class="h2">This device</h2>
    <div class="card">
      <dl class="kv"><dt>Repository</dt><dd>${esc(cfg.owner)}/${esc(cfg.repo)}</dd></dl>
      <div class="row"><button class="btn danger small" id="signout" type="button">Disconnect this phone</button></div>
      <p class="muted small">Disconnecting removes your token and key from this phone. Your shows stay on GitHub.</p>
    </div>
  </div>`;
  $$("[data-skip]").forEach((i) => (i.onchange = () => { prefs.skip[i.dataset.skip] = i.checked; savePrefs(); player.refreshAds(); }));
  $$("[data-pref]").forEach((i) => (i.onchange = () => {
    prefs[i.dataset.pref] = i.checked; savePrefs();
    if (i.checked && i.dataset.pref === "autoDl") { autoDlFull = false; autoDownload(); }
    if (i.checked && i.dataset.pref === "cleanDl") cleanupPlayed();
  }));
  $$("[data-sound]").forEach((b) => (b.onclick = () => {
    prefs.sound = b.dataset.sound; savePrefs();
    $$("[data-sound]").forEach((x) => x.setAttribute("aria-pressed", x === b));
    playSkipSound();
  }));
  $$("#perShow button").forEach((b) => (b.onclick = async () => {
    $$("#perShow button").forEach((x) => x.setAttribute("aria-pressed", x === b));
    try { await changeSubs((s) => { s.perShow = +b.dataset.n; }, "Change scan depth"); scanNow(true); toast("Saved"); } catch (e) { handleErr(e); }
  }));
  $("#scan").onclick = () => scanNow();
  paintNotifCard();
  const clr = $("#dl-clear");
  if (clr) clr.onclick = async () => {
    if (clr.dataset.sure !== "1") { clr.dataset.sure = "1"; clr.textContent = "Tap again to remove them all"; return; }
    clr.disabled = true;
    for (const id of Object.keys(dlIndex)) await removeDownload(id, true);
    toast("Downloads removed");
    viewSettings();
  };
  $("#copysecret").onclick = (e) => copyText(secretValue(), e.currentTarget);
  $("#gemsave").onclick = () => {
    cfg.gemini = $("#gem").value.trim(); LS.set("cfg", cfg);
    $("#secret").textContent = secretValue();
    toast("Saved. Now copy the new secret value into GitHub.");
  };
  $("#signout").onclick = (e) => {
    const b = e.currentTarget;
    if (b.dataset.sure !== "1") { b.dataset.sure = "1"; b.textContent = "Tap again to disconnect"; return; }
    ["cfg", "index", "status", "current"].forEach(LS.del);
    location.hash = ""; location.reload();
  };
}
function prefRow(k, title, sub) {
  return `<div class="setting"><span class="setting-text">${esc(title)}<small>${esc(sub)}</small></span>
    <span class="switch"><input type="checkbox" role="switch" data-pref="${k}" ${prefs[k] ? "checked" : ""} aria-label="${esc(title)}"><span></span></span></div>`;
}
function toggleRow(k, title, sub) {
  return `<div class="setting"><span class="setting-text">${esc(title)}<small>${esc(sub)}</small></span>
    <span class="switch"><input type="checkbox" role="switch" id="skip-${k}" data-skip="${k}" ${prefs.skip[k] ? "checked" : ""} aria-label="Skip ${esc(title)}"><span></span></span></div>`;
}

// ---- setup
let setup = LS.get("setup", {});
function viewSetup() {
  $("#dock").hidden = true;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent);
  const installed = navigator.standalone || matchMedia("(display-mode: standalone)").matches;
  if (ios && !installed && !setup.skipInstall) {
    view.innerHTML = `<div class="section"><h1 class="h1">Put Podskip on your Home Screen first</h1>
      <p class="lede">The Home Screen app keeps its own storage, so set it up from there. It also gets the lock-screen player.</p>
      <div class="card"><ol class="howto">
        <li>Tap the <b>Share</b> button in Safari.</li>
        <li>Choose <b>Add to Home Screen</b>, then <b>Add</b>.</li>
        <li>Open <b>Podskip</b> from your Home Screen.</li>
      </ol></div>
      <button class="btn ghost" id="skipinstall" type="button">Set it up in Safari instead</button></div>`;
    $("#skipinstall").onclick = () => { setup.skipInstall = true; LS.set("setup", setup); viewSetup(); };
    return;
  }
  const owner = cfg?.owner || where.owner;
  const repo = cfg?.repo || where.repo || "podskip";
  const tokenUrl = "https://github.com/settings/personal-access-tokens/new?" + new URLSearchParams({
    name: "Podskip", description: "Lets the Podskip app on my phone save shows and start scans.",
    target_name: owner || "", expires_in: "366", contents: "write", actions: "write", secrets: "read",
  }).toString();
  const step = cfg?.token ? (cfg?.geminiDone ? 3 : 2) : 1;
  view.innerHTML = `<div class="section"><h1 class="h1">Set up Podskip</h1>
    <p class="lede">Three steps, all on this phone. Everything here is free.</p></div>
  <div class="section steps">
    <div class="card step"><span class="step-n ${step > 1 ? "done" : ""}">${step > 1 ? "✓" : 1}</span><div class="step-body">
      <h3>Connect GitHub</h3>
      ${step === 1 ? `<p class="muted small">This lets the app save your shows to your repo and start scans.</p>
      <ol class="howto small">
        <li><a href="${esc(tokenUrl)}" target="_blank" rel="noopener">Open the token page</a> (the details are filled in).</li>
        <li>Under <b>Repository access</b>, pick <b>Only select repositories</b> and choose <b>${esc(repo)}</b>.</li>
        <li>Tap <b>Generate token</b>, copy it, and paste it here.</li>
      </ol>
      <div class="field"><label for="repo">Repository</label><input class="input" id="repo" value="${esc(owner ? owner + "/" + repo : "")}" placeholder="username/podskip" autocapitalize="off" autocorrect="off"></div>
      <div class="field"><label for="token">Token</label><input class="input" id="token" type="password" placeholder="github_pat_…" autocomplete="off"></div>
      <p class="err" id="err1" hidden></p>
      <button class="btn" id="go1" type="button">Connect</button>` : `<p class="ok">Connected to ${esc(cfg.owner)}/${esc(cfg.repo)}</p>`}
    </div></div>

    <div class="card step"><span class="step-n ${step > 2 ? "done" : ""}">${step > 2 ? "✓" : 2}</span><div class="step-body">
      <h3>Free AI for finding ads</h3>
      ${step === 2 ? `<p class="muted small">Google's Gemini reads each transcript and marks the ads, the summary and the chapters. The free tier covers personal use.</p>
      <ol class="howto small">
        <li><a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener">Open Google AI Studio</a> and sign in.</li>
        <li>Tap <b>Create API key</b>, copy it, and paste it here.</li>
      </ol>
      <div class="field"><label for="gemkey">Gemini API key</label><input class="input" id="gemkey" type="password" placeholder="AIza…" autocomplete="off"></div>
      <p class="err" id="err2" hidden></p>
      <div class="row"><button class="btn" id="go2" type="button">Check key</button><button class="btn ghost" id="nogem" type="button">Skip for now</button></div>
      <p class="muted small">Skipping uses simple keyword rules, which miss many ads.</p>` : step > 2 ? `<p class="ok">${cfg.gemini ? "Gemini key saved" : "Using keyword rules"}</p>` : ""}
    </div></div>

    <div class="card step"><span class="step-n">3</span><div class="step-body">
      <h3>Save your key to GitHub</h3>
      ${step === 3 ? stepThree() : `<p class="muted small">Your scans are encrypted with a key that only this app and your GitHub secret know.</p>`}
    </div></div>
  </div>`;

  if (step === 1) $("#go1").onclick = connectGitHub;
  if (step === 2) {
    $("#go2").onclick = checkGemini;
    $("#nogem").onclick = () => { cfg.gemini = ""; cfg.geminiDone = true; LS.set("cfg", cfg); viewSetup(); };
  }
  if (step === 3) bindStepThree();
}

async function connectGitHub() {
  const err = $("#err1"); err.hidden = true;
  const [owner, repo] = $("#repo").value.trim().replace(/^https?:\/\/github\.com\//i, "").split("/");
  const token = $("#token").value.trim();
  if (!owner || !repo || !token) { err.textContent = "Fill in the repository and the token."; err.hidden = false; return; }
  const b = $("#go1"); b.disabled = true; b.textContent = "Checking…";
  cfg = { ...(cfg || {}), owner, repo, token };
  try {
    const r = await ghJson(`/repos/${owner}/${repo}`);
    if (!r.permissions?.push) throw new Error("This token can't save to that repo. Give it Contents: Read and write.");
    cfg.hasData = await dataBranchExists();
    LS.set("cfg", cfg);
    // Reconnecting with a new token: keep the existing key and data.
    if (cfg.key && cfg.hasData && cfg.geminiDone) {
      try { await refreshSubs(); cfg.ready = true; LS.set("cfg", cfg); return afterSetup(); } catch {}
    }
    viewSetup();
  } catch (e) {
    cfg.token = null;
    err.textContent = e instanceof AuthError ? "GitHub didn't accept that token. Copy it again." : e.status === 404 ? `Can't see ${owner}/${repo}. Check the name, and that the token has access to it.` : e.message;
    err.hidden = false; b.disabled = false; b.textContent = "Connect";
  }
}

async function checkGemini() {
  const err = $("#err2"); err.hidden = true;
  const k = $("#gemkey").value.trim();
  if (!k) { err.textContent = "Paste your key, or tap Skip for now."; err.hidden = false; return; }
  const b = $("#go2"); b.disabled = true; b.textContent = "Checking…";
  try {
    const r = await fetch("https://generativelanguage.googleapis.com/v1beta/models?pageSize=1&key=" + encodeURIComponent(k));
    if (r.status === 400 || r.status === 403) throw new Error("Google didn't accept that key. Copy it again.");
    if (!r.ok) throw new Error(`Google answered with an error (${r.status}). Try again in a minute.`);
    cfg.gemini = k; cfg.geminiDone = true; LS.set("cfg", cfg); viewSetup();
  } catch (e) {
    err.textContent = e.message.startsWith("Google") ? e.message : "Couldn't reach Google. Check your connection.";
    err.hidden = false; b.disabled = false; b.textContent = "Check key";
  }
}

function stepThree() {
  if (cfg.hasData && !cfg.key && !setup.fresh) {
    return `<p class="small">This repo is already set up, maybe from another phone. Paste your <b>PODSKIP_KEY</b> value from that phone's Settings.</p>
      <div class="field"><label for="oldkey">PODSKIP_KEY value</label><input class="input" id="oldkey" autocomplete="off" autocapitalize="off" placeholder="psk1.…"></div>
      <p class="err" id="err3" hidden></p>
      <div class="row"><button class="btn" id="usekey" type="button">Use this key</button><button class="btn ghost" id="fresh" type="button">Start over</button></div>
      <p class="muted small">Starting over makes a new key. You'll add your shows again and old scans get redone.</p>`;
  }
  if (!cfg.key) { cfg.key = newKey(); setup.keyAt = Date.now(); LS.set("setup", setup); LS.set("cfg", cfg); }
  const secretUrl = setup.fresh ? secretsUrl() : `${secretsUrl()}/new`;
  return `<p class="small">Copy this value, then ${setup.fresh ? "replace your" : "add it as a"} secret named <b>PODSKIP_KEY</b>${setup.fresh ? " with it" : ""}.</p>
    <div class="secretbox">${esc(secretValue())}</div>
    <div class="row"><button class="btn secondary small" id="copy3" type="button">Copy value</button></div>
    <ol class="howto small">
      <li><a href="${secretUrl}" target="_blank" rel="noopener">Open the secret page</a>.</li>
      <li>${setup.fresh ? "Tap the pencil next to <b>PODSKIP_KEY</b> and paste the value" : "Name: <b>PODSKIP_KEY</b>. Secret: paste the value"}.</li>
      <li>Tap <b>${setup.fresh ? "Update secret" : "Add secret"}</b>, then come back here.</li>
    </ol>
    <p class="err" id="err3" hidden></p>
    <button class="btn" id="finish" type="button">I added it</button>`;
}

function bindStepThree() {
  const copy = $("#copy3");
  if (copy) copy.onclick = (e) => copyText(secretValue(), e.currentTarget);
  const fresh = $("#fresh");
  if (fresh) fresh.onclick = () => { setup.fresh = true; LS.set("setup", setup); viewSetup(); };
  const use = $("#usekey");
  if (use) use.onclick = async () => {
    const err = $("#err3"); err.hidden = true;
    const v = $("#oldkey").value.trim();
    const parts = v.startsWith("psk1.") ? v.split(".") : ["", v, ""];
    cfg.key = parts[1]; aesKey = null;
    if (!cfg.gemini && parts[2]) cfg.gemini = parts.slice(2).join(".");
    try {
      await refreshSubs();
      cfg.ready = true; LS.set("cfg", cfg); afterSetup();
    } catch {
      cfg.key = null; aesKey = null;
      err.textContent = "That key doesn't open this repo's data. Check you copied all of it."; err.hidden = false;
    }
  };
  const fin = $("#finish");
  if (fin) fin.onclick = async () => {
    const err = $("#err3"); err.hidden = true;
    fin.disabled = true; fin.textContent = "Checking…";
    try {
      const r = await gh(`${repoPath()}/actions/secrets/PODSKIP_KEY`);
      if (r.status === 404) throw new Error("GitHub doesn't have a PODSKIP_KEY secret yet. Check the name is exactly PODSKIP_KEY.");
      if (r.ok && setup.fresh && setup.keyAt) {
        const j = await r.json();
        if (Date.parse(j.updated_at) < setup.keyAt - 60000) throw new Error("The PODSKIP_KEY secret still has its old value. Paste the new value into it and tap Update secret.");
      }
      if (setup.fresh || !(await dataBranchExists())) await createDataBranch();
      else await refreshSubs();
      setup = {}; LS.set("setup", setup);
      cfg.ready = true; cfg.hasData = true; LS.set("cfg", cfg);
      afterSetup();
    } catch (e) {
      err.textContent = e instanceof AuthError ? "GitHub didn't accept your token." : e.message; err.hidden = false;
      fin.disabled = false; fin.textContent = "I added it";
    }
  };
}

function afterSetup() {
  $("#dock").hidden = false;
  location.hash = "#search";
  route();
  boot();
}

// ------------------------------------------------------------------ notifications
// The phone subscribes to Web Push with a key pair this app makes. The private
// half is saved encrypted on the data branch so the scanner can send pushes.
const pushSupported = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
const b64url = (bytes) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (str) => unb64(str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4));
function swReady() {
  return Promise.race([navigator.serviceWorker.ready, sleep(6000).then(() => { throw new Error("The app's background helper isn't running yet. Close Podskip and open it again."); })]);
}
function sameBytes(a, b) {
  if (!a || !b) return false;
  a = new Uint8Array(a); b = new Uint8Array(b);
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

async function paintNotifCard() {
  const card = $("#notif-card");
  if (!card) return;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent);
  const installed = navigator.standalone || matchMedia("(display-mode: standalone)").matches;
  if (!pushSupported()) {
    card.innerHTML = `<p class="small">${ios && !installed ? "Notifications only work in the Home Screen app. Open Podskip from your Home Screen to turn them on." : "This browser can't show notifications from Podskip."}</p>`;
    return;
  }
  let sub = null;
  try { sub = await (await swReady()).pushManager.getSubscription(); } catch {}
  const perm = Notification.permission;
  const on = perm === "granted" && !!sub;
  card.innerHTML = `<div class="setting" style="padding:0;border:0"><span class="setting-text">When ads are removed<small>A notification each time an episode is scanned, with how many ads were cut.</small></span>
      <span class="switch"><input type="checkbox" role="switch" id="notif" ${on ? "checked" : ""} ${perm === "denied" ? "disabled" : ""} aria-label="Notify me when ads are removed"><span></span></span></div>
    ${perm === "denied" ? `<p class="err">Notifications are blocked for Podskip. Turn them on in your iPhone's Settings → Notifications → Podskip, then come back here.</p>` : ""}
    ${on ? `<div class="row"><button class="btn small secondary" id="notif-test" type="button">Send a test</button></div>` : ""}`;
  if (!card.isConnected) return; // you left Settings while it was checking
  $("#notif", card).onchange = (e) => (e.target.checked ? enableNotifications(e.target) : disableNotifications(e.target));
  const t = $("#notif-test", card);
  if (t) t.onclick = () => { scanNow(true, true); toast("Test sent. It should arrive in a minute or two."); };
}

async function enableNotifications(input) {
  let perm;
  // Ask first, straight from the tap: iOS only shows the prompt for a direct tap.
  try { perm = await Notification.requestPermission(); } catch { perm = Notification.permission; }
  if (perm !== "granted") {
    input.checked = false;
    toast(perm === "denied" ? "Notifications are blocked. You can allow them in iPhone Settings." : "Notifications weren't turned on.");
    return paintNotifCard();
  }
  input.disabled = true;
  try {
    const reg = await swReady();
    await changeEnc("push.enc", () => ({ v: 1, subs: [] }), async (p) => {
      if (!p.vapid || !p.pub) {
        const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
        p.vapid = { d: jwk.d, x: jwk.x, y: jwk.y };
        p.pub = b64url(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
      }
      const appKey = unb64url(p.pub);
      let sub = await reg.pushManager.getSubscription();
      if (sub && !sameBytes(sub.options?.applicationServerKey, appKey)) { await sub.unsubscribe(); sub = null; }
      if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: appKey });
      const j = sub.toJSON();
      p.subs = (p.subs || []).filter((x) => x.endpoint !== j.endpoint);
      p.subs.push({ endpoint: j.endpoint, keys: j.keys, added: Math.floor(Date.now() / 1000) });
    }, "Turn on notifications");
    toast("Notifications are on");
  } catch (e) {
    input.checked = false;
    handleErr(e);
  }
  paintNotifCard();
}

async function disableNotifications(input) {
  input.disabled = true;
  try {
    const reg = await swReady();
    const sub = await reg.pushManager.getSubscription();
    if (sub) {
      const endpoint = sub.endpoint;
      await changeEnc("push.enc", () => ({ v: 1, subs: [] }), (p) => { p.subs = (p.subs || []).filter((x) => x.endpoint !== endpoint); }, "Turn off notifications");
      await sub.unsubscribe();
    }
    toast("Notifications are off");
  } catch (e) {
    input.checked = true;
    handleErr(e);
  }
  paintNotifCard();
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.addEventListener("message", (e) => {
    if (e.data?.open) { location.hash = e.data.open; }
  });
}

// ------------------------------------------------------------------ errors
function handleErr(e) {
  if (e instanceof AuthError) return authProblem();
  if (e instanceof KeyMismatch) return showShowsKeyProblem();
  toast(e.message || "Something went wrong.");
}
function authProblem() {
  const b = $("#banner");
  b.hidden = false;
  b.innerHTML = `<div class="card"><p><b>GitHub stopped accepting your token.</b> It may have expired. Make a new one and connect again.</p>
    <div class="row"><button class="btn small" id="reauth" type="button">Connect again</button></div></div>`;
  $("#reauth").onclick = () => { cfg.token = null; cfg.ready = false; LS.set("cfg", cfg); b.hidden = true; location.hash = ""; viewSetup(); };
}
const secretsUrl = () => `https://github.com/${esc(cfg.owner)}/${esc(cfg.repo)}/settings/secrets/actions`;
function secretSteps() {
  return `<div class="secretbox">${esc(secretValue())}</div>
    <div class="row"><button class="btn small secondary" type="button" data-copysecret>Copy value</button>
    <a class="btn small ghost" href="${secretsUrl()}" target="_blank" rel="noopener">Open GitHub secrets</a></div>
    <p class="muted small">On that page, tap the pencil next to <b>PODSKIP_KEY</b> (or <b>New repository secret</b> if it isn't there), paste the value, and save.</p>`;
}
function bindSecretSteps(root) {
  $$("[data-copysecret]", root).forEach((b) => (b.onclick = () => copyText(secretValue(), b)));
}

// The shows saved on GitHub were encrypted with a different key than this phone has.
function showShowsKeyProblem() {
  const b = $("#banner");
  if (!b.hidden && b.dataset.kind === "shows") return;
  b.dataset.kind = "shows";
  b.hidden = false;
  b.innerHTML = `<div class="card">
    <p><b>This phone can't open the shows saved on GitHub.</b> They were saved with a different key. That usually happens when Podskip gets set up twice, like once in Safari and once from the Home Screen, because each keeps its own storage.</p>
    <div class="row"><button class="btn small" id="km-reset" type="button">Start fresh with this phone's key</button>
    <button class="btn small ghost" id="km-paste" type="button">Paste the other key</button></div>
    <p class="muted small" id="km-hint">Starting fresh clears the list of shows saved on GitHub. You'd add them again.</p>
    <div id="km-more"></div></div>`;
  $("#km-reset").onclick = async (ev) => {
    const btn = ev.currentTarget;
    if (btn.dataset.sure !== "1") { btn.dataset.sure = "1"; btn.textContent = "Tap again to start fresh"; return; }
    btn.disabled = true; btn.textContent = "Starting fresh…";
    try {
      await createDataBranch();
      index = null; LS.del("index"); status = null; LS.del("status"); episodes.clear();
      b.innerHTML = `<div class="card"><p class="ok">Done. Your shows now save with this phone's key.</p>
        <p class="small">One more step so scans can read them: put this value in your <b>PODSKIP_KEY</b> secret on GitHub.</p>
        ${secretSteps()}
        <div class="row"><button class="btn small" id="km-done" type="button">I updated it</button></div></div>`;
      bindSecretSteps(b);
      $("#km-done").onclick = () => { b.hidden = true; b.dataset.kind = ""; route(); };
    } catch (e) {
      btn.disabled = false; btn.dataset.sure = ""; btn.textContent = "Start fresh with this phone's key";
      handleErr(e);
    }
  };
  $("#km-paste").onclick = () => {
    $("#km-hint").hidden = true;
    $("#km-more").innerHTML = `<div class="field"><label for="km-key">PODSKIP_KEY value from your other setup</label>
      <input class="input" id="km-key" autocomplete="off" autocapitalize="off" autocorrect="off" placeholder="psk1.…"></div>
      <p class="err" id="km-err" hidden></p>
      <div class="row"><button class="btn small" id="km-use" type="button">Use this key</button></div>`;
    $("#km-use").onclick = async () => {
      const v = $("#km-key").value.trim();
      const parts = v.startsWith("psk1.") ? v.split(".") : ["", v, ""];
      const old = { key: cfg.key, gemini: cfg.gemini };
      cfg.key = parts[1]; aesKey = null;
      try {
        await refreshSubs();
        if (parts[2] && !cfg.gemini) cfg.gemini = parts.slice(2).join(".");
        LS.set("cfg", cfg);
        b.hidden = true; b.dataset.kind = "";
        toast("Key updated");
        boot();
      } catch (e) {
        Object.assign(cfg, old); aesKey = null;
        const err = $("#km-err");
        err.textContent = e instanceof KeyMismatch ? "That key doesn't open these shows either. Check you copied all of it." : e.message;
        err.hidden = false;
      }
    };
  };
}

// The scanner's secret doesn't match this phone's key.
function showSecretProblem() {
  const b = $("#banner");
  if (!b.hidden && (b.dataset.kind === "secret" || b.dataset.kind === "shows")) return;
  b.dataset.kind = "secret";
  b.hidden = false;
  b.innerHTML = `<div class="card"><p><b>Scans can't read your shows yet.</b> The PODSKIP_KEY secret on GitHub doesn't match this phone's key. Put this value in it:</p>
    ${secretSteps()}
    <div class="row"><button class="btn small" id="sp-scan" type="button">I updated it, scan now</button></div></div>`;
  bindSecretSteps(b);
  $("#sp-scan").onclick = () => { b.hidden = true; b.dataset.kind = ""; scanNow(); };
}

// ------------------------------------------------------------------ scan status pill
function paintPill() {
  const pill = $("#scanpill");
  if (!cfg?.ready) { pill.hidden = true; return; }
  pill.hidden = false;
  let state = "idle", text = status?.finished ? `Scanned ${ago(status.finished)}` : "Not scanned yet";
  const runActive = lastRun && (lastRun.status === "queued" || lastRun.status === "in_progress" || lastRun.status === "waiting" || lastRun.status === "pending");
  if (status?.state === "running" && Date.now() / 1000 - (status.at || 0) < 3 * 3600) {
    state = "running"; text = status.queue ? `Scanning · ${status.queue} left` : "Scanning";
  } else if (runActive) {
    state = "queued"; text = "Starting scan";
  } else if (status?.state === "error" || lastRun?.conclusion === "failure") {
    state = "error"; text = "Scan problem";
  }
  pill.dataset.state = state;
  $("#scanpill-text").textContent = text;
}
$("#scanpill").onclick = () => (location.hash = "#scan");

let pollTimer = null;
function startPolling() {
  if (pollTimer) return;
  const tick = async () => {
    pollTimer = null;
    const onScanPage = location.hash === "#scan";
    try {
      await Promise.all([refreshIndex(), refreshRun().then(() => (onScanPage ? refreshJobs() : null))]);
    } catch (e) { if (e instanceof AuthError) return authProblem(); }
    paintPill();
    rerenderIfList();
    player.retryAnalysis();
    const busy = status?.state === "running" || (lastRun && lastRun.status !== "completed") || Date.now() - dispatchedAt < 90000;
    if (busy && document.visibilityState === "visible") pollTimer = setTimeout(tick, onScanPage ? 8000 : 15000);
  };
  pollTimer = setTimeout(tick, 4000);
}
function rerenderIfList() {
  const h = location.hash.replace("#", "") || "listen";
  if (["listen", "shows", "latest", "downloaded", "scan"].includes(h) || h.startsWith("show-")) {
    const y = window.scrollY;
    route();
    window.scrollTo(0, y);
  }
}

// ------------------------------------------------------------------ skip sound
// Short sounds made on the phone with Web Audio, so there's nothing to download.
// iOS only lets a page make sound after a tap, so the first tap anywhere wakes it.
let actx = null;
function soundCtx() {
  try {
    if (!actx) { const C = window.AudioContext || window.webkitAudioContext; if (!C) return null; actx = new C(); }
    if (actx.state !== "running") actx.resume().catch(() => {});
    return actx;
  } catch { return null; }
}
["touchend", "click"].forEach((ev) => document.addEventListener(ev, () => { if (prefs.sound !== "off") soundCtx(); }, { passive: true }));

const SOUNDS = { chime: "Chime", tick: "Tick", swoosh: "Swoosh" };
function playSkipSound(kind = prefs.sound) {
  if (!kind || kind === "off") return;
  const ctx = soundCtx();
  if (!ctx) return;
  const t0 = ctx.currentTime + 0.02;
  const out = ctx.createGain();
  out.gain.value = 0.9;
  out.connect(ctx.destination);
  const tone = (freq, at, len, type = "sine", vol = 0.22) => {
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.type = type; o.frequency.setValueAtTime(freq, at);
    g.gain.setValueAtTime(0.0001, at);
    g.gain.exponentialRampToValueAtTime(vol, at + 0.012);
    g.gain.exponentialRampToValueAtTime(0.0001, at + len);
    o.connect(g).connect(out); o.start(at); o.stop(at + len + 0.02);
  };
  if (kind === "chime") {
    tone(784, t0, 0.16); tone(1175, t0 + 0.09, 0.28);           // G5 then D6
  } else if (kind === "tick") {
    tone(1900, t0, 0.035, "square", 0.08); tone(2500, t0 + 0.06, 0.035, "square", 0.07);
  } else if (kind === "swoosh") {
    const len = 0.32, buf = ctx.createBuffer(1, Math.ceil(ctx.sampleRate * len), ctx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < d.length; i++) d[i] = Math.random() * 2 - 1;
    const src = ctx.createBufferSource(), f = ctx.createBiquadFilter(), g = ctx.createGain();
    src.buffer = buf; f.type = "bandpass"; f.Q.value = 1.2;
    f.frequency.setValueAtTime(500, t0); f.frequency.exponentialRampToValueAtTime(4500, t0 + len);
    g.gain.setValueAtTime(0.0001, t0); g.gain.exponentialRampToValueAtTime(0.35, t0 + 0.08); g.gain.exponentialRampToValueAtTime(0.0001, t0 + len);
    src.connect(f).connect(g).connect(out); src.start(t0); src.stop(t0 + len + 0.02);
  }
}

// ------------------------------------------------------------------ downloads
// Episodes are saved in this app's own storage (IndexedDB) in 8 MB pieces, so a
// big file never has to sit in memory all at once. A download needs the
// podcast's server to allow web apps to fetch it; most do.
const idb = (() => {
  let dbp;
  const open = () => dbp || (dbp = new Promise((res, rej) => {
    const r = indexedDB.open("podskip", 1);
    r.onupgradeneeded = () => { const db = r.result; for (const n of ["parts", "audio", "analysis"]) db.createObjectStore(n); };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  }));
  const run = async (store, mode, fn) => {
    const db = await open();
    return new Promise((res, rej) => {
      const t = db.transaction(store, mode);
      const req = fn(t.objectStore(store));
      t.oncomplete = () => res(req && "result" in req ? req.result : undefined);
      t.onerror = () => rej(t.error || new Error("Storage error"));
      t.onabort = () => rej(t.error || new Error("Storage is full"));
    });
  };
  return {
    get: (st, k) => run(st, "readonly", (o) => o.get(k)),
    put: (st, k, v) => run(st, "readwrite", (o) => o.put(v, k)),
    del: (st, k) => run(st, "readwrite", (o) => o.delete(k)),
    range: (st, lo, hi) => run(st, "readonly", (o) => o.getAll(IDBKeyRange.bound(lo, hi))),
    delRange: (st, lo, hi) => run(st, "readwrite", (o) => o.delete(IDBKeyRange.bound(lo, hi))),
  };
})();
const partKey = (id, n) => `${id}:${String(n).padStart(5, "0")}`;
let dlIndex = LS.get("downloads", {}); // epId -> { bytes, at }
let allSync = LS.get("sync", {}); // epId -> [{ x: scanned time, d: seconds your stream runs later }]
let spots = LS.get("spots", {}); // reportId -> { ep, at }: spot checks this phone is waiting on
let allMatched = LS.get("matched", {}); // epId -> { k: which copy, r: { anchors, gaps } } from matching by sound
let allMarks = LS.get("marks", {}); // epId -> [{ rid, s, e }] ads you reported, in this phone's timeline
const saveDlIndex = () => LS.set("downloads", dlIndex);
let dlBlocked = LS.get("dlBlocked", {}); // feedId -> true when a download was refused
const dlUrls = {}; // epId -> blob: URL ready to play
const dlBlobs = {}; // epId -> the downloaded file itself
const dlJobs = {}; // epId -> { got, total, ctrl }
const mb = (n) => (n >= 1e9 ? (n / 1e9).toFixed(1) + " GB" : Math.max(1, Math.round(n / 1e6)) + " MB");
function audioType(url, header) {
  const h = (header || "").split(";")[0].trim();
  if (h.startsWith("audio/") || h.startsWith("video/")) return h;
  const ext = (url.match(/\.(mp3|m4a|aac|mp4|ogg|opus|wav)(\?|$)/i) || [])[1]?.toLowerCase();
  return { m4a: "audio/mp4", mp4: "audio/mp4", aac: "audio/aac", ogg: "audio/ogg", opus: "audio/ogg", wav: "audio/wav" }[ext] || "audio/mpeg";
}

async function prepareDownload(id) {
  if (dlUrls[id]) return dlUrls[id];
  const rec = await idb.get("audio", id);
  if (!rec) { delete dlIndex[id]; saveDlIndex(); return null; }
  const parts = await idb.range("parts", `${id}:`, `${id}:\uffff`);
  dlBlobs[id] = new Blob(parts, { type: rec.type });
  dlUrls[id] = URL.createObjectURL(dlBlobs[id]);
  return dlUrls[id];
}
function prepareAllDownloads() {
  return Promise.all(Object.keys(dlIndex).map((id) => prepareDownload(id).catch(() => {})));
}

let dlPaintAt = 0;
function dlChanged(force) {
  if (!force && Date.now() - dlPaintAt < 300) return;
  dlPaintAt = Date.now();
  player.paintDl();
  // Update download buttons in lists without redrawing the page.
  for (const id of new Set([...Object.keys(dlJobs), ...$$("[data-dl]", view).map((b) => b.dataset.dl)])) {
    const ep = findEpisode(id);
    $$(`.ep2-tools [data-dl="${CSS.escape(id)}"], .ep2-tools .done`, view).forEach((b) => {
      if (b.matches(".done") && b.closest("[data-ep]")?.dataset.ep !== id) return;
      if (ep) b.outerHTML = dlButton(ep);
    });
  }
  bindRowTools();
}

async function startDownload(ep, opts = {}) {
  if (dlJobs[ep.id] || dlIndex[ep.id]) return;
  const auto = !!opts.auto;
  if (!auto && dlDismissed[ep.id]) { delete dlDismissed[ep.id]; LS.set("dlDismissed", dlDismissed); }
  const job = (dlJobs[ep.id] = { got: 0, total: 0, ctrl: new AbortController() });
  dlChanged(true);
  try { navigator.storage?.persist?.().catch(() => {}); } catch {}
  let n = 0;
  try {
    const res = await fetch(https(ep.url), { mode: "cors", credentials: "omit", signal: job.ctrl.signal });
    if (!res.ok) throw new Error(`The podcast's server answered with an error (${res.status}). Try again later.`);
    job.total = +res.headers.get("content-length") || 0;
    const type = audioType(ep.url, res.headers.get("content-type"));
    const reader = res.body.getReader();
    let chunks = [], size = 0;
    const flush = async () => {
      if (!size) return;
      await idb.put("parts", partKey(ep.id, n++), new Blob(chunks, { type }));
      chunks = []; size = 0;
    };
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value); size += value.length; job.got += value.length;
      if (size >= 8 << 20) await flush();
      dlChanged();
    }
    await flush();
    await idb.put("audio", ep.id, { bytes: job.got, type, parts: n, at: Date.now(), title: ep.title, fid: ep.fid });
    dlIndex[ep.id] = { bytes: job.got, at: Date.now(), auto };
    saveDlIndex();
    delete dlBlocked[ep.fid]; LS.set("dlBlocked", dlBlocked);
    // Keep the ad timings with it, so skipping works offline too.
    const sc = index?.scanned?.[ep.id];
    const a = sc && episodes.get(`${ep.id}-${sc.at}-${sc.env || 0}`);
    if (a) idb.put("analysis", ep.id, a).catch(() => {});
    await prepareDownload(ep.id);
    if (player.ep?.id === ep.id) player.useLocal();
    if (!auto) toast("Downloaded. It'll play without a connection.");
    prematch();
  } catch (e) {
    await idb.delRange("parts", `${ep.id}:`, `${ep.id}:\uffff`).catch(() => {});
    if (auto) {
      // Automatic downloads fail quietly and try again later; a show that refuses web apps is remembered.
      autoDlFailed[ep.id] = Date.now();
      if (e instanceof TypeError && job.got === 0 && navigator.onLine) { dlBlocked[ep.fid] = true; LS.set("dlBlocked", dlBlocked); }
      if ((e.name === "QuotaExceededError" || /full|quota/i.test(e.message || "")) && !autoDlFull) { autoDlFull = true; toast("Your iPhone is out of space, so new episodes aren't downloading. Remove some in Settings."); }
    } else if (e.name === "AbortError") toast("Download canceled");
    else if (e.name === "QuotaExceededError" || /full|quota/i.test(e.message || "")) toast("Your iPhone is out of space for downloads. Remove some in Settings.");
    else if (e instanceof TypeError && job.got === 0 && navigator.onLine) {
      dlBlocked[ep.fid] = true; LS.set("dlBlocked", dlBlocked);
      toast("This show's server doesn't let web apps download episodes, so this one can only stream.");
    } else if (e instanceof TypeError) toast("The download stopped partway. Keep Podskip open while it downloads, then try again.");
    else toast(e.message || "The download didn't finish.");
  } finally {
    delete dlJobs[ep.id];
    dlChanged(true);
    rerenderIfList();
  }
}

// ---- automatic downloads
// While Podskip is open, the newest episode of every show you follow downloads by
// itself, one at a time, so it's ready offline and already lined up with its scan.
// When you finish an episode or mark it played, its download is removed.
let dlDismissed = LS.get("dlDismissed", {}); // epId -> true: you removed it, so don't fetch it again
const autoDlFailed = {}; // epId -> when it last failed (retried after a few minutes)
let autoDlFull = false, autoDlBusy = false;
function autoDlNext() {
  const follows = new Set((subs?.feeds || []).map((f) => f.url));
  let best = null;
  for (const [fid, f] of Object.entries(index?.feeds || {})) {
    if (!follows.has(f.url) || dlBlocked[fid]) continue;
    const ep = (f.episodes || []).reduce((a, b) => (!a || b.date > a.date ? b : a), null);
    if (!ep || dlIndex[ep.id] || dlJobs[ep.id] || progress[ep.id]?.done || dlDismissed[ep.id]) continue;
    if (Date.now() - (autoDlFailed[ep.id] || 0) < 5 * 60e3) continue;
    if (!best || ep.date > best.date) best = { ...ep, fid, show: f.title, showImg: f.image };
  }
  return best;
}
async function autoDownload() {
  if (!prefs.autoDl || autoDlBusy || autoDlFull || !cfg?.ready || !index || !subs || !navigator.onLine) return;
  autoDlBusy = true;
  try {
    for (let ep = autoDlNext(); ep && prefs.autoDl && !autoDlFull; ep = autoDlNext()) {
      await startDownload(ep, { auto: true });
      if (!dlIndex[ep.id] && !autoDlFailed[ep.id]) autoDlFailed[ep.id] = Date.now(); // canceled: leave it for now
    }
  } finally { autoDlBusy = false; }
}
// Remove downloads of episodes you've finished. The one playing keeps going: its
// audio is already loaded, so you can still hear the end.
async function cleanupPlayed(quiet, why = "Finished") {
  if (!prefs.cleanDl) return;
  const done = Object.keys(dlIndex).filter((id) => progress[id]?.done);
  for (const id of done) await removeDownload(id);
  if (!done.length) return;
  if (!quiet) {
    const ep = findEpisode(done[0]);
    toast(done.length === 1 ? `${why}, so “${ep?.title || "the episode"}” was removed from downloads.` : `Removed ${done.length} finished episodes from downloads.`);
  }
  rerenderIfList(); player.paintDl();
}

async function removeDownload(id, byYou) {
  if (byYou && dlIndex[id] && !progress[id]?.done) { dlDismissed[id] = true; LS.set("dlDismissed", dlDismissed); }
  await idb.delRange("parts", `${id}:`, `${id}:\uffff`).catch(() => {});
  await idb.del("audio", id).catch(() => {});
  await idb.del("analysis", id).catch(() => {});
  if (dlUrls[id] && player.ep?.id !== id) { URL.revokeObjectURL(dlUrls[id]); delete dlUrls[id]; }
  else delete dlUrls[id];
  delete dlBlobs[id];
  delete dlIndex[id];
  saveDlIndex();
}

// ------------------------------------------------------------------ matching your copy by sound
// Shows that stitch ads in per listener can hand your phone a different copy of
// an episode than the one the scanner heard: different ads, different lengths.
// The scanner saves a loudness fingerprint of its copy (one value per 0.1 s).
// Podskip decodes a few seconds of the copy you're actually playing and finds
// where they fit in that fingerprint. That says exactly how your copy lines up
// with the transcript, and where your copy has ads the scanner never heard.
// Works for MP3 files with a constant bitrate (most podcasts), downloaded or
// streamed from a server that lets web apps read it.
const sound = (() => {
  const HZ = 10, FLOOR = -60;
  const prints = new WeakMap();
  function printOf(a) {
    if (!a?.env) return null;
    let p = prints.get(a);
    if (p) return p;
    const s = atob(a.env), n = s.length, E = new Float32Array(n);
    for (let i = 0; i < n; i++) E[i] = Math.max(FLOOR, s.charCodeAt(i) / 3 - 80);
    const c1 = new Float64Array(n + 1), c2 = new Float64Array(n + 1);
    for (let i = 0; i < n; i++) { c1[i + 1] = c1[i] + E[i]; c2[i + 1] = c2[i] + E[i] * E[i]; }
    p = { E, c1, c2, dur: n / HZ };
    prints.set(a, p);
    return p;
  }

  // ---- comparing loudness
  function norm(env) {
    const m = env.length;
    if (m < 30) return null;
    let mu = 0; for (let i = 0; i < m; i++) mu += env[i]; mu /= m;
    let v = 0; for (let i = 0; i < m; i++) v += (env[i] - mu) ** 2;
    const sd = Math.sqrt(v / m);
    if (sd < 2) return null; // silence or a steady music bed: nothing to go on
    const q = new Float32Array(m);
    for (let i = 0; i < m; i++) q[i] = (env[i] - mu) / sd;
    return q;
  }
  function corrAt(q, P, L) {
    const m = q.length, { E, c1, c2 } = P;
    if (L < 0 || L + m > E.length) return -1;
    const mu = (c1[L + m] - c1[L]) / m, sd = Math.sqrt(Math.max(0, (c2[L + m] - c2[L]) / m - mu * mu));
    if (sd < 1) return 0;
    let s = 0;
    for (let k = 0; k < m; k++) s += q[k] * E[L + k];
    return s / (m * sd);
  }
  // Where in the scanned copy does this stretch of sound fit best?
  function locate(q, P) {
    const n = P.E.length - q.length;
    if (n < 0) return null;
    const r = new Float32Array(n + 1);
    let best = -1, bi = 0;
    for (let L = 0; L <= n; L++) { const v = (r[L] = corrAt(q, P, L)); if (v > best) { best = v; bi = L; } }
    let second = -1;
    for (let L = 0; L <= n; L++) if (Math.abs(L - bi) > 15 && r[L] > second) second = r[L];
    let x = bi;
    if (bi > 0 && bi < n) { const a = r[bi - 1], c = r[bi + 1], den = a - 2 * best + c; if (den < 0) x = bi + Math.max(-0.5, Math.min(0.5, (a - c) / (2 * den))); }
    return { x: x / HZ, r: best, margin: best - second };
  }

  // ---- reading MP3 frames
  const KBPS = {
    11: [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    12: [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    13: [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    21: [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    22: [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
  };
  const RATES = { 3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000] };
  function frame(b, i) {
    if (i < 0 || i + 4 > b.length || b[i] !== 0xff || (b[i + 1] & 0xe0) !== 0xe0) return null;
    const ver = (b[i + 1] >> 3) & 3, lay = 4 - ((b[i + 1] >> 1) & 3);
    const bi = b[i + 2] >> 4, si = (b[i + 2] >> 2) & 3, pad = (b[i + 2] >> 1) & 1;
    if (ver === 1 || lay === 4 || !bi || bi === 15 || si === 3) return null;
    const v1 = ver === 3;
    const br = KBPS[v1 ? 10 + lay : lay === 1 ? 21 : 22][bi] * 1000, sr = RATES[ver][si];
    const spf = lay === 1 ? 384 : lay === 3 && !v1 ? 576 : 1152;
    const len = lay === 1 ? (Math.floor((12 * br) / sr) + pad) * 4 : Math.floor(((spf / 8) * br) / sr) + pad;
    return { len, spf, sr, br, v1, mono: b[i + 3] >> 6 === 3, key: ver * 16 + lay * 4 + si };
  }
  // First spot at or after i where three frames in a row check out.
  function sync(b, i, key) {
    for (let j = Math.max(0, i); j + 4 <= b.length; j++) {
      const f = frame(b, j);
      if (!f || (key != null && f.key !== key)) continue;
      const g = frame(b, j + f.len);
      if (!g || g.key !== f.key) continue;
      const h = frame(b, j + f.len + g.len);
      if (h && h.key === f.key) return j;
    }
    return -1;
  }

  // ---- your copy
  async function sourceFor(ep, local) {
    let size, read;
    if (local) {
      const blob = dlBlobs[ep.id];
      if (!blob) return null;
      size = blob.size;
      read = async (a, b) => new Uint8Array(await blob.slice(a, b).arrayBuffer());
    } else {
      if (dlBlocked[ep.fid]) return null;
      let url = https(ep.url);
      const get = async (a, b) => {
        const r = await fetch(url, { mode: "cors", credentials: "omit", headers: { Range: `bytes=${a}-${b - 1}` } });
        if (r.status !== 206) { try { r.body?.cancel(); } catch {} throw new Error("This server doesn't send parts of files."); }
        url = r.url || url; // stay on the same file after redirects
        return r;
      };
      let first;
      try { first = await get(0, 65536); } catch { return null; }
      size = +((first.headers.get("content-range") || "").split("/")[1] || 0);
      const head = new Uint8Array(await first.arrayBuffer());
      if (!size) {
        // The total size isn't readable on a part, but it is on a full request.
        try {
          const ctrl = new AbortController();
          const r = await fetch(url, { mode: "cors", credentials: "omit", signal: ctrl.signal });
          size = +r.headers.get("content-length") || 0;
          ctrl.abort();
        } catch {}
      }
      read = async (a, b) => (a === 0 && b <= head.length ? head.subarray(0, b) : new Uint8Array(await (await get(a, b)).arrayBuffer()));
    }
    // Where the audio starts (after any ID3 tag) and whether the bitrate is constant.
    let start = 0;
    let b = await read(0, Math.min(size || 65536, 65536));
    if (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) start = 10 + (((b[6] & 127) << 21) | ((b[7] & 127) << 14) | ((b[8] & 127) << 7) | (b[9] & 127)) + (b[5] & 0x10 ? 10 : 0);
    let base = 0;
    if (start + 16384 > b.length) { base = start; b = await read(start, start + 65536); }
    const j = sync(b, start - base);
    if (j < 0) return null; // not MP3
    const f = frame(b, j);
    const side = f.v1 ? (f.mono ? 17 : 32) : f.mono ? 9 : 17;
    const tag = String.fromCharCode(...b.subarray(j + 4 + side, j + 8 + side));
    const vbri = String.fromCharCode(...b.subarray(j + 36, j + 40)) === "VBRI";
    let first = j, frames = 0;
    const u32 = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
    if (tag === "Xing" || tag === "Info") { first = j + f.len; if (u32(j + 8 + side) & 1) frames = u32(j + 12 + side); }
    else if (vbri) { first = j + f.len; frames = u32(j + 50); }
    const g = frame(b, first);
    if (!g) return null;
    // Constant bitrate means a time maps straight to a byte position, which lining up
    // the whole episode needs. Variable-bitrate files can still have their opening checked.
    let cbr = tag !== "Xing" && !vbri;
    for (let k = first, n = 0; cbr && n < 30; n++) { const h = frame(b, k); if (!h) break; if (h.br !== g.br) cbr = false; k += h.len; }
    const bytes = size ? size - base - first : 0;
    const dur = frames ? (frames * g.spf) / g.sr : cbr && bytes ? bytes / (g.br / 8) : 0;
    return { size, read, local, cbr, start: base + first, bps: cbr || !dur ? g.br / 8 : bytes / dur, flen: Math.ceil((g.spf / 8) * Math.max(g.br, 320000) / g.sr) + 1, key: g.key, dur };
  }

  let ctx;
  function decode(bytes) {
    const C = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    ctx = ctx || new C(1, 22050, 22050);
    const copy = bytes.slice().buffer;
    return new Promise((res, rej) => {
      const p = ctx.decodeAudioData(copy, res, rej);
      if (p && p.catch) p.catch(rej);
    });
  }
  function envOf(buf) {
    const hop = Math.round(buf.sampleRate / HZ), n = Math.floor(buf.length / hop);
    const chs = [];
    for (let c = 0; c < buf.numberOfChannels; c++) chs.push(buf.getChannelData(c));
    const k = chs.length, out = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      let s = 0;
      for (let j = i * hop, e = j + hop; j < e; j++) { let v = 0; for (let c = 0; c < k; c++) v += chs[c][j]; v /= k; s += v * v; }
      out[i] = Math.max(FLOOR, 10 * Math.log10(s / hop + 1e-10));
    }
    return out;
  }
  // Loudness of your copy from time t for `len` seconds: { t0: exact start, env }
  async function listen(S, t, len) {
    const a = Math.max(S.start, Math.floor(S.start + Math.max(0, t) * S.bps));
    const b = Math.min(S.size || Infinity, Math.ceil(S.start + (Math.max(0, t) + len) * S.bps) + 3 * S.flen);
    const bytes = await S.read(a, b);
    const j = sync(bytes, 0, S.key);
    if (j < 0) throw new Error("No audio frames here");
    const buf = await decode(bytes.subarray(j));
    return { t0: (a + j - S.start) / S.bps, env: envOf(buf) };
  }

  // ---- lining up
  // Does your copy at time t play the scanned copy's sound at t - d? true / false / null (too quiet to tell)
  async function matchesAt(S, P, t, d, len = 6) {
    const p = await listen(S, t, len);
    const q = norm(p.env);
    if (!q) return null;
    return corrAt(q, P, Math.round((p.t0 - d) * HZ)) >= 0.6;
  }
  // Fine pass over a short window: per 0.1 s, does it match offset d1 (before) and d2 (after)?
  // Returns the last moment of d1 sound (u1) and the first moment of d2 sound (u2).
  async function fine(S, P, lo, hi, d1, d2) {
    lo = Math.max(0, lo);
    const p = await listen(S, lo, hi - lo);
    const env = p.env, n = env.length, T = 4;
    const at = (k, d) => { const i = Math.round((p.t0 + k / HZ - d) * HZ); return i >= 0 && i < P.E.length ? P.E[i] : null; };
    const gain = (d, from, to) => {
      const diffs = [];
      for (let k = Math.max(0, from); k < Math.min(n, to); k++) { const e = at(k, d); if (e != null && e > FLOOR + 15 && env[k] > FLOOR + 15) diffs.push(env[k] - e); }
      diffs.sort((x, y) => x - y);
      return diffs.length > 5 ? diffs[diffs.length >> 1] : 0;
    };
    const score = (d, g) => {
      const s = new Float32Array(n);
      for (let k = 0; k < n; k++) { const e = at(k, d); s[k] = e == null ? -T : T - Math.min(Math.abs(env[k] - e - g), 2 * T); }
      return s;
    };
    const s1 = d1 != null ? score(d1, gain(d1, 0, 40)) : null;
    const s2 = d2 != null ? score(d2, gain(d2, n - 40, n)) : null;
    const pre = new Float64Array(n + 1), suf = new Float64Array(n + 1);
    for (let k = 0; k < n; k++) pre[k + 1] = pre[k] + (s1 ? s1[k] : 0);
    for (let k = n - 1; k >= 0; k--) suf[k] = suf[k + 1] + (s2 ? s2[k] : 0);
    const minGap = d1 != null && d2 != null ? Math.max(0, Math.round((d2 - d1) * HZ)) : 0;
    let best = -Infinity, k1 = 0, k2 = n, bestPre = -Infinity, bestPreAt = 0;
    for (let b = 0; b <= n; b++) {
      const a = b - minGap;
      if (a >= 0 && pre[a] > bestPre) { bestPre = pre[a]; bestPreAt = a; }
      if (a < 0) continue;
      const v = (s1 ? bestPre : 0) + (s2 ? suf[b] : 0);
      if (v > best) { best = v; k1 = s1 ? bestPreAt : b; k2 = b; }
    }
    if (!s2) k2 = k1;
    return { u1: p.t0 + k1 / HZ, u2: p.t0 + k2 / HZ };
  }
  // Last moment your copy plays offset-d sound, searching from lo (known) toward hi.
  async function endOf(S, P, d, lo, hi) {
    while (hi - lo > 20) {
      const m = (lo + hi) / 2;
      if ((await matchesAt(S, P, m, d)) !== false) lo = m + 6; else hi = m + 6;
    }
    return (await fine(S, P, lo - 4, hi + 4, d, null)).u1;
  }
  // First moment your copy plays offset-d sound, searching back from hi (known) toward lo.
  async function startOf(S, P, d, lo, hi) {
    while (hi - lo > 20) {
      const m = (lo + hi) / 2;
      if ((await matchesAt(S, P, m, d)) !== false) hi = m + 2; else lo = m;
    }
    return (await fine(S, P, lo - 4, hi + 4, null, d)).u2;
  }
  // Somewhere between lo and hi, offset d1 turns into d2 (with maybe an ad of yours in between).
  async function between(S, P, d1, d2, lo, hi) {
    while (hi - lo > 20) {
      const m = (lo + hi) / 2;
      const p = await listen(S, m, 6);
      const q = norm(p.env);
      const r1 = q ? corrAt(q, P, Math.round((p.t0 - d1) * HZ)) : 0, r2 = q ? corrAt(q, P, Math.round((p.t0 - d2) * HZ)) : 0;
      if (r1 >= 0.6 && r1 >= r2) lo = m + 6;
      else if (r2 >= 0.6) hi = m;
      else return { u1: await endOf(S, P, d1, lo, m + 6), u2: await startOf(S, P, d2, m, hi) };
    }
    return fine(S, P, lo - 4, hi + 4, d1, d2);
  }
  // A few seconds of your copy at t: where are they in the scanned copy?
  // { d: your copy runs d seconds later } / { d: null } (not in the scanned copy) / null (can't tell)
  async function where(S, P, t, len = 10) {
    const p = await listen(S, t, len);
    const q = norm(p.env);
    if (!q) return null;
    const hit = locate(q, P);
    if (hit && hit.r >= 0.75 && hit.margin >= 0.12) return { t0: p.t0, d: p.t0 - hit.x, r: hit.r };
    return hit && hit.r < 0.5 ? { t0: p.t0, d: null } : null;
  }

  // The whole episode: { anchors: [{ x: scanned time, d }], gaps: [{ s, e }] in your copy's time }
  async function align(S, P, dur, ads = [], alive = () => true) {
    const W = 10, step = Math.min(300, Math.max(120, dur / 12));
    const pts = [];
    for (let t = 15; t < dur - W - 5; t += step) pts.push(t);
    if (dur > 60) pts.push(dur - W - 20);
    let hits = [];
    for (const t of pts) {
      if (!alive()) return null;
      const w = await where(S, P, t, W);
      if (w?.d != null) hits.push(w);
    }
    // Content plays in order, so a hit that would run backwards is a false match:
    // drop the hit that disagrees with the most others until they all agree.
    for (;;) {
      const bad = hits.map((h, i) => hits.filter((o, k) => (k < i ? o.t0 - o.d >= h.t0 - h.d : k > i ? o.t0 - o.d <= h.t0 - h.d : false)).length);
      const worst = Math.max(0, ...bad);
      if (!worst) break;
      hits.splice(bad.indexOf(worst), 1);
    }
    if (!hits.length) return null;
    const segs = [];
    for (const h of hits) {
      const last = segs[segs.length - 1];
      if (last && Math.abs(last.d - h.d) < 0.35) { last.to = h.t0 + W; last.n++; }
      else segs.push({ d: h.d, from: h.t0, to: h.t0 + W, n: 1 });
    }
    const anchors = [], gaps = [];
    const first = segs[0];
    const u0 = await startOf(S, P, first.d, 0, first.from + W);
    if (u0 > 1.5) gaps.push({ s: 0, e: u0 });
    anchors.push({ x: -1e6, d: first.d });
    for (let i = 1; i < segs.length; i++) {
      if (!alive()) return null;
      const A = segs[i - 1], B = segs[i];
      const { u1, u2 } = await between(S, P, A.d, B.d, A.to, B.from);
      if (u2 - u1 > 1.5) gaps.push({ s: u1, e: u2 });
      anchors.push({ x: u2 - B.d, d: B.d });
    }
    const last = segs[segs.length - 1];
    if (dur - last.to > 2) {
      const u1 = await endOf(S, P, last.d, last.to, dur);
      if (dur - u1 > 1.5) gaps.push({ s: u1, e: dur });
    }
    // Double-check each gap really is new sound. If it turns up in the scanned copy
    // outside its ads, it's show content, and Podskip must not skip it.
    const checked = [];
    for (const g of gaps) {
      if (g.e - g.s < 3) continue;
      const len = Math.min(8, g.e - g.s - 1);
      const w = len >= 3 ? await where(S, P, (g.s + g.e) / 2 - len / 2, len) : null;
      const x = w?.d != null ? w.t0 - w.d : null;
      if (x != null && !ads.some((a) => x >= a.s - 2 && x <= a.e + 2)) continue;
      checked.push({ s: Math.round(g.s * 10) / 10, e: Math.round(g.e * 10) / 10 });
    }
    return { anchors: anchors.map((a) => ({ x: Math.round(a.x * 100) / 100, d: Math.round(a.d * 100) / 100 })), gaps: checked };
  }

  // ---- the opening
  // Does your copy open with sound the scanned copy doesn't have (an ad stitched in for
  // you), and where does the show itself start? Decodes straight from the beginning, so it
  // works for any MP3, and reads about 30 seconds unless it needs more.
  // { d, start, anchor }: show sound starts at `start` in your copy, runs d seconds later
  // than in the scan, and is confirmed up to `anchor`. null if it can't tell.
  async function opening(S, P, ads = [], steps = [30, 80, 140]) {
    let have = new Uint8Array(0), end = S.start;
    for (const secs of steps) {
      const want = Math.min(S.size || Infinity, Math.ceil(S.start + secs * S.bps * 1.15) + 4 * S.flen);
      if (want > end) {
        const more = await S.read(end, want);
        const all = new Uint8Array(have.length + more.length);
        all.set(have); all.set(more, have.length);
        have = all; end = want;
      }
      const r = openingIn(envOf(await decode(have)), P, ads);
      if (r) return r;
      if (S.size && end >= S.size) break;
    }
    return null;
  }
  const inAd = (x, ads) => ads.some((a) => x >= a.s - 1 && x <= a.e + 1);
  function openingIn(env, P, ads) {
    const W = 100;
    for (let k = 0; k + W + 60 <= env.length; k += 10) {
      const q = norm(env.subarray(k, k + W));
      if (!q) continue;
      const hit = locate(q, P);
      // Anchor on the show itself: near the scan's start, and not inside one of its ads
      // (the same ad can turn up in both copies, even in a different spot).
      if (!hit || hit.r < 0.8 || hit.margin < 0.15 || hit.x > 420 || inAd(hit.x, ads) || inAd(hit.x + W / HZ, ads)) continue;
      const d = k / HZ - hit.x;
      // A second stretch a few seconds later has to agree.
      const q2 = norm(env.subarray(k + 60, k + 60 + W));
      if (q2 && corrAt(q2, P, Math.round((k / HZ + 6 - d) * HZ)) < 0.7) continue;
      return { d: Math.round(d * 100) / 100, start: startIn(env, P, d, k + W), anchor: k / HZ };
    }
    return null;
  }
  // Earliest point from which your copy keeps matching the scan at offset d.
  function startIn(env, P, d, upto) {
    const T = 4, n = Math.min(upto, env.length);
    const at = (k) => { const i = Math.round((k / HZ - d) * HZ); return i >= 0 && i < P.E.length ? P.E[i] : null; };
    const diffs = [];
    for (let k = Math.max(0, n - 100); k < n; k++) { const e = at(k); if (e != null && e > FLOOR + 15 && env[k] > FLOOR + 15) diffs.push(env[k] - e); }
    diffs.sort((x, y) => x - y);
    const g = diffs.length > 5 ? diffs[diffs.length >> 1] : 0;
    let suf = 0, best = 0, bestK = n;
    for (let k = n - 1; k >= 0; k--) {
      const e = at(k);
      suf += e == null ? -T : T - Math.min(Math.abs(env[k] - e - g), 2 * T);
      if (suf >= best) { best = suf; bestK = k; }
    }
    return bestK / HZ;
  }

  return { printOf, sourceFor, align, where, startOf, listen, locate, norm, corrAt, opening };
})();

// Which copy a match belongs to: a download by its size, a stream by its length.
const matchKeyFor = (ep, a, local, dur) => (local ? `L${dlBlobs[ep.id]?.size || 0}` : `R${Math.round(dur * 10)}`) + `-${a.at}`;
const matchJobs = {};
// Line up one copy of an episode with its scan, or reuse the answer. { k, r, same }
function matchCopy(ep, a, local, dur, alive = () => true) {
  const key = matchKeyFor(ep, a, local, dur);
  if (allMatched[ep.id]?.k === key) return Promise.resolve(allMatched[ep.id]);
  if (matchJobs[key]) return matchJobs[key];
  return (matchJobs[key] = (async () => {
    let r = null, same = false;
    try {
      const S = await sound.sourceFor(ep, local);
      if (S) {
        const d = local ? S.dur || dur : dur;
        if (d && Math.abs(d - a.dur) < 0.3) same = true;
        // Make sure the copy Podskip can read is the one you're hearing.
        else if (S.cbr && (local || !S.dur || Math.abs(S.dur - dur) < 1)) r = await sound.align(S, sound.printOf(a), d, a.ads, alive);
      }
    } catch {}
    const out = { k: key, r, same, at: Date.now() };
    if (r || same) {
      allMatched[ep.id] = out;
      const ids = Object.keys(allMatched);
      if (ids.length > 40) ids.sort((x, y) => allMatched[x].at - allMatched[y].at).slice(0, ids.length - 40).forEach((k) => delete allMatched[k]);
      LS.set("matched", allMatched);
    }
    delete matchJobs[key];
    return out;
  })());
}
// Line up downloaded episodes ahead of time, so they play in sync from the first
// second. It all happens on the phone, with no data used.
let prematching = null;
function prematch() {
  if (prematching || !cfg?.ready) return prematching;
  prematching = (async () => {
    for (const id of Object.keys(dlIndex)) {
      const sc = index?.scanned?.[id], ep = findEpisode(id);
      if (!sc?.env || !dlBlobs[id] || !ep || allMatched[id]?.k === `L${dlBlobs[id].size}-${sc.at}`) continue;
      const a = await loadEpisode(id).catch(() => null);
      if (!a?.env) continue;
      await matchCopy(ep, a, true, 0);
      if (player.ep?.id === id) player.autoMatch();
    }
  })().finally(() => (prematching = null));
  return prematching;
}

// ------------------------------------------------------------------ player
const audio = $("#audio");
const player = (() => {
  const el = $("#player");
  const P = {
    ep: null, analysis: null, align: "exact", D: 0, plan: [], force: false, kept: new Set(), tab: "about",
    skipTimer: null, lastSave: 0, skipped: 0, saved: 0, tq: "",
    isOpen: () => !el.hidden,
  };

  // ---- skip plan
  // Shows that insert ads per listener can hand the phone a copy whose ads are a
  // different length than the copy the scanner heard. Show content is the same in
  // both, so when there's only one ad break inside the episode (plus maybe one at
  // the very end), Podskip can line the times up exactly. Otherwise it stops
  // auto-skipping rather than cutting into the show.
  const tolerance = (d) => Math.max(4, d * 0.0015);
  function buildPlan() {
    buildScanPlan();
    const manual = manualAnchors().length > 0;
    if (P.analysis && (manual || P.auto)) {
      // Your copy has been lined up (by sound, or by hand), so place every ad with that.
      P.align = manual ? "synced" : "matched";
      P.plan = P.analysis.ads.map((x, i) => ({ s: Math.max(0, toStream(x.s)), e: toStream(x.e), idx: [i], types: [x.type], who: x.who })).filter((r) => r.e - r.s > 1);
      // Ads only your copy has: the scanner never heard them, the sound match found them.
      // When one is really a break the scan also found, keeping that ad keeps this too.
      if (!manual) P.auto.gaps.forEach((g, i) => {
        const same = P.plan.filter((r) => Math.min(r.e, g.e) - Math.max(r.s, g.s) > 0.5 * (g.e - g.s));
        P.plan.push({ s: g.s, e: g.e, idx: ["g" + i, ...same.flatMap((r) => r.idx)], types: same.length ? same.flatMap((r) => r.types) : ["sponsor"], who: same[0]?.who || "", gap: !same.length });
      });
    }
    // Your reported ads apply right away, until the scanner's exact version arrives.
    // (An ad only your copy has isn't in the scanner's version, so that mark stays.)
    const done = index?.reports_done || {};
    let marks = (allMarks[P.ep?.id] || []).filter((m) => m.kind === "gap" || !(done[m.rid] && P.analysis && P.analysis.at >= done[m.rid]));
    if (P.ep && marks.length !== (allMarks[P.ep.id] || []).length) { allMarks[P.ep.id] = marks; if (!marks.length) delete allMarks[P.ep.id]; LS.set("marks", allMarks); }
    const copy = copyKey();
    for (const m of marks) if (!m.k || m.k === copy) P.plan.push({ s: m.s, e: m.e, idx: ["m" + m.rid], types: ["sponsor"], who: "", mark: true });
    // The opening, checked first: until the whole episode is lined up, skip what's known for sure.
    if (P.analysis && !manual && !P.auto && P.opening) {
      const { d, start, anchor } = P.opening;
      if (start > 1.5) P.plan.push({ s: 0, e: start, idx: ["open"], types: ["sponsor"], who: "", gap: true });
      // The scan's ads before the confirmed show sound sit exactly d seconds later in your copy.
      P.analysis.ads.forEach((x, i) => {
        if (x.e + d <= anchor + 1 && x.e + d > 0 && !P.plan.some((r) => r.idx.includes(i))) P.plan.push({ s: Math.max(0, x.s + d), e: x.e + d, idx: [i], types: [x.type], who: x.who });
      });
    }
    // An ad that starts in the first few seconds starts at 0:00, so not a word of it plays.
    for (const r of P.plan) if (r.s < 3) r.s = 0;
  }
  function buildScanPlan() {
    const a = P.analysis;
    P.plan = []; P.align = "exact"; P.D = 0; P.pivot = null;
    if (!a) return;
    const raw = a.ads.map((x, i) => ({ s: x.s, e: x.e, idx: [i], types: [x.type], who: x.who }));
    const dur = audio.duration;
    if (!isFinite(dur) || !dur || Math.abs(dur - a.dur) <= tolerance(a.dur)) { P.plan = raw; return; }
    const D = dur - a.dur;
    P.D = D;
    // Matching by sound is about to say exactly where everything is; until then, don't guess.
    if (P.matchState === "working") { P.align = "unknown"; if (P.force) P.plan = raw; return; }
    const blocks = [];
    for (const r of [...raw].sort((x, y) => x.s - y.s)) {
      const b = blocks[blocks.length - 1];
      if (b && r.s - b.e < 3) { b.e = Math.max(b.e, r.e); b.idx.push(...r.idx); b.types.push(...r.types); b.who = [b.who, r.who].filter(Boolean).join(", "); }
      else blocks.push({ ...r, idx: [...r.idx], types: [...r.types] });
    }
    const last = blocks[blocks.length - 1];
    const tail = last && a.dur - last.e < 3 ? last : null;
    const inner = blocks.filter((b) => b !== tail);
    const pivot = inner[0];
    if (inner.length > 1 || (pivot && pivot.e + D - pivot.s < 3) || (!pivot && !tail)) {
      P.align = "unknown";
      if (P.force) P.plan = raw;
      return;
    }
    P.align = "shifted";
    P.pivot = pivot || null;
    P.plan = blocks.map((b) => (b === tail ? { ...b, s: b.s + D, e: dur } : { ...b, e: b.e + D }));
  }
  // Scanned-copy time <-> time in the stream you're hearing.
  // Sync points: from scanned time x onward, your stream runs d seconds later.
  // Ones you set with "Fix sync" win; otherwise the ones the sound match found.
  const manualAnchors = () => (P.ep && allSync[P.ep.id]) || [];
  const anchors = () => { const m = manualAnchors(); return m.length ? m : P.auto?.anchors || []; };
  const toStream = (t) => {
    const a = anchors().filter((p) => p.x <= t + 0.01).pop();
    if (a) return t + a.d;
    return P.align === "shifted" && (!P.pivot || t >= P.pivot.e) ? t + P.D : t;
  };
  const fromStream = (t) => {
    const a = anchors().filter((p) => p.x + p.d <= t + 0.01).pop();
    if (a) return t - a.d;
    return P.align === "shifted" && (!P.pivot || t >= P.pivot.e + P.D) ? t - P.D : t;
  };
  // Which copy is playing: downloaded or streamed, and its length.
  const copyKey = () => `${P.local ? "L" : "R"}${Math.round((audio.duration || 0) * 10)}`;
  const planOn = (r) => r.idx.every((i) => !P.kept.has(i)) && r.types.every((t) => prefs.skip[t]);
  function activeAds() { return P.plan.filter(planOn); }
  function adAt(t) { return P.plan.find((r) => t >= r.s && t < r.e) || null; }

  function checkSkip() {
    clearTimeout(P.skipTimer);
    if (audio.paused && audio.readyState < 2) return;
    const t = audio.currentTime;
    const ads = activeAds();
    const hit = ads.find((a) => t >= a.s - 0.05 && t < a.e - 0.6);
    if (hit) {
      // Ads that touch or overlap are skipped in one go.
      let to = hit.e;
      for (let more = true; more; ) { more = false; for (const a of ads) if (to >= a.s - 1 && to < a.e - 0.6) { to = a.e; more = true; } }
      audio.currentTime = to;
      P.skipped++; P.saved += to - Math.max(t, hit.s);
      playSkipSound();
      const type = hit.types[0];
      const label = hit.who ? `Skipped ${hit.who}` : type === "self" ? "Skipped a plug" : type === "promo" ? "Skipped a promo" : hit.gap ? "Skipped an ad only your copy has" : "Skipped an ad";
      toast(`${label} · ${clock(to - hit.s)}`, { label: "Play it", run: () => { ads.filter((a) => a.s < to && a.e > hit.s).forEach((a) => a.idx.forEach((i) => P.kept.add(i))); audio.currentTime = hit.s; paintScrub(); paintNote(); if (P.tab === "ads") paintPane(); } });
      paintNote();
    }
    const next = ads.filter((a) => a.s > audio.currentTime).sort((a, b) => a.s - b.s)[0];
    if (next && !audio.paused) {
      const ms = ((next.s - audio.currentTime) / (audio.playbackRate || 1)) * 1000;
      P.skipTimer = setTimeout(checkSkip, Math.max(50, ms + 30));
    }
  }

  function checkMatch() {
    if (!P.analysis) { buildPlan(); return; }
    const was = P.align + P.D.toFixed(1);
    buildPlan();
    if (P.align + P.D.toFixed(1) !== was) { paintNote(); paintScrub(); if (P.tab === "chapters") paintPane(); paintTranscript(); }
  }

  function paintNote() {
    const n = $("#p-note");
    n.className = "p-note";
    const st = P.ep ? epState(P.ep) : null;
    if (!P.ep) { n.hidden = true; return; }
    if (guard) { n.innerHTML = `<span>Checking the first minute for ads…</span>`; n.hidden = false; return; }
    if (P.analysis && P.align === "unknown" && !P.force && P.matchState === "working") {
      n.innerHTML = `<span>Your copy of this episode has different ads than the one Podskip scanned. Matching the two by sound so skips land in the right places…</span>`;
      n.hidden = false;
      return;
    }
    if (P.analysis && P.align === "unknown" && !P.force && !anchors().length) {
      n.classList.add("warn");
      n.innerHTML = `<span>This stream is ${clock(Math.abs(audio.duration - P.analysis.dur))} ${audio.duration > P.analysis.dur ? "longer" : "shorter"} than the copy Podskip scanned, so the show probably served different ads. Automatic skipping is off for this episode. You can line it up yourself with Fix sync in the Transcript tab.</span>
        <span class="row"><button class="btn small secondary" id="force" type="button">Skip anyway</button><button class="btn small ghost" id="rescan" type="button">Scan again</button></span>`;
      $("#force").onclick = () => { P.force = true; buildPlan(); paintNote(); paintScrub(); checkSkip(); };
      $("#rescan").onclick = () => requestScan(true);
      n.hidden = false;
      return;
    }
    if (P.analysis) {
      const ads = activeAds();
      if (!P.analysis.ads.length && !ads.length) { n.innerHTML = `<span>No ads found in this episode.</span>`; n.hidden = false; return; }
      // Count overlapping skips (an ad the scan found plus the same break in your copy) once.
      const merged = [];
      for (const a of [...ads].sort((x, y) => x.s - y.s)) { const m = merged[merged.length - 1]; if (m && a.s <= m.e + 1) m.e = Math.max(m.e, a.e); else merged.push({ s: a.s, e: a.e }); }
      const total = merged.reduce((s, a) => s + (a.e - a.s), 0);
      const own = P.align === "matched" ? ownAds().length : 0;
      const shifted = P.align === "shifted" ? ` Your stream's ads run ${clock(Math.abs(P.D))} ${P.D > 0 ? "longer" : "shorter"} than the scanned copy, so the skip times were adjusted.`
        : P.align === "matched" ? ` Lined up with your copy by sound${own ? `, including ${own} ad${own > 1 ? "s" : ""} only your copy has` : ""}.` : "";
      n.innerHTML = P.skipped
        ? `<span>Skipped ${P.skipped} ad${P.skipped > 1 ? "s" : ""}, saved ${clock(P.saved)} so far.${shifted}</span>`
        : `<span>${merged.length ? `Skipping ${merged.length} ad${merged.length > 1 ? "s" : ""} (${clock(total)}).` : "Ads found, but your settings keep them all."}${shifted}${P.analysis.det === "keywords" ? " Found with keyword rules, so some may be missed." : ""}</span>`;
      n.hidden = false;
      return;
    }
    if (st?.kind === "scanning") { n.innerHTML = `<span>Scanning this episode now. Keep listening; ads get skipped as soon as it's done, usually within ${scanEta(P.ep)} minutes.</span>`; n.hidden = false; return; }
    if (st?.kind === "queued") { n.innerHTML = `<span>Waiting to be scanned, so ads aren't skipped yet. Keep listening; skipping starts once the scan is done.</span>`; n.hidden = false; return; }
    if (st?.kind === "failed") {
      n.classList.add("warn");
      n.innerHTML = `<span>Podskip couldn't scan this episode: ${esc(index?.failed?.[P.ep.id]?.err || "unknown error")}</span><span class="row"><button class="btn small secondary" id="rescan" type="button">Try again</button></span>`;
      $("#rescan").onclick = () => requestScan(true); n.hidden = false; return;
    }
    n.innerHTML = `<span>This episode hasn't been scanned, so ads won't be skipped.</span><span class="row"><button class="btn small" id="rescan" type="button">Scan this episode</button></span>`;
    $("#rescan").onclick = () => requestScan(false);
    n.hidden = false;
  }

  // Rough time until a scan finishes: GitHub start-up and download, then about 20x real time.
  const scanEta = (ep) => {
    const d = ep?.dur || (isFinite(audio.duration) ? audio.duration : 3600);
    return Math.ceil(d / 60 / 20) + 3;
  };
  const autoAsked = new Set();
  async function requestScan(again, auto) {
    try {
      if (!(await scanEpisode(P.ep, again, true))) return;
      toast(auto ? `This episode wasn't scanned yet, so Podskip started scanning it. Ad skipping kicks in when it's done, in about ${scanEta(P.ep)} minutes.` : `Scan requested. It takes about ${scanEta(P.ep)} minutes.`);
      paintNote();
    } catch (e) { handleErr(e); }
  }

  function paintScrub() {
    const d = audio.duration || P.analysis?.dur || P.ep?.dur || 0;
    const t = audio.currentTime || 0;
    const pct = d ? (t / d) * 100 : 0;
    $("#scrub-fill").style.width = pct + "%";
    $("#scrub-knob").style.left = pct + "%";
    if (audio.buffered.length && d) $("#scrub-buffer").style.width = (audio.buffered.end(audio.buffered.length - 1) / d) * 100 + "%";
    if (!P.dragging) $("#scrub").value = d ? Math.round((t / d) * 1000) : 0;
    $("#t-now").textContent = clock(t);
    $("#t-left").textContent = "-" + clock(Math.max(0, d - t));
    const ch = (P.analysis?.chapters || []).filter((c) => c.t <= fromStream(t) + 0.5).pop();
    $("#t-chapter").textContent = ch ? ch.title : "";
    const adsEl = $("#scrub-ads");
    const key = `${d}|${P.align}|${P.D}|${P.force}|${[...P.kept]}|${JSON.stringify(prefs.skip)}|${P.analysis?.at}`;
    if (adsEl.dataset.key !== key) {
      adsEl.dataset.key = key;
      adsEl.innerHTML = d ? P.plan.map((r) => `<i class="${planOn(r) ? "" : "kept"}" style="left:${(r.s / d) * 100}%;width:${((r.e - r.s) / d) * 100}%"></i>`).join("") : "";
      $("#scrub-marks").innerHTML = P.analysis && d ? (P.analysis.chapters || []).filter((c) => c.t > 1).map((c) => `<i style="left:${(toStream(c.t) / d) * 100}%"></i>`).join("") : "";
    }
    const inAd = adAt(t);
    $("#c-skipad").disabled = !inAd;
    if (P.tsheet) { followTranscript(); paintSheetCtl(); }
    if (P.tab === "chapters") markChapter();
  }

  function paintMini() {
    const m = $("#mini");
    if (!P.ep) { m.hidden = true; return; }
    m.hidden = false;
    $("#mini-art").src = https(P.ep.img || P.ep.showImg || "");
    $("#mini-title").textContent = P.ep.title;
    $("#mini-sub").textContent = P.ep.show;
    $("#mini-play").innerHTML = audio.paused
      ? `<svg viewBox="0 0 24 24"><path d="M8 5.5v13l11-6.5z"/></svg>`
      : `<svg viewBox="0 0 24 24"><path d="M7 5h3.5v14H7zM13.5 5H17v14h-3.5z"/></svg>`;
    $("#mini-play").setAttribute("aria-label", audio.paused ? "Play" : "Pause");
    const d = audio.duration || P.ep.dur || 0;
    $("#mini-bar-fill").style.width = d ? (audio.currentTime / d) * 100 + "%" : "0";
  }

  // ---- panes
  function paintPane() {
    const pane = $("#ppane");
    $$(".ptabs button[data-ptab]").forEach((b) => b.setAttribute("aria-selected", b.dataset.ptab === P.tab));
    const a = P.analysis;
    if (P.tab === "about") {
      pane.innerHTML = `${a?.summary ? `<p class="summary">${esc(a.summary)}</p>` : ""}
        ${P.ep.desc ? `<p class="desc">${esc(P.ep.desc)}</p>` : ""}
        <p class="detline">${[day(P.ep.date), length(a?.dur || P.ep.dur), a ? `Scanned ${ago(a.at)} with ${a.det.startsWith("gemini") ? "Gemini" : "keyword rules"}` : ""].filter(Boolean).map(esc).join(" · ")}</p>
        ${!a?.summary && !P.ep.desc ? `<p class="muted">No description.</p>` : ""}`;
    } else if (P.tab === "chapters") {
      const ch = a?.chapters || [];
      pane.innerHTML = ch.length
        ? `<div>${ch.map((c, i) => `<button class="chap" type="button" data-t="${c.t}" data-i="${i}"><time>${clock(c.t)}</time><span>${esc(c.title)}</span></button>`).join("")}</div>`
        : `<p class="muted">${a ? (a.det === "keywords" ? "Chapters need a Gemini key." : "No chapters for this episode.") : "Chapters appear after the episode is scanned."}</p>`;
      $$("[data-t]", pane).forEach((b) => (b.onclick = () => seek(toStream(+b.dataset.t), true)));
      markChapter();
    } else if (P.tab === "ads") {
      const names = { sponsor: "Ad", promo: "Promo", self: "Show plug" };
      const mapped = anchors().length > 0;
      const ads = [
        ...(a?.ads || []).map((x, i) => ({ ...x, key: i, s: mapped ? Math.max(0, toStream(x.s)) : x.s, e: mapped ? toStream(x.e) : x.e })),
        ...ownAds().map((g) => ({ s: g.s, e: g.e, type: "sponsor", who: "", key: "g" + g.i, own: true })),
      ].filter((x) => x.e - x.s > 1).sort((x, y) => x.s - y.s);
      const sub = (x) => (x.own ? "Only in your copy · found by matching the audio" : x.src === "report" ? "You reported this" : x.src === "spot" ? "Found by a spot check" : x.src === "opening" ? "Found by the opening check" : `${names[x.type]} · ${Math.round(x.conf * 100)}% sure`);
      pane.innerHTML = !a ? `<p class="muted">Ads are listed after the episode is scanned.</p>` : !ads.length ? `<p class="muted">No ads found.</p>` :
        `<div>${ads.map((x) => {
          const off = !prefs.skip[x.type];
          const kept = P.kept.has(x.key);
          return `<div class="adrow ${kept ? "kept" : ""} ${off ? "off" : ""}"><span class="stripe"></span>
            <div class="adrow-main"><span class="adrow-head">${esc(x.who || (x.own ? "Ad" : names[x.type]))}</span>
              <span class="adrow-sub">${sub(x)} · ${clock(x.s)}–${clock(x.e)} · ${clock(x.e - x.s)}</span>
              ${x.quote ? `<q>${esc(x.quote)}</q>` : ""}</div>
            ${off ? `<span class="chip">Kept</span>` : `<button class="btn small ${kept ? "secondary" : "ghost"}" type="button" data-keep="${x.key}">${kept ? "Skip it" : "Keep"}</button>`}</div>`;
        }).join("")}</div><p class="muted small">Keep an ad to hear it this time. Change which kinds get skipped in Settings.</p>`;
      $$("[data-keep]", pane).forEach((b) => (b.onclick = () => {
        const i = /^\d+$/.test(b.dataset.keep) ? +b.dataset.keep : b.dataset.keep;
        P.kept.has(i) ? P.kept.delete(i) : P.kept.add(i);
        paintPane(); paintScrub(); paintNote(); checkSkip();
      }));
    }
  }

  // ---- transcript sheet: slides up from the bottom, over the player
  const ts = $("#tsheet"), tbody = $("#tsheet-body"), tpanel = $(".tsheet-panel", ts);
  function paintTranscript() {
    if (!P.tsheet || !P.ep) return;
    const a = P.analysis;
    $("#tsheet-title").textContent = P.ep.title;
    if (!a) { tbody.innerHTML = `<p class="muted tsheet-empty">The transcript appears after the episode is scanned.</p>`; paintFollow(); return; }
    {
      const pane = tbody;
      pane.innerHTML = `<div class="tsearch"><div class="tsearch-row"><div class="searchbar"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>
        <input class="input" id="tq" type="search" placeholder="Search the transcript" value="${esc(P.tq)}" aria-label="Search the transcript"></div>
        <button class="btn small ghost" id="fixsync" type="button">${P.syncing ? "Cancel" : "Fix sync"}</button></div>
        ${P.syncing ? `<p class="syncnote">Tap the words you're hearing right now. The transcript and ad skips will line up from there.</p>`
          : manualAnchors().length ? `<p class="muted small" style="margin:6px 0 0">Synced by hand at ${manualAnchors().map((a) => clock(a.x + a.d)).join(", ")}. <button class="linkbtn" id="resetsync" type="button">Undo sync</button></p>`
          : P.matchState === "working" ? `<p class="muted small syncstate" style="margin:6px 0 0"><span class="spin"></span>Matching your copy to the transcript by sound…</p>`
          : P.matchState === "done" ? `<p class="muted small syncstate" style="margin:6px 0 0">✓ Lined up with your copy by sound.</p>` : ""}
        <span class="tcount" id="tcount"></span></div>
        <div id="tlines" class="${P.syncing ? "syncing" : ""}"></div>`;
      $("#fixsync").onclick = () => { P.syncing = !P.syncing; P.tq = ""; paintTranscript(); };
      const rs = $("#resetsync");
      if (rs) rs.onclick = () => { delete allSync[P.ep.id]; LS.set("sync", allSync); afterSync(P.auto ? "Back to the automatic sync." : "Sync undone."); };
      const q = $("#tq");
      q.oninput = () => { P.tq = q.value; paintLines(); paintFollow(); };
      paintLines();
    }
  }

  function paintLines() {
    const box = $("#tlines");
    if (!box) return;
    const q = P.tq.trim().toLowerCase();
    const ads = P.analysis.ads;
    const lines = P.analysis.lines;
    const hits = q ? lines.map((l, i) => [l, i]).filter(([l]) => l[2].toLowerCase().includes(q)) : lines.map((l, i) => [l, i]);
    $("#tcount").textContent = q ? `${hits.length} match${hits.length === 1 ? "" : "es"}` : "";
    const rx = q ? new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi") : null;
    const timing = P.analysis.words;
    const wordSpans = (txt, marks) => marks.map(([, c], k) => `<span class="word">${esc(txt.slice(c, k + 1 < marks.length ? marks[k + 1][1] : undefined))}</span>`).join("");
    box.innerHTML = hits.slice(0, 4000).map(([l, i]) => {
      const isAd = ads.some((a) => l[0] >= a.s - 0.5 && l[1] <= a.e + 0.5);
      const text = rx ? esc(l[2]).replace(rx, (m) => `<mark>${m}</mark>`) : timing?.[i]?.length ? wordSpans(l[2], timing[i]) : esc(l[2]);
      return `<button class="tline ${isAd ? "ad" : ""}" type="button" data-i="${i}" data-t="${l[0]}"><time>${clock(l[0])}</time><span>${text}</span></button>`;
    }).join("");
    $$("[data-t]", box).forEach((b) => (b.onclick = (e) => {
      if (P.syncing) return setSyncPoint(b, e);
      seek(toStream(+b.dataset.t), true);
      P.follow = true; paintFollow(); // tapping a line means "take me here and keep up"
    }));
    P.followAt = -1;
    followTranscript(P.follow);
  }

  function openTranscript() {
    if (!P.ep) return;
    P.tsheet = true; P.follow = true; P.followAt = -1;
    ts.hidden = false;
    ts.classList.toggle("playing", !audio.paused);
    paintTranscript(); paintSheetCtl();
    requestAnimationFrame(() => requestAnimationFrame(() => { ts.classList.add("open"); followTranscript(true); }));
  }
  function closeTranscript() {
    if (!P.tsheet) return;
    P.tsheet = false; P.syncing = false;
    ts.classList.remove("open");
    tpanel.style.transform = "";
    $("#follow").hidden = true;
    if (document.activeElement && ts.contains(document.activeElement)) document.activeElement.blur();
    setTimeout(() => { if (!P.tsheet) { ts.hidden = true; tbody.innerHTML = ""; } }, 380);
  }
  P.openTranscript = openTranscript;
  function paintSheetCtl() {
    if (!P.tsheet) return;
    const d = audio.duration || P.analysis?.dur || P.ep?.dur || 0, t = audio.currentTime || 0;
    $("#ts-now").textContent = clock(t);
    $("#ts-left").textContent = "-" + clock(Math.max(0, d - t));
    $("#ts-fill").style.width = d ? (t / d) * 100 + "%" : "0";
  }
  $("#open-transcript").onclick = openTranscript;
  $("#tsheet-close").onclick = closeTranscript;
  $("#tsheet-shade").onclick = closeTranscript;
  $("#ts-play").onclick = () => (audio.paused ? audio.play().catch(() => {}) : audio.pause());
  $("#ts-back").onclick = () => seek(audio.currentTime - 15);
  $("#ts-fwd").onclick = () => seek(audio.currentTime + 30);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && P.tsheet) closeTranscript(); });
  // Drag the sheet down by its top bar, or from the top of the transcript, to close it.
  {
    let y0 = null, dy = 0, t0 = 0, fromBody = false;
    const start = (e, body) => {
      if (e.touches.length !== 1 || (body && tbody.scrollTop > 0) || e.target.closest("input, #fixsync, #resetsync, #tsheet-close")) { y0 = null; return; }
      y0 = e.touches[0].clientY; dy = 0; t0 = Date.now(); fromBody = body;
    };
    const move = (e) => {
      if (y0 == null) return;
      const d = e.touches[0].clientY - y0;
      if (fromBody && dy === 0 && d <= 0) { y0 = null; return; } // scrolling the transcript, not closing
      dy = Math.max(0, d);
      if (fromBody && tbody.scrollTop > 0) { y0 = null; tpanel.style.transform = ""; return; }
      if (dy > 0) e.preventDefault();
      tpanel.style.transition = "none";
      tpanel.style.transform = `translateY(${dy}px)`;
    };
    const end = () => {
      if (y0 == null) return;
      y0 = null;
      tpanel.style.transition = "";
      if (dy > 140 || (dy > 50 && Date.now() - t0 < 260)) closeTranscript();
      else tpanel.style.transform = "";
    };
    const head = $("#tsheet-head");
    head.addEventListener("touchstart", (e) => start(e, false), { passive: true });
    tbody.addEventListener("touchstart", (e) => start(e, true), { passive: true });
    for (const n of [head, tbody]) {
      n.addEventListener("touchmove", move, { passive: false });
      n.addEventListener("touchend", end, { passive: true });
      n.addEventListener("touchcancel", end, { passive: true });
    }
  }

  // ---- fix sync by hand
  function setSyncPoint(lineBtn, ev) {
    const i = +lineBtn.dataset.i;
    const line = P.analysis.lines[i];
    // Which word did you tap? Fall back to the start of the line.
    const wordEl = ev.target.closest(".word");
    let x = line[0];
    if (wordEl) {
      const k = [...lineBtn.querySelectorAll(".word")].indexOf(wordEl);
      const off = P.analysis.words?.[i]?.[k]?.[0];
      if (off != null) x = line[0] + off;
    }
    const d = Math.round((audio.currentTime - x) * 10) / 10;
    const list = (allSync[P.ep.id] || []).filter((a) => Math.abs(a.x - x) > 20);
    list.push({ x, d });
    list.sort((a, b) => a.x - b.x);
    allSync[P.ep.id] = list;
    LS.set("sync", allSync);
    P.syncing = false;
    afterSync(Math.abs(d) < 0.5 ? "Already in sync at that point." : `Synced. Your audio is ${Math.abs(d).toFixed(1)} s ${d > 0 ? "behind" : "ahead of"} the transcript here, so Podskip adjusted it.`);
  }
  function afterSync(msg) {
    buildPlan(); $("#scrub-ads").dataset.key = ""; paintScrub(); paintNote(); paintPane(); paintTranscript(); checkSkip();
    P.follow = true; P.followAt = -1; followTranscript(true); paintFollow();
    toast(msg);
  }

  // ---- follow along
  // The transcript keeps the line you're hearing in view, but the moment you
  // touch or scroll it, it stops moving. "Follow along" turns it back on.
  P.follow = true;
  function paintFollow() {
    $("#follow").hidden = !(P.tsheet && P.analysis && !P.follow && !P.tq);
  }
  const stopFollowing = (e) => {
    if (!P.tsheet || !P.follow) return;
    if (e.target.closest && e.target.closest("#follow")) return;
    P.follow = false;
    paintFollow();
  };
  tbody.addEventListener("touchstart", stopFollowing, { passive: true });
  tbody.addEventListener("wheel", stopFollowing, { passive: true });
  // Any scrolling the app didn't do itself also counts as you taking over.
  P.autoScrollUntil = 0;
  tbody.addEventListener("scroll", (e) => { if (Date.now() > P.autoScrollUntil) stopFollowing(e); }, { passive: true });
  $("#follow").onclick = () => { P.follow = true; P.followAt = -1; paintFollow(); followTranscript(true); };

  function followTranscript(jump) {
    const box = $("#tlines");
    if (!box || !P.analysis) return;
    const t = fromStream(audio.currentTime);
    const lines = P.analysis.lines;
    let lo = 0, hi = lines.length - 1, idx = -1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (lines[m][0] <= t) { idx = m; lo = m + 1; } else hi = m - 1; }
    if (inOwnAd(audio.currentTime)) idx = -1; // an ad the transcript doesn't have
    paintWord(box, idx, t);
    if (idx === P.followAt) return;
    P.followAt = idx;
    $$(".tline.now", box).forEach((x) => x.classList.remove("now"));
    const cur = box.querySelector(`[data-i="${idx}"]`);
    if (!cur) return;
    cur.classList.add("now");
    if (!P.follow || P.tq) return;
    // Scroll the transcript only when the line drifts out of the comfortable middle.
    const r = cur.getBoundingClientRect(), box2 = tbody.getBoundingClientRect();
    const h = tbody.clientHeight, top = r.top - box2.top;
    if (jump || top < h * 0.15 || top + r.height > h * 0.7) {
      P.autoScrollUntil = Date.now() + (jump ? 150 : 900);
      tbody.scrollTo({ top: tbody.scrollTop + top - h * 0.3, behavior: jump ? "auto" : "smooth" });
    }
  }
  // Light up the word being said (only when the scan saved word timings).
  function paintWord(box, idx, t) {
    const words = P.analysis.words?.[idx];
    const line = box.querySelector(`[data-i="${idx}"] span`);
    if (!words || !line || P.tq) return;
    let w = -1;
    for (let k = 0; k < words.length; k++) if (P.analysis.lines[idx][0] + words[k][0] <= t + 0.05) w = k;
    if (line.dataset.w === String(w)) return;
    line.dataset.w = w;
    $$(".tline .word.on", box).forEach((x) => x.classList.remove("on"));
    line.querySelectorAll(".word")[w]?.classList.add("on");
  }
  function markChapter() {
    const t = fromStream(audio.currentTime);
    const btns = $$(".chap");
    let cur = -1;
    btns.forEach((b, i) => { if (+b.dataset.t <= t + 0.5) cur = i; });
    btns.forEach((b, i) => b.classList.toggle("now", i === cur));
  }

  function seek(t, play) {
    audio.currentTime = Math.max(0, t);
    if (play && audio.paused) audio.play().catch(() => {});
    paintScrub();
  }

  // ---- media session
  function mediaSession() {
    if (!("mediaSession" in navigator) || !P.ep) return;
    const art = https(P.ep.img || P.ep.showImg || "");
    navigator.mediaSession.metadata = new MediaMetadata({ title: P.ep.title, artist: P.ep.show, album: "Podskip", artwork: art ? [{ src: art, sizes: "600x600" }] : [] });
    const h = (a, f) => { try { navigator.mediaSession.setActionHandler(a, f); } catch {} };
    h("play", () => audio.play());
    h("pause", () => audio.pause());
    h("seekbackward", (d) => seek(audio.currentTime - (d.seekOffset || 15)));
    h("seekforward", (d) => seek(audio.currentTime + (d.seekOffset || 30)));
    h("seekto", (d) => seek(d.seekTime));
    h("previoustrack", null);
    h("nexttrack", null);
  }
  let lastPos = 0;
  function positionState() {
    if (!("mediaSession" in navigator) || !isFinite(audio.duration)) return;
    const now = Date.now();
    if (now - lastPos < 4000) return;
    lastPos = now;
    try { navigator.mediaSession.setPositionState({ duration: audio.duration, position: Math.min(audio.currentTime, audio.duration), playbackRate: audio.playbackRate }); } catch {}
  }

  // ---- open / close
  async function open(id, play, show = true) {
    const ep = findEpisode(id);
    if (!ep) return;
    if (!P.ep || P.ep.id !== id) {
      saveNow();
      if (P.ep && progress[P.ep.id]?.done && dlIndex[P.ep.id]) setTimeout(() => cleanupPlayed(), 0); // you moved on from a finished one
      Object.assign(P, { ep, analysis: null, align: "exact", D: 0, plan: [], pivot: null, force: false, kept: new Set(), skipped: 0, saved: 0, tq: "", dlSure: false, auto: null, matchState: "", matchKey: "", opening: null, openingState: "" });
      endGuard(false);
      LS.set("current", id);
      P.local = !!dlUrls[id];
      audio.src = dlUrls[id] || https(ep.url);
      audio.playbackRate = prefs.speed;
      audio.defaultPlaybackRate = prefs.speed;
      const p = progress[id];
      P.resumeAt = p && !p.done && p.t > 5 ? p.t : 0;
      if (play) audio.play().catch(() => {});
      if (play && epState(ep).kind === "none" && !autoAsked.has(id)) {
        autoAsked.add(id);
        requestScan(false, true);
      }
      $("#p-art").src = https(ep.img || ep.showImg || "");
      $("#p-show").textContent = ep.show;
      $("#p-title").textContent = ep.title;
      $("#scrub-ads").dataset.key = "";
      P.tab = "about";
      closeTranscript();
      mediaSession();
      paintMini();
      loadAnalysis();
    } else {
      useLocal();
      if (play && audio.paused) audio.play().catch(() => {});
    }
    if (!show) return;
    el.hidden = false;
    document.body.style.overflow = "hidden";
    $("#c-speed").textContent = speedLabel(prefs.speed);
    paintNote(); paintScrub(); paintPane(); paintDl();
  }

  // ---- report an ad = spot check
  const AD_CUE = /(brought to you by|sponsored by|today'?s sponsor|this (message|episode|podcast) (comes|is) (from|supported by)|support for (this|the) (show|podcast|episode)|messages? from (our|these) sponsors?|promo code|offer code|use (the )?code|discount code|dot com slash|\.com ?(\/|slash)|\b\w+(\.| dot )com\b|\b\d{1,2} ?(%|percent) off\b|free trial|terms (and conditions )?apply|first (month|box|order) free|(visit|go to|head to) \w+)/i;
  const AD_BACK = /(and we'?re back|welcome back|back to (the|our) (show|story|episode))/i;
  // Where does the ad at scanned time x end? A scanned ad covering x says so;
  // otherwise read ahead in the transcript until the ad cues stop for 25 s or
  // the host says they're back. { end (scanned time), how: "scan" | "cues" | "guess" }
  function adEndAt(x) {
    const known = (P.analysis?.ads || []).find((a) => x >= a.s - 3 && x < a.e);
    if (known) return { end: known.e, how: "scan" };
    const lines = P.analysis?.lines;
    const i = lines ? lines.findIndex((l) => l[1] > x) : -1;
    if (i < 0) return { end: x + 30, how: "guess" };
    let lastCue = null, end = null;
    for (let j = i; j < lines.length; j++) {
      const [ls, le, txt] = lines[j];
      if (ls - x > 180) break;
      if (j > i && AD_BACK.test(txt)) { end = ls; break; }
      if (AD_CUE.test(txt)) lastCue = le;
      if (lastCue != null && ls - lastCue > 25) { end = lastCue; break; }
      if (lastCue == null && ls - x > 45) break;
    }
    if (end == null && lastCue != null) end = lastCue;
    return end == null ? { end: x + 30, how: "guess" } : { end: Math.max(end, x + 10), how: "cues" };
  }
  const withTimeout = (p, ms) => Promise.race([p, new Promise((res) => setTimeout(() => res(undefined), ms))]);
  let sourceMemo = null;
  async function sourceNow() {
    const k = `${P.ep.id}-${P.local}`;
    if (sourceMemo?.k !== k) sourceMemo = { k, p: sound.sourceFor(P.ep, P.local).catch(() => null) };
    return sourceMemo.p;
  }
  // What's playing at t in your copy? Checks on the phone, in a few seconds:
  //   { kind: "gap", s, e }  an ad only your copy has, with its exact end
  //   { kind: "content", d } sound that's in the scanned copy (d = how much later yours runs)
  //   null                   couldn't tell
  async function spotHere(t) {
    const g = inOwnAd(t) || (!manualAnchors().length && P.auto?.gaps.find((g) => g.s > t && g.s - t < 3));
    if (g) return { kind: "gap", s: g.s, e: g.e, x: fromStream(g.e) };
    if (P.auto || manualAnchors().length) return { kind: "content", d: toStream(fromStream(t)) - fromStream(t) };
    const pr = sound.printOf(P.analysis);
    if (!pr) return null;
    const S = await sourceNow();
    if (!S || !S.cbr || (!S.local && S.dur && Math.abs(S.dur - audio.duration) > 1)) return null;
    const here = await sound.where(S, pr, Math.max(0, t - 5), 8);
    if (!here) return null;
    if (here.d != null) return { kind: "content", d: here.d };
    // Not in the scanned copy: an ad stitched into yours. Listen ahead for the show coming back.
    for (let T = t + 15; T < Math.min(audio.duration - 8, t + 200); T += 20) {
      const w = await sound.where(S, pr, T, 8);
      if (w?.d != null) {
        const e = await sound.startOf(S, pr, w.d, T - 20, w.t0 + 8);
        return { kind: "gap", s: Math.max(0, t - 1), e, x: e - w.d };
      }
    }
    return null;
  }

  async function reportAd() {
    if (!P.ep || P.spotting) return;
    const id = P.ep.id, dur = audio.duration || Infinity;
    const t = audio.currentTime || 0;
    P.spotting = true; paintSpotting();
    let found;
    try { found = await withTimeout(spotHere(t), 9000); } catch { found = null; }
    P.spotting = false; paintSpotting();
    if (!P.ep || P.ep.id !== id) return;
    const now = audio.currentTime || t;
    let s, e, x, xEnd, kind, msg;
    if (found?.kind === "gap") {
      kind = "gap"; s = found.s; e = Math.min(found.e, dur - 0.5);
      x = found.x; xEnd = x; // where the show picks up again, in the scanned copy
      msg = `Spot check: this ad was only in your copy of the episode, so Podskip found where it ends by sound and skipped ${clock(Math.max(0, e - now))}.`;
    } else {
      kind = found ? "content" : "guess";
      const d = found?.d ?? toStream(fromStream(t)) - fromStream(t);
      x = t - d;
      const end = adEndAt(x);
      xEnd = end.end; s = Math.max(0, t - 1); e = Math.min(xEnd + d, dur - 0.5);
      msg = end.how === "guess" ? `Spot check: skipped ahead ${clock(Math.max(0, e - now))}.` : `Spot check: skipped to where this ad ends (${clock(Math.max(0, e - now))}).`;
    }
    msg += " Now checking 5 minutes either side for anything else the scan missed.";
    const rid = Date.now().toString(36);
    if (e > now + 1) {
      (allMarks[id] = allMarks[id] || []).push({ rid, s, e, kind, k: copyKey() });
      LS.set("marks", allMarks);
      buildPlan();
      audio.currentTime = e;
      playSkipSound();
      paintScrub();
    }
    toast(msg, {
      label: "Undo",
      run: async () => {
        allMarks[id] = (allMarks[id] || []).filter((m) => m.rid !== rid);
        if (!allMarks[id].length) delete allMarks[id];
        LS.set("marks", allMarks);
        delete spots[rid]; LS.set("spots", spots);
        buildPlan(); seek(t); paintScrub();
        try { await changeSubs((s) => { s.reports = (s.reports || []).filter((r) => r.id !== rid); }, "Undo an ad report"); } catch {}
      },
    }, 9000);
    spots[rid] = { ep: id, at: Date.now() }; LS.set("spots", spots);
    try {
      await changeSubs((sb) => {
        sb.reports = [...(sb.reports || []), { id: rid, ep: id, t: Math.round(x * 10) / 10, end: Math.round(xEnd * 10) / 10, kind, at: Math.floor(Date.now() / 1000) }].slice(-60);
        if (!index?.scanned?.[id]) sb.want = [id, ...(sb.want || []).filter((y) => y !== id)].slice(0, 20);
      }, "Spot check");
      scanNow(true);
    } catch (err) { handleErr(err); }
  }
  function paintSpotting() {
    const b = $("#p-report");
    if (!b) return;
    b.disabled = !!P.spotting;
    b.classList.toggle("busy", !!P.spotting);
    $("span", b).textContent = P.spotting ? "Checking…" : "Report ad";
  }

  // Switch a loaded, paused episode over to its downloaded copy.
  function useLocal() {
    const id = P.ep?.id;
    if (!id || P.local || !dlUrls[id] || !audio.paused) return;
    const t = audio.currentTime;
    P.local = true;
    audio.src = dlUrls[id];
    if (t > 1) P.resumeAt = t;
  }
  P.useLocal = useLocal;

  // ---- download button
  function paintDl() {
    const box = $("#p-actions");
    if (!P.ep || el.hidden) return;
    setTimeout(() => { const r = $("#p-report"); if (r) r.onclick = reportAd; paintSpotting(); });
    const id = P.ep.id, job = dlJobs[id], have = dlIndex[id];
    const icon = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v11m0 0-4.5-4.5M12 15l4.5-4.5M5 19h14"/></svg>`;
    const reportBtn = `<button class="dlbtn report" id="p-report" type="button"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 21V4m0 0h11l-2 4 2 4H5"/></svg><span>Report ad</span></button>`;
    if (job) {
      const pct = job.total ? Math.min(99, Math.floor((job.got / job.total) * 100)) : null;
      box.innerHTML = `${reportBtn}<button class="dlbtn busy" id="p-dl" type="button" style="--p:${pct ?? 0}%">${icon}<span>Downloading ${pct != null ? pct + "%" : mb(job.got)}</span><b>Cancel</b></button>`;
      $("#p-dl").onclick = () => job.ctrl.abort();
    } else if (have) {
      box.innerHTML = `${reportBtn}<button class="dlbtn done" id="p-dl" type="button">${icon}<span>${P.dlSure ? "Tap again to remove the download" : `Downloaded · ${mb(have.bytes)}`}</span>${P.dlSure ? "" : "<b>Remove</b>"}</button>`;
      $("#p-dl").onclick = async () => {
        if (!P.dlSure) { P.dlSure = true; paintDl(); setTimeout(() => { P.dlSure = false; paintDl(); }, 4000); return; }
        P.dlSure = false;
        await removeDownload(id, true);
        toast("Download removed");
        paintDl(); rerenderIfList();
      };
    } else {
      const blocked = dlBlocked[P.ep.fid];
      box.innerHTML = `${reportBtn}<button class="dlbtn" id="p-dl" type="button">${icon}<span>${blocked ? "Try downloading" : "Download"}</span></button>
        ${blocked ? `<span class="muted small">This show's server refused a download before.</span>` : ""}`;
      $("#p-dl").onclick = () => startDownload(P.ep);
    }
  }
  P.paintDl = () => { paintDl(); const r = $("#p-report"); if (r) r.onclick = reportAd; };
  // ---- line up your copy by sound (see `sound` above)
  // ---- the first 75 seconds
  // The opening gets checked before anything else: a quick look at your copy's first
  // half minute (more if needed) says whether it opens with an ad and where the show starts.
  async function checkOpening() {
    const ep = P.ep, a = P.analysis, dur = audio.duration;
    if (!ep || !a?.env || P.openingState || P.noAutoMatch || !isFinite(dur) || !dur) return;
    if (manualAnchors().length || P.auto || P.matchState === "same" || Math.abs(dur - a.dur) < 0.3) return;
    if ((P.resumeAt || audio.currentTime) > 180) return; // you're past the opening
    P.openingState = "working";
    let r = null;
    try {
      const S = await sourceNow();
      // Only trust it if the copy Podskip can read is the one you're hearing.
      if (S && (S.local || (S.dur && Math.abs(S.dur - dur) < 1))) r = await withTimeout(sound.opening(S, sound.printOf(a), a.ads), 20000);
    } catch {}
    if (P.ep !== ep) return;
    P.opening = r || null;
    P.openingState = r ? "done" : "none";
    if (!P.auto) { buildPlan(); $("#scrub-ads").dataset.key = ""; paintScrub(); paintNote(); checkSkip(); }
  }

  // Start an episode near the top and Podskip keeps the sound off for the moment it takes
  // to check the opening, then jumps past an opening ad, or goes back to where you
  // started if there isn't one. Either way you don't hear the ad.
  let guard = null;
  function openingSettled() {
    const id = P.ep?.id;
    if (!id || !index?.scanned?.[id]) return true; // not scanned yet: nothing to wait for
    if (!P.analysis) return false;
    if (!P.analysis.env || manualAnchors().length || P.auto || P.opening || P.matchState === "same") return true;
    return P.openingState === "none" || (!P.openingState && ["done", "none"].includes(P.matchState));
  }
  function guardOpening() {
    if (guard || !P.ep) return;
    const from = P.resumeAt || audio.currentTime || 0;
    if (from > 75 || openingSettled()) return;
    guard = { from, ep: P.ep, skipped: P.skipped, until: Date.now() + 8000 };
    audio.muted = true;
    paintNote();
    const tick = () => {
      if (!guard) return;
      if (P.ep !== guard.ep) return endGuard(false);
      if (openingSettled() || Date.now() > guard.until) return endGuard(true);
      setTimeout(tick, 120);
    };
    setTimeout(tick, 120);
  }
  function endGuard(apply) {
    const g = guard;
    guard = null;
    if (g && apply) {
      const t = audio.currentTime;
      // Nothing was skipped while it checked and there's no ad where you started: go back,
      // so you hear the show from where you meant to.
      if (P.skipped === g.skipped && !activeAds().some((a) => g.from >= a.s - 0.5 && g.from < a.e) && t > g.from + 0.3 && t < g.from + 12) audio.currentTime = g.from;
      checkSkip();
    }
    audio.muted = false;
    if (g) paintNote();
  }

  async function autoMatch() {
    const ep = P.ep, a = P.analysis, dur = audio.duration;
    if (!ep || !a?.env || !isFinite(dur) || !dur || P.noAutoMatch) return;
    const key = matchKeyFor(ep, a, P.local, dur);
    if (P.matchKey === key) return;
    // Already lined up (a download is matched in the background as soon as it finishes).
    const saved = allMatched[ep.id];
    if (saved?.k === key) { P.matchKey = key; P.auto = saved.r; P.matchState = saved.same ? "same" : "done"; afterMatch(); return; }
    if (audio.paused && !P.isOpen()) return; // only stream-match what you're listening to
    P.matchKey = key;
    P.auto = null;
    // Same length to a fraction of a second: it's the very copy the scanner heard.
    if (Math.abs(dur - a.dur) < 0.3) { P.matchState = "same"; return; }
    P.matchState = "working";
    paintNote(); paintTranscript();
    checkOpening(); // the first minute first; the whole episode follows
    const res = await matchCopy(ep, a, P.local, dur, () => P.ep === ep);
    if (P.ep !== ep || P.matchKey !== key) return;
    P.auto = res.r;
    P.matchState = res.r ? "done" : res.same ? "same" : "none";
    afterMatch();
  }
  P.autoMatch = autoMatch;
  function afterMatch() {
    buildPlan(); $("#scrub-ads").dataset.key = ""; paintNote(); paintScrub();
    if (P.isOpen() && ["ads", "chapters"].includes(P.tab)) paintPane();
    paintTranscript();
    checkSkip();
  }
  // Ads only your copy has, leaving out ones that are really a break the scan also found.
  const ownAds = () => {
    if (manualAnchors().length || !P.auto) return [];
    const found = (P.analysis?.ads || []).map((x) => [toStream(x.s), toStream(x.e)]);
    return P.auto.gaps.map((g, i) => ({ ...g, i })).filter((g) => !found.some(([s, e]) => Math.min(e, g.e) - Math.max(s, g.s) > 0.5 * (g.e - g.s)));
  };
  const inOwnAd = (t) => !manualAnchors().length && P.auto?.gaps.find((g) => t >= g.s && t < g.e);

  async function loadAnalysis() {
    const id = P.ep.id;
    try {
      const a = await loadEpisode(id);
      if (!P.ep || P.ep.id !== id) return;
      if (!a) { buildPlan(); paintScrub(); return; }
      P.analysis = a;
      if (!a.env && guard) endGuard(true);
      checkMatch();
      paintNote(); paintScrub(); if (P.isOpen()) paintPane(); paintTranscript();
      checkSkip();
      autoMatch();
    } catch (e) {
      if (e instanceof AuthError) authProblem();
    }
  }
  P.retryAnalysis = () => {
    if (!P.ep) return;
    const sc = index?.scanned?.[P.ep.id];
    if (sc && (!P.analysis || P.analysis.at < sc.at || (sc.env && !P.analysis.env))) loadAnalysis();
    else paintNote();
  };
  P.refreshAds = () => { if (P.ep) { buildPlan(); paintNote(); paintScrub(); checkSkip(); } };

  function close() {
    el.hidden = true;
    closeTranscript();
    document.body.style.overflow = "";
    paintMini();
  }

  function saveNow() {
    if (!P.ep || !isFinite(audio.duration) || !audio.duration) return;
    const d = audio.duration, t = audio.currentTime;
    progress[P.ep.id] = { t, d, done: d - t < Math.max(30, d * 0.02), at: Date.now() };
    // Its download goes once it ends or you stop near the end (the rest of it stays loaded meanwhile).
    if (progress[P.ep.id].done && dlIndex[P.ep.id] && (audio.ended || audio.paused)) setTimeout(() => cleanupPlayed(), 0);
    const ids = Object.keys(progress);
    if (ids.length > 400) ids.sort((a, b) => progress[a].at - progress[b].at).slice(0, ids.length - 400).forEach((k) => delete progress[k]);
    saveProgress();
  }

  const speeds = [1, 1.2, 1.5, 1.75, 2, 0.8];
  const speedLabel = (s) => (s === 1 ? "1×" : s + "×");

  // ---- wiring
  $("#player-close").onclick = close;
  $("#mini").onclick = (e) => {
    if (e.target.closest("#mini-play")) { audio.paused ? audio.play().catch(() => {}) : audio.pause(); return; }
    open(P.ep.id, false);
  };
  $("#c-play").onclick = () => (audio.paused ? audio.play().catch((e) => toast("Couldn't play this episode: " + e.message)) : audio.pause());
  $("#c-back").onclick = () => seek(audio.currentTime - 15);
  $("#c-fwd").onclick = () => seek(audio.currentTime + 30);
  $("#c-skipad").onclick = () => { const a = adAt(audio.currentTime); if (a) seek(a.e); };
  $("#c-speed").onclick = () => {
    const i = speeds.indexOf(prefs.speed);
    prefs.speed = speeds[(i + 1) % speeds.length];
    audio.playbackRate = prefs.speed; audio.defaultPlaybackRate = prefs.speed;
    $("#c-speed").textContent = speedLabel(prefs.speed);
    savePrefs(); checkSkip();
  };
  $$(".ptabs button[data-ptab]").forEach((b) => (b.onclick = () => { P.tab = b.dataset.ptab; paintPane(); }));
  const scrub = $("#scrub");
  scrub.addEventListener("input", () => {
    P.dragging = true;
    const d = audio.duration || 0;
    const t = (scrub.value / 1000) * d;
    $("#scrub-fill").style.width = scrub.value / 10 + "%";
    $("#scrub-knob").style.left = scrub.value / 10 + "%";
    $("#t-now").textContent = clock(t);
  });
  scrub.addEventListener("change", () => { P.dragging = false; seek((scrub.value / 1000) * (audio.duration || 0)); });

  audio.addEventListener("loadedmetadata", () => {
    if (P.resumeAt) { audio.currentTime = P.resumeAt; P.resumeAt = 0; }
    checkMatch(); paintScrub(); positionState(); autoMatch();
  });
  audio.addEventListener("durationchange", () => { checkMatch(); paintScrub(); autoMatch(); });
  audio.addEventListener("timeupdate", () => {
    checkSkip();
    if (P.isOpen()) paintScrub();
    paintMini();
    positionState();
    if (Date.now() - P.lastSave > 5000) { P.lastSave = Date.now(); saveNow(); }
  });
  audio.addEventListener("play", () => { el.classList.add("playing"); ts.classList.add("playing"); guardOpening(); paintMini(); checkSkip(); lastPos = 0; positionState(); refreshPills(); autoMatch(); });
  audio.addEventListener("pause", () => { el.classList.remove("playing"); ts.classList.remove("playing"); paintMini(); saveNow(); clearTimeout(P.skipTimer); refreshPills(); });
  audio.addEventListener("seeked", () => { checkSkip(); lastPos = 0; positionState(); });
  audio.addEventListener("progress", () => { if (P.isOpen()) paintScrub(); });
  audio.addEventListener("ended", () => { saveNow(); paintMini(); });
  audio.addEventListener("error", () => {
    if (!P.ep) return;
    toast(!navigator.onLine && !P.local ? "You're offline, and this episode isn't downloaded." : "This episode won't play. The podcast's server may be down, or the file was removed.");
  });
  addEventListener("pagehide", saveNow);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") saveNow(); });

  P.open = open;
  return P;
})();

function openEpisode(id, play) { player.open(id, play); }

// ------------------------------------------------------------------ pull to refresh
// Drag down from the top of a page and let go: Podskip reloads your shows from
// GitHub and, unless a scan just ran or is running, asks the scanner to check
// every show for new episodes (they show up a minute or two later).
async function pullRefresh() {
  if (!navigator.onLine) { toast("You're offline. Downloaded episodes still play."); return; }
  const before = new Set(Object.values(index?.feeds || {}).flatMap((f) => (f.episodes || []).map((e) => e.id)));
  try {
    await Promise.all([refreshSubs(), refreshIndex(), refreshRun()]);
    if (location.hash === "#scan") await refreshJobs();
  } catch (e) {
    if (e instanceof AuthError) return authProblem();
    toast("Couldn't reach GitHub. Try again in a moment.");
    return;
  }
  paintPill(); rerenderIfList(); player.retryAnalysis(); autoDownload();
  const fresh = Object.values(index?.feeds || {}).flatMap((f) => f.episodes || []).filter((e) => !before.has(e.id)).length;
  const running = status?.state === "running" || (lastRun && lastRun.status !== "completed") || Date.now() - dispatchedAt < 90000;
  const recent = status?.finished && Date.now() / 1000 - status.finished < 10 * 60;
  if (fresh) toast(`${fresh} new episode${fresh > 1 ? "s" : ""}`);
  if (running) { startPolling(); if (!fresh) toast("Up to date. A scan is running now, so anything new will show up shortly."); }
  else if (!recent && (subs?.feeds || []).length) { await scanNow(true); if (!fresh) toast("Checking your shows for new episodes. Anything new shows up in a minute or two."); }
  else if (!fresh) toast("Up to date");
}
(() => {
  const ptr = $("#ptr"), arc = $("#ptr circle"), page = $("#view");
  const TRIGGER = 72, MAX = 120, REST = 58;
  let x0 = null, y0 = null, pull = 0, busy = false;
  const paint = (d, smooth) => {
    const ease = smooth ? "transform .32s cubic-bezier(.2,.8,.2,1)" : "none";
    page.style.transition = ease;
    page.style.transform = d ? `translateY(${d}px)` : "";
    ptr.style.transition = smooth ? `${ease}, opacity .25s` : "none";
    ptr.style.opacity = Math.min(1, d / (TRIGGER * 0.6));
    ptr.style.transform = `translate(-50%, ${Math.min(d, REST) - 44}px)`;
    arc.style.strokeDashoffset = 63 * (1 - Math.min(1, d / TRIGGER));
    ptr.classList.toggle("ready", d >= TRIGGER);
  };
  const canStart = (e) =>
    !busy && cfg?.ready && e.touches.length === 1 && window.scrollY <= 0 && !player.isOpen() && $("#sheet").hidden &&
    !e.target.closest(".player, .sheet-backdrop, .dock, input, textarea, select, [data-noptr]");
  document.addEventListener("touchstart", (e) => {
    pull = 0;
    if (!canStart(e)) { y0 = null; return; }
    x0 = e.touches[0].clientX; y0 = e.touches[0].clientY;
  }, { passive: true });
  document.addEventListener("touchmove", (e) => {
    if (y0 == null) return;
    const dx = e.touches[0].clientX - x0, dy = e.touches[0].clientY - y0;
    // Sideways swipes (the Up Next row) and upward scrolls aren't pulls.
    if (!pull && (Math.abs(dx) > Math.abs(dy) || dy < 0)) { y0 = null; return; }
    if (window.scrollY > 0) { y0 = null; if (pull) { pull = 0; paint(0, true); } return; }
    pull = Math.max(0, Math.min(MAX, dy * 0.55));
    if (pull > 0) e.preventDefault(); // keep the page itself from bouncing while you pull
    paint(pull);
  }, { passive: false });
  const release = async () => {
    if (y0 == null) return;
    y0 = null;
    if (pull < TRIGGER) { if (pull) paint(0, true); pull = 0; return; }
    pull = 0; busy = true;
    ptr.classList.add("busy");
    paint(REST, true);
    if (navigator.vibrate) try { navigator.vibrate(8); } catch {}
    const minSpin = new Promise((r) => setTimeout(r, 600));
    try { await pullRefresh(); } catch {}
    await minSpin;
    busy = false;
    ptr.classList.remove("busy");
    paint(0, true);
  };
  document.addEventListener("touchend", release, { passive: true });
  document.addEventListener("touchcancel", release, { passive: true });
})();

// ------------------------------------------------------------------ boot
async function boot() {
  route();
  paintPill();
  if (!cfg?.ready) return;
  const downloadsReady = prepareAllDownloads();
  try {
    await Promise.all([refreshSubs(), refreshIndex(), refreshRun()]);
  } catch (e) {
    if (e instanceof AuthError) return authProblem();
    if (e instanceof KeyMismatch) showShowsKeyProblem();
    else if (!navigator.onLine) toast("You're offline. Downloaded episodes still play.");
    else if (!index) toast(e.message || "Couldn't load your shows.");
  }
  paintPill();
  rerenderIfList();
  if (pendingOpen) openFromLink(pendingOpen);
  await downloadsReady;
  await cleanupPlayed(true);
  prematch();
  autoDownload();
  const cur = LS.get("current", null);
  if (cur && !player.ep && findEpisode(cur)) {
    // Load the last episode into the mini player without playing.
    player.open(cur, false, false);
  }
  // Keep things fresh: ask for a scan when the last one is old.
  const stale = !status?.finished || Date.now() / 1000 - status.finished > 90 * 60;
  const running = status?.state === "running" || (lastRun && lastRun.status !== "completed");
  if ((subs?.feeds || []).length && stale && !running) scanNow(true);
  if (running) startPolling();
}

document.addEventListener("visibilitychange", async () => {
  if (document.visibilityState !== "visible" || !cfg?.ready) return;
  try { await Promise.all([refreshIndex(), refreshRun()]); } catch (e) { if (e instanceof AuthError) return authProblem(); }
  paintPill();
  rerenderIfList();
  if (status?.state === "running" || (lastRun && lastRun.status !== "completed")) startPolling();
});

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
boot();
