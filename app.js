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
function toast(msg, action) {
  const t = $("#toast");
  t.innerHTML = `<span>${esc(msg)}</span>` + (action ? `<button type="button">${esc(action.label)}</button>` : "");
  t.hidden = false;
  if (action) $("button", t).onclick = () => { t.hidden = true; action.run(); };
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), action ? 6000 : 3200);
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
let prefs = Object.assign({ skip: { sponsor: true, promo: true, self: false }, speed: 1 }, LS.get("prefs", {}));
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
async function unseal(buf) {
  const u = new Uint8Array(buf);
  if (String.fromCharCode(u[0], u[1], u[2], u[3]) !== "PSK1") throw new Error("not a Podskip file");
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(4, 16), additionalData: AAD }, await key(), u.slice(16));
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
async function rawFile(path) {
  const r = await gh(`${repoPath()}/contents/${path}?ref=data`, { accept: "application/vnd.github.raw+json" });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`Couldn't load ${path} (${r.status})`);
  return r.arrayBuffer();
}

async function loadSubs() {
  const r = await gh(`${repoPath()}/contents/subs.enc?ref=data`);
  if (r.status === 404) return { obj: null, sha: null };
  if (!r.ok) throw new Error(`Couldn't load your shows (${r.status})`);
  const j = await r.json();
  const bytes = j.content ? unb64(j.content) : new Uint8Array(await rawFile("subs.enc"));
  return { obj: await unseal(bytes), sha: j.sha };
}

async function changeSubs(mutate, message) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const { obj, sha } = await loadSubs();
    const next = obj || { v: 1, feeds: [], want: [], perShow: 3 };
    mutate(next);
    const r = await gh(`${repoPath()}/contents/subs.enc`, {
      method: "PUT",
      body: { message, content: b64(await seal(next)), branch: "data", ...(sha ? { sha } : {}) },
    });
    if (r.ok) { subs = next; return next; }
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
  return r.ok;
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
}

async function scanNow(quiet) {
  try {
    await ghJson(`${repoPath()}/actions/workflows/scan.yml/dispatches`, { method: "POST", body: { ref: "main" } });
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
  const s = await rawFile("status.json");
  if (s) { status = JSON.parse(new TextDecoder().decode(s)); LS.set("status", status); }
  const buf = await rawFile("index.enc");
  if (buf) {
    try {
      index = await unseal(buf);
      LS.set("index", index);
    } catch {
      showKeyMismatch();
    }
  }
}

async function refreshSubs() {
  const { obj } = await loadSubs();
  subs = obj;
}

let epCache;
async function loadEpisode(id) {
  const done = index?.scanned?.[id];
  if (!done) return null;
  const memo = `${id}-${done.at}`;
  if (episodes.has(memo)) return episodes.get(memo);
  const cacheKey = `/podskip-cache/eps/${id}-${done.at}`;
  let buf = null;
  try {
    epCache = epCache || (await caches.open("podskip-eps"));
    const hit = await epCache.match(cacheKey);
    if (hit) buf = await hit.arrayBuffer();
  } catch {}
  if (!buf) {
    buf = await rawFile(`eps/${id}.enc`);
    if (!buf) return null;
    try { await epCache?.put(cacheKey, new Response(buf.slice(0))); } catch {}
  }
  const a = await unseal(buf);
  episodes.set(memo, a);
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
const routes = { listen: viewListen, shows: viewShows, search: viewSearch, settings: viewSettings };

function route() {
  if (!cfg?.ready) return viewSetup();
  const h = location.hash.replace(/^#/, "") || "listen";
  $$("#tabs a").forEach((a) => a.toggleAttribute("aria-current", false));
  const tab = h.startsWith("show-") ? "shows" : h;
  const link = $(`#tabs a[data-tab="${tab}"]`);
  if (link) link.setAttribute("aria-current", "page");
  if (h.startsWith("show-")) return viewShow(h.slice(5));
  (routes[h] || viewListen)();
}
window.addEventListener("hashchange", () => { route(); window.scrollTo(0, 0); });

function epRow(ep, showShow = true) {
  const st = epState(ep);
  const p = progress[ep.id];
  const pct = p && p.d ? Math.min(100, (p.t / p.d) * 100) : 0;
  const meta = [day(ep.date), length(ep.dur)].filter(Boolean).join(" · ");
  return `<button class="ep ${p?.done ? "played" : ""}" type="button" data-ep="${esc(ep.id)}">
    ${artImg(ep.img || ep.showImg, ep.show)}
    <span class="ep-main">
      ${showShow ? `<span class="ep-show">${esc(ep.show)}</span>` : ""}
      <span class="ep-title">${esc(ep.title)}</span>
      <span class="ep-meta">${stateChip(st)}<span>${esc(meta)}</span>${pct > 1 && !p.done ? `<span class="ep-prog"><i style="width:${pct.toFixed(0)}%"></i></span>` : ""}${p?.done ? "<span>Played</span>" : ""}</span>
    </span>
  </button>`;
}
function bindEpRows(root = view) {
  $$("[data-ep]", root).forEach((b) => (b.onclick = () => openEpisode(b.dataset.ep, true)));
}

function viewListen() {
  const eps = allEpisodes().sort((a, b) => b.date - a.date);
  const feedsPending = (subs?.feeds || []).length && !eps.length;
  const resumeId = LS.get("current", null);
  const resume = resumeId && findEpisode(resumeId);
  const rp = resume && progress[resume.id];
  let html = "";
  if (resume && rp && !rp.done && rp.t > 10 && (!player.ep || player.ep.id !== resume.id)) {
    html += `<div class="section"><h2 class="h2">Pick up where you left off</h2>
      <button class="card resume" type="button" data-ep="${esc(resume.id)}">${artImg(resume.img || resume.showImg, resume.show)}
      <span class="ep-main"><span class="ep-show">${esc(resume.show)}</span><span class="ep-title">${esc(resume.title)}</span>
      <span class="ep-meta"><span>${clock(rp.d - rp.t)} left</span></span></span></button></div>`;
  }
  if (!eps.length) {
    html += feedsPending
      ? `<div class="empty"><span class="splice"></span><h2 class="h1">Fetching your shows</h2><p class="lede">The first scan is getting your episodes. This page fills in when it's done, usually within a few minutes.</p></div>`
      : `<div class="empty"><span class="splice"></span><h2 class="h1">No shows yet</h2><p class="lede">Add a podcast and Podskip will scan its newest episodes for ads.</p><a class="btn" href="#search">Add a show</a></div>`;
  } else {
    html += `<div class="section"><h2 class="h2">Latest episodes</h2><div class="list">${eps.slice(0, 60).map((e) => epRow(e)).join("")}</div></div>`;
  }
  view.innerHTML = html;
  bindEpRows();
}

function viewShows() {
  const feeds = subs?.feeds || [];
  if (!feeds.length) {
    view.innerHTML = `<div class="empty"><span class="splice"></span><h2 class="h1">No shows yet</h2><a class="btn" href="#search">Add a show</a></div>`;
    return;
  }
  view.innerHTML = `<div class="section"><h1 class="h1">Your shows</h1><div class="grid" id="tiles"></div></div>`;
  Promise.all(feeds.map(async (f) => {
    const fid = await sha1hex(f.url, 12);
    const live = index?.feeds?.[fid];
    const title = live?.title || f.title;
    return `<a class="tile" href="#show-${fid}">${artImg(live?.image || f.image, title)}<span class="tile-name">${esc(title)}</span>${live ? (live.error ? `<span class="chip fail">Feed problem</span>` : "") : `<span class="chip busy">Fetching</span>`}</a>`;
  })).then((t) => { const el = $("#tiles"); if (el) el.innerHTML = t.join(""); });
}

async function viewShow(fid) {
  const f = index?.feeds?.[fid];
  let sub = null;
  for (const s of subs?.feeds || []) if ((await sha1hex(s.url, 12)) === fid) sub = s;
  if (!f && !sub) { location.hash = "#shows"; return; }
  const title = f?.title || sub.title;
  const eps = (f?.episodes || []).map((e) => ({ ...e, fid, show: title, showImg: f.image }));
  view.innerHTML = `<div class="section">
    <div class="showhead">${artImg(f?.image || sub?.image, title)}<div style="display:grid;gap:6px;min-width:0"><h1 class="h1" style="font-size:24px">${esc(title)}</h1><span class="muted small">${esc(f?.author || sub?.author || "")}</span></div></div>
    ${f?.error ? `<div class="card"><p class="err">Podskip couldn't read this show's feed last time: ${esc(f.error)}</p></div>` : ""}
    ${f?.desc ? `<p class="desc">${esc(f.desc)}</p>` : ""}
    <div class="row"><button class="btn danger small" id="unsub" type="button">Remove show</button></div>
  </div>
  <div class="section"><h2 class="h2">Episodes</h2>
    ${eps.length ? `<div class="list">${eps.map((e) => epRow(e, false)).join("")}</div>` : `<p class="muted">Episodes appear after the next scan.</p>`}
  </div>`;
  bindEpRows();
  $("#unsub").onclick = async (ev) => {
    const b = ev.currentTarget;
    if (b.dataset.sure !== "1") { b.dataset.sure = "1"; b.textContent = "Tap again to remove"; return; }
    b.disabled = true;
    try {
      await changeSubs((s) => { s.feeds = s.feeds.filter((x) => x.url !== (sub?.url || f.url)); }, "Remove a show");
      if (index?.feeds) delete index.feeds[fid];
      LS.set("index", index);
      toast("Show removed");
      location.hash = "#shows";
    } catch (e) { handleErr(e); b.disabled = false; }
  };
}

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
    <h1 class="h1">Add a show</h1>
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
  <div class="section"><h1 class="h1">Settings</h1></div>
  <div class="section"><h2 class="h2">What to skip</h2>
    <div class="card" style="gap:0;padding-block:6px">
      ${toggleRow("sponsor", "Ads and sponsor reads", "Ad breaks, host-read ads, “brought to you by”")}
      ${toggleRow("promo", "Promos for other shows", "Trailers and network plugs")}
      ${toggleRow("self", "The show's own plugs", "Patreon, merch, “leave a review”")}
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
      <a class="btn ghost small" href="https://github.com/${esc(cfg.owner)}/${esc(cfg.repo)}/actions/workflows/scan.yml" target="_blank" rel="noopener">See scan log</a></div>
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
      <a class="btn ghost small" href="https://github.com/${esc(cfg.owner)}/${esc(cfg.repo)}/settings/secrets/actions/PODSKIP_KEY" target="_blank" rel="noopener">Open GitHub secret</a></div>
    </div>
  </div>
  <div class="section"><h2 class="h2">This device</h2>
    <div class="card">
      <dl class="kv"><dt>Repository</dt><dd>${esc(cfg.owner)}/${esc(cfg.repo)}</dd></dl>
      <div class="row"><button class="btn danger small" id="signout" type="button">Disconnect this phone</button></div>
      <p class="muted small">Disconnecting removes your token and key from this phone. Your shows stay on GitHub.</p>
    </div>
  </div>`;
  $$("[data-skip]").forEach((i) => (i.onchange = () => { prefs.skip[i.dataset.skip] = i.checked; savePrefs(); player.refreshAds(); }));
  $$("#perShow button").forEach((b) => (b.onclick = async () => {
    $$("#perShow button").forEach((x) => x.setAttribute("aria-pressed", x === b));
    try { await changeSubs((s) => { s.perShow = +b.dataset.n; }, "Change scan depth"); scanNow(true); toast("Saved"); } catch (e) { handleErr(e); }
  }));
  $("#scan").onclick = () => scanNow();
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
  const secretUrl = `https://github.com/${esc(cfg.owner)}/${esc(cfg.repo)}/settings/secrets/actions/${setup.fresh ? "PODSKIP_KEY" : "new"}`;
  return `<p class="small">Copy this value, then ${setup.fresh ? "replace your" : "add it as a"} secret named <b>PODSKIP_KEY</b>${setup.fresh ? " with it" : ""}.</p>
    <div class="secretbox">${esc(secretValue())}</div>
    <div class="row"><button class="btn secondary small" id="copy3" type="button">Copy value</button></div>
    <ol class="howto small">
      <li><a href="${secretUrl}" target="_blank" rel="noopener">Open the secret page</a>.</li>
      <li>${setup.fresh ? "Paste the value into the secret" : "Name: <b>PODSKIP_KEY</b>. Secret: paste the value"}.</li>
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

// ------------------------------------------------------------------ errors
function handleErr(e) {
  if (e instanceof AuthError) return authProblem();
  toast(e.message || "Something went wrong.");
}
function authProblem() {
  const b = $("#banner");
  b.hidden = false;
  b.innerHTML = `<div class="card"><p><b>GitHub stopped accepting your token.</b> It may have expired. Make a new one and connect again.</p>
    <div class="row"><button class="btn small" id="reauth" type="button">Connect again</button></div></div>`;
  $("#reauth").onclick = () => { cfg.token = null; cfg.ready = false; LS.set("cfg", cfg); b.hidden = true; location.hash = ""; viewSetup(); };
}
function showKeyMismatch() {
  const b = $("#banner");
  b.hidden = false;
  b.innerHTML = `<div class="card"><p><b>Your scans can't be opened with this phone's key.</b> The PODSKIP_KEY secret on GitHub probably has a different value. Copy the value from Settings into the secret, then tap Scan now.</p>
    <div class="row"><a class="btn small" href="#settings">Open Settings</a></div></div>`;
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
$("#scanpill").onclick = () => (location.hash = "#settings");

let pollTimer = null;
function startPolling() {
  if (pollTimer) return;
  const tick = async () => {
    pollTimer = null;
    try {
      await Promise.all([refreshIndex(), refreshRun()]);
    } catch (e) { if (e instanceof AuthError) return authProblem(); }
    paintPill();
    rerenderIfList();
    player.retryAnalysis();
    const busy = status?.state === "running" || (lastRun && lastRun.status !== "completed") || Date.now() - dispatchedAt < 90000;
    if (busy && document.visibilityState === "visible") pollTimer = setTimeout(tick, 15000);
  };
  pollTimer = setTimeout(tick, 4000);
}
function rerenderIfList() {
  const h = location.hash.replace("#", "") || "listen";
  if (["listen", "shows"].includes(h) || h.startsWith("show-")) {
    const y = window.scrollY;
    route();
    window.scrollTo(0, y);
  }
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
    const a = P.analysis;
    P.plan = []; P.align = "exact"; P.D = 0; P.pivot = null;
    if (!a) return;
    const raw = a.ads.map((x, i) => ({ s: x.s, e: x.e, idx: [i], types: [x.type], who: x.who }));
    const dur = audio.duration;
    if (!isFinite(dur) || !dur || Math.abs(dur - a.dur) <= tolerance(a.dur)) { P.plan = raw; return; }
    const D = dur - a.dur;
    P.D = D;
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
  const toStream = (t) => (P.align === "shifted" && (!P.pivot || t >= P.pivot.e) ? t + P.D : t);
  const fromStream = (t) => (P.align === "shifted" && (!P.pivot || t >= P.pivot.e + P.D) ? t - P.D : t);
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
      audio.currentTime = hit.e;
      P.skipped++; P.saved += hit.e - Math.max(t, hit.s);
      const type = hit.types[0];
      const label = hit.who ? `Skipped ${hit.who}` : type === "self" ? "Skipped a plug" : type === "promo" ? "Skipped a promo" : "Skipped an ad";
      toast(`${label} · ${clock(hit.e - hit.s)}`, { label: "Play it", run: () => { hit.idx.forEach((i) => P.kept.add(i)); audio.currentTime = hit.s; paintScrub(); paintNote(); if (P.tab === "ads") paintPane(); } });
      paintNote();
    }
    const next = ads.filter((a) => a.s > audio.currentTime).sort((a, b) => a.s - b.s)[0];
    if (next && !audio.paused) {
      const ms = ((next.s - audio.currentTime) / (audio.playbackRate || 1)) * 1000;
      P.skipTimer = setTimeout(checkSkip, Math.max(50, ms + 30));
    }
  }

  function checkMatch() {
    if (!P.analysis) return;
    const was = P.align + P.D.toFixed(1);
    buildPlan();
    if (P.align + P.D.toFixed(1) !== was) { paintNote(); paintScrub(); if (P.tab === "transcript" || P.tab === "chapters") paintPane(); }
  }

  function paintNote() {
    const n = $("#p-note");
    n.className = "p-note";
    const st = P.ep ? epState(P.ep) : null;
    if (!P.ep) { n.hidden = true; return; }
    if (P.analysis && P.align === "unknown" && !P.force) {
      n.classList.add("warn");
      n.innerHTML = `<span>This stream is ${clock(Math.abs(audio.duration - P.analysis.dur))} ${audio.duration > P.analysis.dur ? "longer" : "shorter"} than the copy Podskip scanned, so the show probably served different ads. Automatic skipping is off for this episode.</span>
        <span class="row"><button class="btn small secondary" id="force" type="button">Skip anyway</button><button class="btn small ghost" id="rescan" type="button">Scan again</button></span>`;
      $("#force").onclick = () => { P.force = true; buildPlan(); paintNote(); paintScrub(); checkSkip(); };
      $("#rescan").onclick = () => requestScan(true);
      n.hidden = false;
      return;
    }
    if (P.analysis) {
      const ads = activeAds();
      if (!P.analysis.ads.length) { n.innerHTML = `<span>No ads found in this episode.</span>`; n.hidden = false; return; }
      const total = ads.reduce((s, a) => s + (a.e - a.s), 0);
      const shifted = P.align === "shifted" ? ` Your stream's ads run ${clock(Math.abs(P.D))} ${P.D > 0 ? "longer" : "shorter"} than the scanned copy, so the skip times were adjusted.` : "";
      n.innerHTML = P.skipped
        ? `<span>Skipped ${P.skipped} ad${P.skipped > 1 ? "s" : ""}, saved ${clock(P.saved)} so far.${shifted}</span>`
        : `<span>${ads.length ? `Skipping ${ads.length} ad${ads.length > 1 ? "s" : ""} (${clock(total)}).` : "Ads found, but your settings keep them all."}${shifted}${P.analysis.det === "keywords" ? " Found with keyword rules, so some may be missed." : ""}</span>`;
      n.hidden = false;
      return;
    }
    if (st?.kind === "scanning") { n.innerHTML = `<span>Scanning this episode now. Ads will be skipped once it's done.</span>`; n.hidden = false; return; }
    if (st?.kind === "queued") { n.innerHTML = `<span>Waiting in line to be scanned. You can listen now; ads will be skipped once it's scanned.</span>`; n.hidden = false; return; }
    if (st?.kind === "failed") {
      n.classList.add("warn");
      n.innerHTML = `<span>Podskip couldn't scan this episode: ${esc(index?.failed?.[P.ep.id]?.err || "unknown error")}</span><span class="row"><button class="btn small secondary" id="rescan" type="button">Try again</button></span>`;
      $("#rescan").onclick = () => requestScan(true); n.hidden = false; return;
    }
    n.innerHTML = `<span>This episode hasn't been scanned, so ads won't be skipped.</span><span class="row"><button class="btn small" id="rescan" type="button">Scan this episode</button></span>`;
    $("#rescan").onclick = () => requestScan(false);
    n.hidden = false;
  }

  async function requestScan(again) {
    const id = P.ep.id;
    try {
      const now = Math.floor(Date.now() / 1000);
      await changeSubs((s) => {
        s.want = [id, ...(s.want || []).filter((x) => x !== id)].slice(0, 20);
        if (again) {
          const r = { ...(s.rescan && typeof s.rescan === "object" ? s.rescan : {}), [id]: now };
          // Keep only the 20 newest requests.
          s.rescan = Object.fromEntries(Object.entries(r).sort((a, b) => b[1] - a[1]).slice(0, 20));
        }
      }, "Scan an episode");
      toast("Scan requested. It usually takes a few minutes.");
      scanNow(true);
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
    if (P.tab === "transcript") followTranscript();
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
    $$(".ptabs button").forEach((b) => b.setAttribute("aria-selected", b.dataset.ptab === P.tab));
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
      const ads = a?.ads || [];
      const names = { sponsor: "Ad", promo: "Promo", self: "Show plug" };
      pane.innerHTML = !a ? `<p class="muted">Ads are listed after the episode is scanned.</p>` : !ads.length ? `<p class="muted">No ads found.</p>` :
        `<div>${ads.map((x, i) => {
          const off = !prefs.skip[x.type];
          const kept = P.kept.has(i);
          return `<div class="adrow ${kept ? "kept" : ""} ${off ? "off" : ""}"><span class="stripe"></span>
            <div class="adrow-main"><span class="adrow-head">${esc(x.who || names[x.type])}</span>
              <span class="adrow-sub">${names[x.type]} · ${clock(x.s)}–${clock(x.e)} · ${clock(x.e - x.s)} · ${Math.round(x.conf * 100)}% sure</span>
              ${x.quote ? `<q>${esc(x.quote)}</q>` : ""}</div>
            ${off ? `<span class="chip">Kept</span>` : `<button class="btn small ${kept ? "secondary" : "ghost"}" type="button" data-keep="${i}">${kept ? "Skip it" : "Keep"}</button>`}</div>`;
        }).join("")}</div><p class="muted small">Keep an ad to hear it this time. Change which kinds get skipped in Settings.</p>`;
      $$("[data-keep]", pane).forEach((b) => (b.onclick = () => {
        const i = +b.dataset.keep;
        P.kept.has(i) ? P.kept.delete(i) : P.kept.add(i);
        paintPane(); paintScrub(); paintNote(); checkSkip();
      }));
    } else if (P.tab === "transcript") {
      if (!a) { pane.innerHTML = `<p class="muted">The transcript appears after the episode is scanned.</p>`; return; }
      pane.innerHTML = `<div class="tsearch"><div class="searchbar"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>
        <input class="input" id="tq" type="search" placeholder="Search the transcript" value="${esc(P.tq)}" aria-label="Search the transcript"></div><span class="tcount" id="tcount"></span></div>
        <div id="tlines"></div>`;
      const q = $("#tq");
      q.oninput = () => { P.tq = q.value; paintLines(); };
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
    box.innerHTML = hits.slice(0, 4000).map(([l, i]) => {
      const isAd = ads.some((a) => l[0] >= a.s - 0.5 && l[1] <= a.e + 0.5);
      const text = rx ? esc(l[2]).replace(rx, (m) => `<mark>${m}</mark>`) : esc(l[2]);
      return `<button class="tline ${isAd ? "ad" : ""}" type="button" data-i="${i}" data-t="${l[0]}"><time>${clock(l[0])}</time><span>${text}</span></button>`;
    }).join("");
    $$("[data-t]", box).forEach((b) => (b.onclick = () => seek(toStream(+b.dataset.t), true)));
    P.followAt = -1;
    followTranscript(true);
  }

  function followTranscript(jump) {
    const box = $("#tlines");
    if (!box || !P.analysis) return;
    const t = fromStream(audio.currentTime);
    const lines = P.analysis.lines;
    let lo = 0, hi = lines.length - 1, idx = -1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (lines[m][0] <= t) { idx = m; lo = m + 1; } else hi = m - 1; }
    if (idx === P.followAt) return;
    P.followAt = idx;
    $$(".tline.now", box).forEach((x) => x.classList.remove("now"));
    const cur = box.querySelector(`[data-i="${idx}"]`);
    if (cur) {
      cur.classList.add("now");
      if (!P.tq && (jump || !audio.paused)) {
        const r = cur.getBoundingClientRect();
        if (jump || r.top < 120 || r.bottom > innerHeight - 80) cur.scrollIntoView({ block: "center", behavior: jump ? "auto" : "smooth" });
      }
    }
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
      Object.assign(P, { ep, analysis: null, align: "exact", D: 0, plan: [], pivot: null, force: false, kept: new Set(), skipped: 0, saved: 0, tq: "" });
      LS.set("current", id);
      audio.src = https(ep.url);
      audio.playbackRate = prefs.speed;
      audio.defaultPlaybackRate = prefs.speed;
      const p = progress[id];
      P.resumeAt = p && !p.done && p.t > 5 ? p.t : 0;
      if (play) audio.play().catch(() => {});
      $("#p-art").src = https(ep.img || ep.showImg || "");
      $("#p-show").textContent = ep.show;
      $("#p-title").textContent = ep.title;
      $("#scrub-ads").dataset.key = "";
      P.tab = "about";
      mediaSession();
      paintMini();
      loadAnalysis();
    } else if (play && audio.paused) {
      audio.play().catch(() => {});
    }
    if (!show) return;
    el.hidden = false;
    document.body.style.overflow = "hidden";
    $("#c-speed").textContent = speedLabel(prefs.speed);
    paintNote(); paintScrub(); paintPane();
  }
  async function loadAnalysis() {
    const id = P.ep.id;
    try {
      const a = await loadEpisode(id);
      if (!P.ep || P.ep.id !== id || !a) return;
      P.analysis = a;
      checkMatch();
      paintNote(); paintScrub(); if (P.isOpen()) paintPane();
      checkSkip();
    } catch (e) {
      if (e instanceof AuthError) authProblem();
    }
  }
  P.retryAnalysis = () => {
    if (!P.ep) return;
    const sc = index?.scanned?.[P.ep.id];
    if (sc && (!P.analysis || P.analysis.at < sc.at)) loadAnalysis();
    else paintNote();
  };
  P.refreshAds = () => { if (P.ep) { buildPlan(); paintNote(); paintScrub(); checkSkip(); } };

  function close() {
    el.hidden = true;
    document.body.style.overflow = "";
    paintMini();
  }

  function saveNow() {
    if (!P.ep || !isFinite(audio.duration) || !audio.duration) return;
    const d = audio.duration, t = audio.currentTime;
    progress[P.ep.id] = { t, d, done: d - t < Math.max(30, d * 0.02), at: Date.now() };
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
  $$(".ptabs button").forEach((b) => (b.onclick = () => { P.tab = b.dataset.ptab; paintPane(); }));
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
    checkMatch(); paintScrub(); positionState();
  });
  audio.addEventListener("durationchange", () => { checkMatch(); paintScrub(); });
  audio.addEventListener("timeupdate", () => {
    checkSkip();
    if (P.isOpen()) paintScrub();
    paintMini();
    positionState();
    if (Date.now() - P.lastSave > 5000) { P.lastSave = Date.now(); saveNow(); }
  });
  audio.addEventListener("play", () => { el.classList.add("playing"); paintMini(); checkSkip(); lastPos = 0; positionState(); });
  audio.addEventListener("pause", () => { el.classList.remove("playing"); paintMini(); saveNow(); clearTimeout(P.skipTimer); });
  audio.addEventListener("seeked", () => { checkSkip(); lastPos = 0; positionState(); });
  audio.addEventListener("progress", () => { if (P.isOpen()) paintScrub(); });
  audio.addEventListener("ended", () => { saveNow(); paintMini(); });
  audio.addEventListener("error", () => {
    if (P.ep) toast("This episode won't play. The podcast's server may be down, or the file was removed.");
  });
  addEventListener("pagehide", saveNow);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") saveNow(); });

  P.open = open;
  return P;
})();

function openEpisode(id, play) { player.open(id, play); }

// ------------------------------------------------------------------ boot
async function boot() {
  route();
  paintPill();
  if (!cfg?.ready) return;
  try {
    await Promise.all([refreshSubs(), refreshIndex(), refreshRun()]);
  } catch (e) {
    if (e instanceof AuthError) return authProblem();
    if (!index) toast(e.message || "Couldn't load your shows.");
  }
  paintPill();
  rerenderIfList();
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
