// Keeps the app itself available offline. Podcast audio and your data
// always come from the network.
const CACHE = "podskip-shell-v8";
const SHELL = ["./", "index.html", "app.css?v=8", "app.js?v=8", "manifest.webmanifest", "icons/icon-192.png", "icons/apple-touch-icon.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k.startsWith("podskip-shell-") && k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  // Network first so updates show up right away; the cache covers offline.
  // Ask the server whether files changed (instead of trusting the browser cache),
  // so app updates show up the next time you open Podskip.
  e.respondWith(
    fetch(e.request.url, { cache: "no-cache", credentials: "same-origin" })
      .then((res) => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: true }).then((r) => r || caches.match("index.html")))
  );
});

// Notifications sent by the scan job when an episode's ads are removed.
self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data ? e.data.text() : "" }; }
  e.waitUntil(
    self.registration.showNotification(d.title || "Podskip", {
      body: d.body || "",
      tag: d.tag || undefined,
      icon: "icons/icon-192.png",
      badge: "icons/icon-192.png",
      data: { url: d.url || "./" },
    })
  );
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "./", self.registration.scope).href;
  e.waitUntil(
    (async () => {
      const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      for (const w of wins) {
        if (w.url.startsWith(self.registration.scope)) {
          w.postMessage({ open: new URL(url).hash || "#listen" });
          return w.focus();
        }
      }
      return self.clients.openWindow(url);
    })()
  );
});
