const CACHE_NAME = "scam-analyzer-v3";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.json",
  "./css/styles.css",
  "./js/i18n.js",
  "./js/rules.js",
  "./js/links.js",
  "./js/email.js",
  "./js/scoring.js",
  "./js/history.js",
  "./js/ai.js",
  "./js/charts.js",
  "./js/ui.js",
  "./js/app.js",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) =>
      Promise.all(ASSETS.map((url) => cache.add(url).catch(() => null)))
    )
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // AI second-opinion requests always go to the network (user's own key).
  if (/^https?:\/\/(generativelanguage\.googleapis|api\.anthropic\.com)/i.test(url.href)) {
    return;
  }
  if (event.request.method !== "GET") return;

  const isNavigation =
    event.request.mode === "navigate" ||
    url.pathname.endsWith("/") ||
    url.pathname.endsWith(".html");

  if (isNavigation) {
    // Pages are network-first so a new deploy always reaches the user.
    event.respondWith(
      fetch(event.request)
        .then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(event.request, copy));
            // Keep bundled assets in step with the fresh HTML.
            caches
              .open(CACHE_NAME)
              .then((c) => Promise.all(ASSETS.map((a) => c.add(a).catch(() => null))));
          }
          return res;
        })
        .catch(() =>
          caches.match(event.request).then((r) => r || caches.match("./index.html"))
        )
    );
    return;
  }

  // Static assets: serve from cache instantly, refresh in the background.
  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(event.request, copy));
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
