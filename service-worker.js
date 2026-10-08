const CACHE_NAME = "scam-analyzer-v2";
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
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
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
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request))
  );
});