const CACHE = "kazstem-browser-d0df783b4a51-v4";
const CORE = [
  "./", "./index.html", "./styles.css", "./app.js", "./worker.js", "./csr.js", "./analysis.js", "./casefold.js", "./formats.js",
  "./manifest.webmanifest", "./icons/icon.svg", "./resources/resource-manifest.json", "./resources/probe-ledger-summary.json", "./resources/analyzer.kzc",
  "./legal/LICENSE", "./legal/THIRD_PARTY.md", "./legal/SOURCE.md", "./legal/SOURCE-ARCHIVE.json",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(CORE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) => Promise.all(names.filter((name) => name !== CACHE).map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request).then((response) => {
      if (!response.ok) return response;
      const copy = response.clone();
      caches.open(CACHE).then((cache) => cache.put(event.request, copy));
      return response;
    })).catch(() => event.request.mode === "navigate" ? caches.match("./index.html") : Response.error()),
  );
});
