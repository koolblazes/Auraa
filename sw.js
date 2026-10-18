// AURAA Service Worker — v1.0
// Minimal service worker required for TWA (Trusted Web Activity).
// Provides offline fallback and caches the app shell.

const CACHE_NAME = 'auraa-v1';
const OFFLINE_URL = '/offline.html';

// Install: cache the offline page
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll([
      '/',
      '/offline.html',
      '/manifest.json'
    ]))
  );
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Fetch: network-first, fall back to cache, then offline page
self.addEventListener('fetch', event => {
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request).catch(() =>
        caches.match(event.request).then(r => r || caches.match(OFFLINE_URL))
      )
    );
  }
});
