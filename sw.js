/* Vigie – service worker : ouverture hors ligne, mises à jour, notifications SOS.
   Changez VERSION à chaque mise à jour des fichiers pour que les téléphones la récupèrent. */
const VERSION = 'vigie-v7';
const SHELL = ['./', './index.html', './manifest.webmanifest', './vendor/jsQR.js', './vendor/qrcode.js', './vendor/supabase.js',
  './icons/icon-192.png', './icons/icon-512.png', './icons/apple-touch-icon.png',
  ...Array.from({ length: 10 }, (_, i) => './slides/slide-' + String(i + 1).padStart(2, '0') + '.jpg')];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
const networkFirst = (req, key) => fetch(req).then(r => { if (r && r.ok) { const copy = r.clone(); caches.open(VERSION).then(c => c.put(key || req, copy)); } return r; }).catch(() => caches.match(key || req));
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (req.mode === 'navigate') { e.respondWith(networkFirst(req, './index.html')); return; }
  if (url.origin === location.origin && url.pathname.endsWith('/config.js')) { e.respondWith(networkFirst(req)); return; }
  // Supabase (données, connexion, temps réel) : jamais mis en cache
  if (url.hostname.endsWith('supabase.co') || url.hostname.endsWith('supabase.in')) return;
  if (url.origin === location.origin || url.hostname.endsWith('fonts.googleapis.com') || url.hostname.endsWith('fonts.gstatic.com')) {
    e.respondWith(caches.match(req).then(hit => {
      const net = fetch(req).then(r => { if (r && (r.ok || r.type === 'opaque')) { const copy = r.clone(); caches.open(VERSION).then(c => c.put(req, copy)); } return r; }).catch(() => hit);
      return hit || net;
    }));
  }
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    for (const c of list) { if ('focus' in c) { c.navigate && c.navigate('./index.html#accueil'); return c.focus(); } }
    return self.clients.openWindow('./index.html#accueil');
  }));
});
