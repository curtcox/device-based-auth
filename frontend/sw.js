// Service worker for security notices (master plan §10). It only shows the notices
// devicebasedauth.org pushes to this browser; it never intercepts page requests.
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = { body: event.data ? event.data.text() : '' }; }
  // Notices only ever link back into this site's dashboard.
  let url = '/app.html';
  try { if (typeof data.url === 'string' && new URL(data.url, self.location.origin).origin === self.location.origin) url = data.url; } catch { /* keep the default */ }
  event.waitUntil(self.registration.showNotification(String(data.title || 'devicebasedauth.org').slice(0, 100), {
    body: String(data.body || '').slice(0, 300), tag: typeof data.tag === 'string' ? data.tag : undefined, icon: '/favicon.svg', data: { url }
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(self.clients.openWindow(event.notification.data?.url || '/app.html'));
});
