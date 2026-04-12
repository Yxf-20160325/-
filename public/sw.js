// Service Worker for Push Notifications
const CACHE_NAME = 'chatroom-notifications-v1';

// 安装事件
self.addEventListener('install', (event) => {
    console.log('Service Worker installed');
    self.skipWaiting();
});

// 激活事件
self.addEventListener('activate', (event) => {
    console.log('Service Worker activated');
    event.waitUntil(clients.claim());
});

// 推送事件处理
self.addEventListener('push', (event) => {
    console.log('Push received:', event);
    
    let data = {
        title: '聊天室通知',
        body: '有新消息',
        icon: '/icon.png',
        badge: '/badge.png',
        tag: 'chatroom-notification'
    };
    
    if (event.data) {
        try {
            data = { ...data, ...event.data.json() };
        } catch (e) {
            data.body = event.data.text();
        }
    }
    
    const options = {
        body: data.body,
        icon: data.icon || '/icon.png',
        badge: data.badge || '/badge.png',
        tag: data.tag || 'chatroom-notification',
        requireInteraction: data.requireInteraction || false,
        vibrate: [200, 100, 200],
        data: {
            url: data.url || '/',
            timestamp: Date.now()
        }
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// 通知点击事件
self.addEventListener('notificationclick', (event) => {
    console.log('Notification clicked:', event);
    event.notification.close();
    
    const url = event.notification.data?.url || '/';
    
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            // 如果已有窗口，打开它
            for (const client of clientList) {
                if (client.url === url && 'focus' in client) {
                    return client.focus();
                }
            }
            // 否则打开新窗口
            if (clients.openWindow) {
                return clients.openWindow(url);
            }
        })
    );
});

// 通知关闭事件
self.addEventListener('notificationclose', (event) => {
    console.log('Notification closed');
});
