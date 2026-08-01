// LIAS Dashboard Core Application
// File:    apps/lias/web/src/main.js
// Version: 1.0

import { devicesView } from './views/devices.js';

const state = {
    devices: [],
    tags: [],
    policies: [],
    schedules: []
};

const listeners = {};

export function subscribe(event, callback) {
    if (!listeners[event]) listeners[event] = [];
    listeners[event].push(callback);
}

export function notify(event, data) {
    if (listeners[event]) {
        listeners[event].forEach(cb => cb(data));
    }
}

export const api = {
    async get(path) {
        const res = await fetch(`/api/v1${path}`);
        if (!res.ok) throw new Error(`API Error: ${res.status}`);
        return res.json();
    },
    async post(path, body) {
        const res = await fetch(`/api/v1${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok && res.status !== 204) throw new Error(`API Error: ${res.status}`);
        return res.status === 204 ? null : res.json();
    },
    async put(path, body) {
        const res = await fetch(`/api/v1${path}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok && res.status !== 204) throw new Error(`API Error: ${res.status}`);
        return res.status === 204 ? null : res.json();
    },
    async del(path) {
        const res = await fetch(`/api/v1${path}`, { method: 'DELETE' });
        if (!res.ok && res.status !== 204) throw new Error(`API Error: ${res.status}`);
        return null;
    }
};

export function showToast(message, type = 'info') {
    const root = document.getElementById('toast-root');
    const el = document.createElement('div');
    el.className = 'toast';
    el.innerText = message;
    root.appendChild(el);
    setTimeout(() => el.remove(), 3000);
}

export function showModal(title, bodyHtml, footerButtons = []) {
    const root = document.getElementById('modal-root');
    document.getElementById('modal-title').innerText = title;
    document.getElementById('modal-body').innerHTML = bodyHtml;
    
    const footer = document.getElementById('modal-footer');
    footer.innerHTML = '';
    footerButtons.forEach(btn => {
        const b = document.createElement('button');
        b.className = `btn ${btn.class || 'btn-primary'}`;
        b.innerText = btn.text;
        b.onclick = () => {
            if (btn.onClick) btn.onClick();
            if (btn.dismiss !== false) hideModal();
        };
        footer.appendChild(b);
    });

    root.classList.remove('hidden');
}

export function hideModal() {
    document.getElementById('modal-root').classList.add('hidden');
}

// Close modal on backdrop click or close button
document.getElementById('modal-root').addEventListener('click', (e) => {
    if (e.target.id === 'modal-root' || e.target.classList.contains('modal-close-btn')) {
        hideModal();
    }
});

const routes = {
    dashboard: {
        render: async () => `<div class="card"><h1>Dashboard</h1><p>Welcome to LIAS Control Center.</p></div>`,
        afterRender: () => {}
    },
    devices: devicesView,
    schedules: {
        render: async () => `<div class="card"><h1>Schedules</h1><p>Manage time-based rules here.</p></div>`,
        afterRender: () => {}
    },
    policies: {
        render: async () => `<div class="card"><h1>Policies</h1><p>Manage network access policies.</p></div>`,
        afterRender: () => {}
    },
    settings: {
        render: async () => `<div class="card"><h1>Settings</h1><p>System configuration.</p></div>`,
        afterRender: () => {}
    }
};

async function navigate(view) {
    const container = document.getElementById('view-container');
    const title = document.getElementById('view-title');
    
    // Update active states
    document.querySelectorAll('.nav-item, .mob-nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.view === view);
    });

    container.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;
    
    try {
        const viewModule = routes[view] || routes.dashboard;
        title.innerText = view.charAt(0).toUpperCase() + view.slice(1);
        
        const html = await viewModule.render();
        container.innerHTML = html;
        
        if (viewModule.afterRender) {
            viewModule.afterRender();
        }
    } catch (err) {
        container.innerHTML = `<div class="card"><h3>Error</h3><p>${err.message}</p></div>`;
    }
}

// Setup navigation listeners
document.addEventListener('click', (e) => {
    const navItem = e.target.closest('.nav-item, .mob-nav-item');
    if (navItem) {
        navigate(navItem.dataset.view);
    }
});

// SSE Listener
function connectSSE() {
    const evtSource = new EventSource('/api/v1/events');
    evtSource.onopen = () => console.log('SSE Connected');
    evtSource.onerror = () => console.log('SSE Connection Error');
    
    evtSource.addEventListener('device.online', (e) => {
        const data = JSON.parse(e.data);
        showToast(`Device came online: ${data.hostname || data.pdid}`);
    });
    
    evtSource.addEventListener('device.offline', (e) => {
        const data = JSON.parse(e.data);
        showToast(`Device went offline: ${data.hostname || data.pdid}`);
    });
}

// Init
async function init() {
    navigate('dashboard');
    connectSSE();
}

init();
