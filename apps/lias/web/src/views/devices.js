// LIAS Dashboard View: Devices
// File:    apps/lias/web/src/views/devices.js
// Version: 1.0

import { api, showModal, hideModal, showToast } from '../main.js';

export const devicesView = {
    async render() {
        const res = await api.get('/devices');
        if (!res.devices || res.devices.length === 0) {
            return `<div class="card"><h3>No Devices Found</h3><p>Waiting for Discovery Service to report inventory...</p></div>`;
        }

        const cards = res.devices.map(d => `
            <div class="card device-card" data-pdid="${d.pdid}">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <h3 style="margin-bottom:4px;">${d.friendly_name || d.hostname || 'Unknown Device'}</h3>
                        <p style="color:var(--text-secondary); font-size:14px;">${d.current_ip || 'No IP'} • ${d.device_type || 'Unknown Type'}</p>
                    </div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="width:10px; height:10px; border-radius:50%; background-color:${d.online ? 'var(--success)' : 'var(--text-secondary)'};"></span>
                        <span style="font-size:12px; font-weight:600; color:${d.online ? 'var(--success)' : 'var(--text-secondary)'}; text-transform:uppercase;">${d.online ? 'Online' : 'Offline'}</span>
                    </div>
                </div>
            </div>
        `).join('');

        return `<div class="device-list">${cards}</div>`;
    },

    afterRender() {
        document.querySelectorAll('.device-card').forEach(card => {
            card.addEventListener('click', () => this.openDeviceModal(card.dataset.pdid));
        });
    },

    async openDeviceModal(pdid) {
        try {
            // Fetch tags and device list in parallel
            const [tagsRes, devsRes] = await Promise.all([
                api.get('/tags'),
                api.get('/devices')
            ]);

            const device = devsRes.devices.find(d => d.pdid === pdid);
            if (!device) {
                showToast('Device not found');
                return;
            }

            const currentTag = device.tags && device.tags.length > 0 ? device.tags[0] : 'generic';
            const tagOptions = tagsRes.map(t => `<option value="${t.id}" ${t.id === currentTag ? 'selected' : ''}>${t.name}</option>`).join('');

            const bodyHtml = `
                <div style="margin-bottom: 24px;">
                    <h4 style="color:var(--text-secondary); font-size:12px; text-transform:uppercase; margin-bottom:8px;">Identity</h4>
                    <p style="margin-bottom:4px;"><strong>Hostname:</strong> ${device.hostname || 'N/A'}</p>
                    <p style="margin-bottom:4px;"><strong>MAC:</strong> ${device.current_mac || 'N/A'}</p>
                    <p><strong>Vendor:</strong> ${device.vendor || 'N/A'}</p>
                </div>
                <div>
                    <h4 style="color:var(--text-secondary); font-size:12px; text-transform:uppercase; margin-bottom:8px;">Classification</h4>
                    <label for="tag-select" style="display:block; margin-bottom:4px; font-size:14px;">Assigned Tag</label>
                    <select id="tag-select" class="search-bar" style="width:100%; max-width:none; margin-bottom:16px; padding:12px;">
                        ${tagOptions}
                    </select>
                </div>
            `;

            showModal(`${device.friendly_name || device.hostname || 'Device Details'}`, bodyHtml, [
                { text: 'Cancel', class: 'btn-ghost' },
                { 
                    text: 'Save', 
                    class: 'btn-primary', 
                    onClick: async () => {
                        const selectedTag = document.getElementById('tag-select').value;
                        await api.post(`/devices/${pdid}/tags`, { tag_id: selectedTag });
                        showToast('Policy applied — device updated');
                        // Force a re-render of the view to reflect changes
                        document.querySelector('.nav-item[data-view="devices"]').click();
                    },
                    dismiss: true
                }
            ]);
        } catch(err) {
            showToast('Error loading device details');
        }
    }
};
