/**
 * LIAS Control Center - Production Web Dashboard SPA Controller
 * File:    apps/lias/web/src/main.js
 * Version: 1.5 (Apple HIG Dialog Compliance & Human-Readable Schedule Association)
 */

import { API } from './api.js';

class AppController {
    constructor() {
        this.currentView = 'dashboard';
        this.devices = [];
        this.tags = [];
        this.policies = [];
        this.schedules = [];
        this.searchQuery = '';
        this.sseSubscription = null;

        this.init();
    }

    async init() {
        this.bindGlobalEvents();
        await this.loadInitialData();
        this.initRealtimeEvents();
    }

    /**
     * Canonical Display Name Helper enforcing strict hierarchy:
     * 1. Hostname (if non-empty)
     * 2. Friendly Name (if Hostname is empty)
     * 3. Vendor + Model / Vendor / Model (if Friendly Name is empty)
     * 4. Current MAC / PDID (if metadata is empty)
     */
    getDisplayName(dev) {
        if (!dev) return 'Unknown Device';
        if (dev.hostname && dev.hostname.trim() !== '') {
            return dev.hostname.trim();
        }
        if (dev.friendly_name && dev.friendly_name.trim() !== '') {
            return dev.friendly_name.trim();
        }
        const vendor = (dev.vendor || '').trim();
        const model = (dev.model || '').trim();
        if (vendor && model) return `${vendor} ${model}`;
        if (vendor) return vendor;
        if (model) return model;
        if (dev.current_mac) return dev.current_mac;
        if (dev.pdid) return dev.pdid;
        return 'Unknown Device';
    }

    /**
     * Resolves human-readable Schedule Name and Time Rules Summary for Policy rendering.
     * Prevents displaying raw, cryptic database IDs like (sched_a1b2c3d4).
     */
    getScheduleSummary(scheduleId) {
        if (!scheduleId) return '';
        const sched = this.schedules.find(s => s.id === scheduleId);
        if (!sched) {
            return '⚠️ Missing Schedule (Fails Closed: BLOCK)';
        }
        const ruleSummaries = (sched.rules || []).map(r => {
            const days = (r.days || []).map(d => d.toUpperCase()).join(',');
            return `${days}: ${r.start_time}-${r.end_time} [${r.action.toUpperCase()}]`;
        }).join(' | ');

        return `${sched.name} (${ruleSummaries})`;
    }

    /**
     * Resolves human-readable Policy Target Name for Tags and Devices.
     */
    getPolicyTargetLabel(policy) {
        if (policy.type === 'global' || !policy.target_id) {
            return 'Global Access Switch';
        }
        if (policy.type === 'tag') {
            const tag = this.tags.find(t => t.id === policy.target_id);
            return tag ? `Tag Group: ${tag.name}` : `Tag Group: ${policy.target_id}`;
        }
        if (policy.type === 'device') {
            const dev = this.devices.find(d => d.pdid === policy.target_id);
            return dev ? `Device: ${this.getDisplayName(dev)}` : `Device: ${policy.target_id}`;
        }
        return policy.target_id;
    }

    bindGlobalEvents() {
        // Desktop Sidebar Navigation
        document.querySelectorAll('.sidebar-nav .nav-item').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.switchView(view);
            });
        });

        // Mobile Bottom Navigation Tab Bar
        document.querySelectorAll('#mobile-nav .mob-nav-item').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.switchView(view);
            });
        });

        // Search Input Filter
        const searchInput = document.getElementById('global-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = e.target.value.toLowerCase().trim();
                this.render();
            });
        }

        // Modal Window Close Event Handlers
        const closeBtn = document.getElementById('modal-close-x');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.closeModal());
        }

        const modalBackdrop = document.getElementById('modal-root');
        if (modalBackdrop) {
            modalBackdrop.addEventListener('click', (e) => {
                if (e.target === modalBackdrop) {
                    this.closeModal();
                }
            });
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });
    }

    switchView(view) {
        this.currentView = view;

        document.querySelectorAll('.nav-item, .mob-nav-item').forEach(el => {
            el.classList.toggle('active', el.dataset.view === view);
        });

        const titleMap = {
            'dashboard': 'Dashboard',
            'devices': 'Tag Groups',
            'schedules': 'Schedules',
            'policies': 'Policies',
            'settings': 'Settings'
        };

        const viewTitle = document.getElementById('view-title');
        if (viewTitle) {
            viewTitle.textContent = titleMap[view] || 'Dashboard';
        }

        this.render();
    }

    async loadInitialData() {
        try {
            const [devsRes, tagsRes, polsRes, schedsRes] = await Promise.all([
                API.getDevices(),
                API.getTags(),
                API.getPolicies(),
                API.getSchedules()
            ]);

            this.devices = devsRes.devices || [];
            this.tags = tagsRes || [];
            this.policies = polsRes || [];
            this.schedules = schedsRes || [];

            this.render();
        } catch (err) {
            this.showToast('Failed to load system state from LIAS server', 'error');
        }
    }

    async loadInitialDataSilently() {
        try {
            const [devsRes, tagsRes, polsRes, schedsRes] = await Promise.all([
                API.getDevices(),
                API.getTags(),
                API.getPolicies(),
                API.getSchedules()
            ]);

            this.devices = devsRes.devices || [];
            this.tags = tagsRes || [];
            this.policies = polsRes || [];
            this.schedules = schedsRes || [];

            this.render();
        } catch (err) {
            // Silently absorb transport errors during background refresh
        }
    }

    initRealtimeEvents() {
        if (this.sseSubscription) {
            this.sseSubscription.close();
        }

        this.sseSubscription = API.subscribeEvents((evt) => {
            // Re-fetch state silently to update green/gray status indicator dots and device cards
            this.loadInitialDataSilently();

            // Immediate Toast Alert ONLY when a completely new device is discovered
            if (evt.type === 'device.added') {
                let devName = 'New Device';
                if (evt.payload) {
                    devName = this.getDisplayName(evt.payload);
                }
                this.showToast(`🎉 New Device Discovered: ${devName}`, 'info');
            }
            // Routine 'device.online' and 'device.offline' events update UI status dots quietly
        });

        // Defense-in-Depth (GAP-12): 20s backstop polling interval ensures the UI
        // auto-corrects even if SSE connections drop or miss packets.
        setInterval(() => this.loadInitialDataSilently(), 20000);
    }

    render() {
        const container = document.getElementById('view-container');
        if (!container) return;

        switch (this.currentView) {
            case 'dashboard':
            case 'devices':
                this.renderTagGroupsView(container);
                break;
            case 'schedules':
                this.renderSchedulesView(container);
                break;
            case 'policies':
                this.renderPoliciesView(container);
                break;
            case 'settings':
                this.renderSettingsView(container);
                break;
            default:
                container.innerHTML = '<div class="card"><p>View not found.</p></div>';
        }
    }

    // =========================================================================
    // 1. DASHBOARD & TAG GROUPS VIEW
    // =========================================================================

    renderTagGroupsView(container) {
        let html = '';

        const globalPolicy = this.policies.find(p => p.id === 'global_default') || { action: 'schedule' };
        html += `
            <div class="global-switch-banner">
                <div>
                    <h3 style="font-size:16px; font-weight:700; margin-bottom:4px;">Global Network Access</h3>
                    <p style="font-size:13px; color:var(--text-secondary);">Master internet switch across all network devices</p>
                </div>
                <div class="segmented-control">
                    <button class="segmented-btn ${globalPolicy.action === 'allow' ? 'active' : ''}" data-act="allow">Allow All</button>
                    <button class="segmented-btn ${globalPolicy.action === 'schedule' ? 'active' : ''}" data-act="schedule">Schedule</button>
                    <button class="segmented-btn danger ${globalPolicy.action === 'block' ? 'active' : ''}" data-act="block">Block All</button>
                </div>
            </div>
        `;

        if (this.currentView === 'devices') {
            html += `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                    <h3 style="font-size:18px; font-weight:700;">Configured Tag Groups</h3>
                    <button class="btn btn-primary" id="btn-create-tag">+ Create Custom Tag Group</button>
                </div>
            `;
        }

        const tagMap = new Map();
        this.tags.forEach(t => tagMap.set(t.id, { ...t, devices: [] }));

        this.devices.forEach(dev => {
            if (this.searchQuery) {
                const displayName = this.getDisplayName(dev).toLowerCase();
                const match = displayName.includes(this.searchQuery) ||
                              (dev.hostname || '').toLowerCase().includes(this.searchQuery) ||
                              (dev.friendly_name || '').toLowerCase().includes(this.searchQuery) ||
                              (dev.current_mac || '').toLowerCase().includes(this.searchQuery) ||
                              (dev.current_ip || '').toLowerCase().includes(this.searchQuery) ||
                              (dev.vendor || '').toLowerCase().includes(this.searchQuery) ||
                              (dev.pdid || '').toLowerCase().includes(this.searchQuery);
                if (!match) return;
            }

            const assignedTag = (dev.tags && dev.tags[0]) ? dev.tags[0] : 'generic';
            if (tagMap.has(assignedTag)) {
                tagMap.get(assignedTag).devices.push(dev);
            } else {
                if (!tagMap.has('generic')) {
                    tagMap.set('generic', { id: 'generic', name: 'Generic Devices', color: '#636366', precedence: 0, devices: [] });
                }
                tagMap.get('generic').devices.push(dev);
            }
        });

        tagMap.forEach(group => {
            if (group.devices.length === 0 && this.searchQuery) return;

            html += `
                <div class="group-card">
                    <div class="group-header" data-tag-id="${group.id}">
                        <div class="group-header-title">
                            <span class="group-tag-badge" style="background-color:${group.color};">${this.escapeHtml(group.name)}</span>
                            <span class="group-count">(${group.devices.length} ${group.devices.length === 1 ? 'device' : 'devices'})</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:12px;">
                            ${(this.currentView === 'devices' && !group.builtin) ? `
                                <button class="btn btn-secondary btn-edit-tag" data-tag-id="${group.id}" style="padding:4px 10px; font-size:12px;">Edit</button>
                                <button class="btn btn-danger btn-delete-tag" data-tag-id="${group.id}" style="padding:4px 10px; font-size:12px;">Delete</button>
                            ` : ''}
                            <svg class="group-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                        </div>
                    </div>
                    <div class="group-content">
                        ${group.devices.length === 0 ? '<p style="color:var(--text-secondary); font-size:13px;">No devices assigned to this group.</p>' : `
                            <div class="device-grid">
                                ${group.devices.map(d => this.renderDeviceCard(d)).join('')}
                            </div>
                        `}
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;

        // Bind Global Access Switch Buttons
        container.querySelectorAll('.global-switch-banner .segmented-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const act = e.currentTarget.dataset.act;
                try {
                    await API.savePolicy({
                        id: 'global_default',
                        name: 'Global Access Switch',
                        type: 'global',
                        action: act,
                        priority: 0
                    });
                    this.showToast(`Global access updated to ${act.toUpperCase()}`, 'info');
                    await this.loadInitialDataSilently();
                } catch (err) {
                    this.showToast(`Failed to set global policy: ${err.message}`, 'error');
                }
            });
        });

        // Bind Collapsible Group Headers
        container.querySelectorAll('.group-header').forEach(header => {
            header.addEventListener('click', (e) => {
                if (e.target.closest('button')) return;
                header.parentElement.classList.toggle('collapsed');
            });
        });

        // Bind Tag Reassignment Buttons on Devices
        container.querySelectorAll('.btn-reassign-tag').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const pdid = e.currentTarget.dataset.pdid;
                this.openAssignTagModal(pdid);
            });
        });

        // Bind Tag Management Action Buttons
        const createTagBtn = document.getElementById('btn-create-tag');
        if (createTagBtn) {
            createTagBtn.addEventListener('click', () => this.openTagModal());
        }

        container.querySelectorAll('.btn-edit-tag').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tagId = e.currentTarget.dataset.tagId;
                const tag = this.tags.find(t => t.id === tagId);
                if (tag) this.openTagModal(tag);
            });
        });

        // Replaced Primitive confirm() with Apple HIG Sheet for Tag Deletion
        container.querySelectorAll('.btn-delete-tag').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tagId = e.currentTarget.dataset.tagId;
                const tag = this.tags.find(t => t.id === tagId);
                const tagName = tag ? tag.name : tagId;

                this.openConfirmModal({
                    title: 'Delete Tag Group',
                    message: `Are you sure you want to delete the tag group '${tagName}'? Any assigned devices will revert to Generic Devices.`,
                    confirmText: 'Delete Group',
                    confirmDanger: true,
                    onConfirm: async () => {
                        try {
                            await API.deleteTag(tagId);
                            this.showToast('Tag group deleted', 'info');
                            await this.loadInitialData();
                        } catch (err) {
                            this.showToast(`Failed to delete tag: ${err.message}`, 'error');
                        }
                    }
                });
            });
        });
    }

    renderDeviceCard(dev) {
        const isOnline = dev.online;
        // Enforce strict display name hierarchy: Hostname -> Friendly Name -> Vendor/Model -> MAC/PDID
        const displayName = this.getDisplayName(dev);
        const services = dev.services || [];
        const currentTag = (dev.tags && dev.tags[0]) ? dev.tags[0] : 'generic';

        return `
            <div class="device-item">
                <div>
                    <div class="device-item-header">
                        <span class="device-name" title="${this.escapeHtml(dev.pdid)}">${this.escapeHtml(displayName)}</span>
                        <div class="status-indicator ${isOnline ? 'online' : 'offline'}" title="${isOnline ? 'Online' : 'Offline'}"></div>
                    </div>
                    <div class="device-meta">
                        <div><strong>IP:</strong> ${dev.current_ip || 'N/A'}</div>
                        <div><strong>MAC:</strong> ${dev.current_mac || 'N/A'}</div>
                        <div><strong>Vendor:</strong> ${dev.vendor || 'Unknown'}</div>
                        ${dev.model ? `<div><strong>Model:</strong> ${this.escapeHtml(dev.model)}</div>` : ''}
                    </div>
                    ${services.length > 0 ? `
                        <div class="service-pill-list">
                            ${services.map(s => `<span class="service-pill">${this.escapeHtml(s)}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:12px; padding-top:10px; border-top:1px solid var(--separator);">
                    <span class="last-seen-badge">${isOnline ? 'Active now' : (dev.last_seen ? new Date(dev.last_seen).toLocaleTimeString() : 'Offline')}</span>
                    <button class="btn btn-secondary btn-reassign-tag" data-pdid="${dev.pdid}" style="padding:4px 8px; font-size:11px;">Tag: ${currentTag}</button>
                </div>
            </div>
        `;
    }

    openAssignTagModal(pdid) {
        const dev = this.devices.find(d => d.pdid === pdid);
        if (!dev) return;

        const currentTag = (dev.tags && dev.tags[0]) ? dev.tags[0] : 'generic';
        const displayName = this.getDisplayName(dev);

        let bodyHtml = `
            <p style="font-size:14px; margin-bottom:16px;">Select tag group assignment for device <strong>${this.escapeHtml(displayName)}</strong>:</p>
            <div style="display:flex; flex-direction:column; gap:8px;">
                ${this.tags.map(t => `
                    <label style="display:flex; align-items:center; justify-content:space-between; padding:10px 14px; border:1px solid var(--separator); border-radius:10px; cursor:pointer; background:var(--bg-tertiary);">
                        <div style="display:flex; align-items:center; gap:10px;">
                            <span class="group-tag-badge" style="background-color:${t.color};">${this.escapeHtml(t.name)}</span>
                        </div>
                        <input type="radio" name="tag_selection" value="${t.id}" ${t.id === currentTag ? 'checked' : ''}>
                    </label>
                `).join('')}
            </div>
        `;

        this.openModal('Assign Device Tag Group', bodyHtml, `
            <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
            <button class="btn btn-primary" id="modal-save-tag">Save Assignment</button>
        `);

        document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-save-tag').addEventListener('click', async () => {
            const selected = document.querySelector('input[name="tag_selection"]:checked');
            if (selected) {
                try {
                    await API.assignDeviceTag(pdid, selected.value);
                    this.showToast('Device tag assigned successfully', 'info');
                    this.closeModal();
                    await this.loadInitialDataSilently();
                } catch (err) {
                    this.showToast(`Failed to assign tag: ${err.message}`, 'error');
                }
            }
        });
    }

    openTagModal(tag = null) {
        const isEdit = !!tag;
        const bodyHtml = `
            <form id="form-tag">
                <div style="margin-bottom:16px;">
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:6px;">Tag Name</label>
                    <input type="text" id="tag-name" value="${isEdit ? this.escapeHtml(tag.name) : ''}" placeholder="e.g. Kids Gaming" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary); font-family:inherit;" required>
                </div>
                <div style="margin-bottom:16px;">
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:6px;">Badge Color</label>
                    <input type="color" id="tag-color" value="${isEdit ? tag.color : '#0071e3'}" style="width:100%; height:40px; border:none; border-radius:8px; cursor:pointer; background:transparent;">
                </div>
            </form>
        `;

        this.openModal(isEdit ? 'Edit Custom Tag Group' : 'Create Custom Tag Group', bodyHtml, `
            <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
            <button class="btn btn-primary" id="modal-save-tag-def">${isEdit ? 'Update' : 'Create'}</button>
        `);

        document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-save-tag-def').addEventListener('click', async () => {
            const name = document.getElementById('tag-name').value.trim();
            const color = document.getElementById('tag-color').value;

            if (!name) {
                this.showToast('Tag name is required', 'warning');
                return;
            }

            try {
                if (isEdit) {
                    await API.updateTag(tag.id, { name, color });
                    this.showToast('Tag group updated', 'info');
                } else {
                    await API.createTag({ name, color });
                    this.showToast('Tag group created', 'info');
                }
                this.closeModal();
                await this.loadInitialData();
            } catch (err) {
                this.showToast(`Failed to save tag: ${err.message}`, 'error');
            }
        });
    }

    // =========================================================================
    // 2. SCHEDULES VIEW & RULE BUILDER
    // =========================================================================

    renderSchedulesView(container) {
        container.innerHTML = `
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                    <div>
                        <h3 style="font-size:18px; font-weight:700;">Time Schedules</h3>
                        <p style="font-size:13px; color:var(--text-secondary);">Define automatic internet allowance and bedtime block windows</p>
                    </div>
                    <button class="btn btn-primary" id="btn-create-schedule">+ Create Schedule</button>
                </div>
                <div>
                    ${this.schedules.length === 0 ? '<p style="color:var(--text-secondary); font-size:14px;">No schedules configured yet.</p>' : ''}
                    ${this.schedules.map(s => `
                        <div class="card" style="box-shadow:none; border:1px solid var(--separator); margin-bottom:14px; padding:16px;">
                            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
                                <div>
                                    <h4 style="font-size:16px; font-weight:700;">${this.escapeHtml(s.name)}</h4>
                                    <span style="font-size:12px; color:var(--text-secondary);">Timezone: ${this.escapeHtml(s.timezone || 'UTC')}</span>
                                </div>
                                <div style="display:flex; gap:8px;">
                                    <button class="btn btn-secondary btn-edit-sched" data-sched-id="${s.id}" style="padding:6px 12px; font-size:12px;">Edit</button>
                                    <button class="btn btn-danger btn-delete-sched" data-sched-id="${s.id}" style="padding:6px 12px; font-size:12px;">Delete</button>
                                </div>
                            </div>
                            <div style="display:flex; flex-direction:column; gap:6px;">
                                ${(s.rules || []).map(r => `
                                    <div style="font-size:13px; background:var(--bg-tertiary); padding:8px 12px; border-radius:8px; display:flex; justify-content:space-between; align-items:center;">
                                        <span><strong>${(r.days || []).join(', ').toUpperCase()}:</strong> ${r.start_time} - ${r.end_time}</span>
                                        <span class="group-tag-badge" style="background-color:${r.action === 'allow' ? 'var(--success)' : 'var(--danger)'}; padding:2px 8px; font-size:10px;">${r.action.toUpperCase()}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;

        document.getElementById('btn-create-schedule').addEventListener('click', () => this.openScheduleModal());

        container.querySelectorAll('.btn-edit-sched').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const schedId = e.currentTarget.dataset.schedId;
                const sched = this.schedules.find(s => s.id === schedId);
                if (sched) this.openScheduleModal(sched);
            });
        });

        // Replaced Primitive confirm() with Apple HIG Sheet & Impact Transparency for Schedule Deletion
        container.querySelectorAll('.btn-delete-sched').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const schedId = e.currentTarget.dataset.schedId;
                const sched = this.schedules.find(s => s.id === schedId);
                const schedName = sched ? sched.name : schedId;

                // Query all active policies currently attached to this schedule
                const affectedPolicies = this.policies.filter(p => p.schedule_id === schedId);

                let impactHtml = '';
                if (affectedPolicies.length > 0) {
                    impactHtml = `
                        <div class="hig-callout-warning">
                            <strong>⚠️ Active Policy Impact Warning:</strong>
                            <p style="margin-top:4px;">Deleting <strong>'${this.escapeHtml(schedName)}'</strong> will affect ${affectedPolicies.length} active policy rule(s):</p>
                            <ul>
                                ${affectedPolicies.map(p => `<li><strong>${this.escapeHtml(p.name)}</strong> (${this.escapeHtml(this.getPolicyTargetLabel(p))})</li>`).join('')}
                            </ul>
                            <p style="margin-top:6px; font-weight:600;">These policies will fail-closed (BLOCK ALL access) until reassigned to a new schedule.</p>
                        </div>
                    `;
                }

                this.openConfirmModal({
                    title: 'Delete Schedule',
                    message: `Are you sure you want to delete time schedule '${this.escapeHtml(schedName)}'? ${impactHtml}`,
                    confirmText: 'Delete Schedule',
                    confirmDanger: true,
                    onConfirm: async () => {
                        try {
                            await API.deleteSchedule(schedId);
                            this.showToast('Schedule deleted', 'info');
                            await this.loadInitialData();
                        } catch (err) {
                            this.showToast(`Failed to delete schedule: ${err.message}`, 'error');
                        }
                    }
                });
            });
        });
    }

    openScheduleModal(schedule = null) {
        const isEdit = !!schedule;
        let rules = isEdit && schedule.rules ? JSON.parse(JSON.stringify(schedule.rules)) : [
            { days: ['mon', 'tue', 'wed', 'thu', 'fri'], start_time: '22:00', end_time: '06:00', action: 'block' }
        ];

        const renderRulesEditor = () => {
            return rules.map((r, idx) => `
                <div style="background:var(--bg-tertiary); padding:14px; border-radius:12px; border:1px solid var(--separator); margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <span style="font-size:12px; font-weight:700;">Rule #${idx + 1}</span>
                        ${rules.length > 1 ? `<button type="button" class="btn btn-danger btn-remove-rule" data-idx="${idx}" style="padding:2px 6px; font-size:11px;">Remove</button>` : ''}
                    </div>
                    <div style="margin-bottom:8px;">
                        <label style="display:block; font-size:11px; font-weight:600; margin-bottom:4px;">Days Active</label>
                        <div class="day-chip-group">
                            ${['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'].map(day => `
                                <div class="day-chip ${r.days.includes(day) ? 'selected' : ''}" data-rule-idx="${idx}" data-day="${day}">${day.toUpperCase()}</div>
                            `).join('')}
                        </div>
                    </div>
                    <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:8px; align-items:center;">
                        <div>
                            <label style="display:block; font-size:11px; font-weight:600; margin-bottom:2px;">Start Time</label>
                            <input type="time" class="rule-start" data-rule-idx="${idx}" value="${r.start_time}" style="width:100%;">
                        </div>
                        <div>
                            <label style="display:block; font-size:11px; font-weight:600; margin-bottom:2px;">End Time</label>
                            <input type="time" class="rule-end" data-rule-idx="${idx}" value="${r.end_time}" style="width:100%;">
                        </div>
                        <div>
                            <label style="display:block; font-size:11px; font-weight:600; margin-bottom:2px;">Action</label>
                            <select class="rule-action" data-rule-idx="${idx}" style="width:100%; padding:9px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-secondary); color:var(--text-primary); font-size:13px;">
                                <option value="block" ${r.action === 'block' ? 'selected' : ''}>BLOCK</option>
                                <option value="allow" ${r.action === 'allow' ? 'selected' : ''}>ALLOW</option>
                            </select>
                        </div>
                    </div>
                </div>
            `).join('');
        };

        const updateModalBody = () => {
            const bodyHtml = `
                <form id="form-schedule">
                    <div style="margin-bottom:14px;">
                        <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Schedule Name</label>
                        <input type="text" id="sched-name" value="${isEdit ? this.escapeHtml(schedule.name) : ''}" placeholder="e.g. Bedtime Curfew" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);" required>
                    </div>
                    <div style="margin-bottom:14px;">
                        <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Timezone</label>
                        <select id="sched-tz" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);">
                            <option value="UTC" ${isEdit && schedule.timezone === 'UTC' ? 'selected' : ''}>UTC</option>
                            <option value="America/Los_Angeles" ${isEdit && schedule.timezone === 'America/Los_Angeles' ? 'selected' : ''}>America/Los_Angeles (PT)</option>
                            <option value="America/New_York" ${isEdit && schedule.timezone === 'America/New_York' ? 'selected' : ''}>America/New_York (ET)</option>
                            <option value="Europe/London" ${isEdit && schedule.timezone === 'Europe/London' ? 'selected' : ''}>Europe/London (GMT/BST)</option>
                            <option value="Asia/Tokyo" ${isEdit && schedule.timezone === 'Asia/Tokyo' ? 'selected' : ''}>Asia/Tokyo (JST)</option>
                        </select>
                    </div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <label style="font-size:13px; font-weight:600;">Time Windows</label>
                        <button type="button" class="btn btn-secondary" id="btn-add-rule-window" style="padding:4px 10px; font-size:11px;">+ Add Window</button>
                    </div>
                    <div id="rules-container">${renderRulesEditor()}</div>
                </form>
            `;

            document.getElementById('modal-body').innerHTML = bodyHtml;
            bindRuleEvents();
        };

        const bindRuleEvents = () => {
            document.querySelectorAll('.day-chip').forEach(chip => {
                chip.addEventListener('click', (e) => {
                    const ruleIdx = parseInt(e.currentTarget.dataset.ruleIdx, 10);
                    const day = e.currentTarget.dataset.day;

                    if (rules[ruleIdx].days.includes(day)) {
                        rules[ruleIdx].days = rules[ruleIdx].days.filter(d => d !== day);
                    } else {
                        rules[ruleIdx].days.push(day);
                    }
                    updateModalBody();
                });
            });

            document.querySelectorAll('.rule-start').forEach(input => {
                input.addEventListener('change', (e) => {
                    const idx = parseInt(e.target.dataset.ruleIdx, 10);
                    rules[idx].start_time = e.target.value;
                });
            });

            document.querySelectorAll('.rule-end').forEach(input => {
                input.addEventListener('change', (e) => {
                    const idx = parseInt(e.target.dataset.ruleIdx, 10);
                    rules[idx].end_time = e.target.value;
                });
            });

            document.querySelectorAll('.rule-action').forEach(select => {
                select.addEventListener('change', (e) => {
                    const idx = parseInt(e.target.dataset.ruleIdx, 10);
                    rules[idx].action = e.target.value;
                });
            });

            document.querySelectorAll('.btn-remove-rule').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const idx = parseInt(e.currentTarget.dataset.idx, 10);
                    rules.splice(idx, 1);
                    updateModalBody();
                });
            });

            const addWindowBtn = document.getElementById('btn-add-rule-window');
            if (addWindowBtn) {
                addWindowBtn.addEventListener('click', () => {
                    rules.push({ days: ['sat', 'sun'], start_time: '12:00', end_time: '18:00', action: 'allow' });
                    updateModalBody();
                });
            }
        };

        this.openModal(isEdit ? 'Edit Schedule' : 'Create Schedule', '', `
            <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
            <button class="btn btn-primary" id="modal-save-sched">${isEdit ? 'Update' : 'Create'}</button>
        `);

        updateModalBody();

        document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-save-sched').addEventListener('click', async () => {
            const name = document.getElementById('sched-name').value.trim();
            const timezone = document.getElementById('sched-tz').value;

            if (!name) {
                this.showToast('Schedule name is required', 'warning');
                return;
            }

            try {
                const payload = {
                    id: isEdit ? schedule.id : undefined,
                    name,
                    timezone,
                    rules
                };
                await API.saveSchedule(payload);
                this.showToast('Schedule saved successfully', 'info');
                this.closeModal();
                await this.loadInitialData();
            } catch (err) {
                this.showToast(`Failed to save schedule: ${err.message}`, 'error');
            }
        });
    }

    // =========================================================================
    // 3. POLICIES VIEW
    // =========================================================================

    renderPoliciesView(container) {
        container.innerHTML = `
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                    <div>
                        <h3 style="font-size:18px; font-weight:700;">Firewall Rule Policies</h3>
                        <p style="font-size:13px; color:var(--text-secondary);">Manage Precedence Hierarchy (Infrastructure > Global > Device > Tag)</p>
                    </div>
                    <button class="btn btn-primary" id="btn-create-policy">+ Create Policy Rule</button>
                </div>
                <div>
                    ${this.policies.length === 0 ? '<p style="color:var(--text-secondary); font-size:14px;">No custom policies configured.</p>' : ''}
                    ${this.policies.map(p => {
                        const targetLabel = this.getPolicyTargetLabel(p);
                        const scheduleSummary = p.schedule_id ? this.getScheduleSummary(p.schedule_id) : '';
                        const isMissingSched = p.action === 'schedule' && p.schedule_id && !this.schedules.some(s => s.id === p.schedule_id);

                        return `
                            <div class="card" style="box-shadow:none; border:1px solid var(--separator); margin-bottom:12px; padding:16px;">
                                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                                    <div>
                                        <h4 style="font-size:15px; font-weight:700;">${this.escapeHtml(p.name)}</h4>
                                        <div style="font-size:12px; color:var(--text-secondary); margin-top:3px;">
                                            Type: <strong>${p.type.toUpperCase()}</strong> | Target: <strong>${this.escapeHtml(targetLabel)}</strong> | Priority: ${p.priority}
                                        </div>
                                        ${scheduleSummary ? `
                                            <div style="font-size:12px; color:${isMissingSched ? 'var(--danger)' : 'var(--accent)'}; margin-top:6px; font-weight:600;">
                                                📅 ${this.escapeHtml(scheduleSummary)}
                                            </div>
                                        ` : ''}
                                    </div>
                                    <div style="display:flex; align-items:center; gap:10px;">
                                        <span class="group-tag-badge ${isMissingSched ? 'badge-missing-sched' : ''}" style="background-color:${p.action === 'allow' ? 'var(--success)' : (p.action === 'block' ? 'var(--danger)' : 'var(--accent)')};">
                                            ${p.action.toUpperCase()}
                                        </span>
                                        ${p.id !== 'global_default' ? `
                                            <button class="btn btn-danger btn-delete-policy" data-policy-id="${p.id}" style="padding:4px 8px; font-size:11px;">Delete</button>
                                        ` : ''}
                                    </div>
                                </div>
                            </div>
                        `;
                    }).join('')}
                </div>
            </div>
        `;

        document.getElementById('btn-create-policy').addEventListener('click', () => this.openPolicyModal());

        // Replaced Primitive confirm() with Apple HIG Sheet for Policy Deletion
        container.querySelectorAll('.btn-delete-policy').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const polId = e.currentTarget.dataset.policyId;
                const pol = this.policies.find(p => p.id === polId);
                const polName = pol ? pol.name : polId;

                this.openConfirmModal({
                    title: 'Delete Policy Rule',
                    message: `Are you sure you want to delete policy rule '${this.escapeHtml(polName)}'? Targets matching this rule will revert to global default policy.`,
                    confirmText: 'Delete Policy',
                    confirmDanger: true,
                    onConfirm: async () => {
                        try {
                            await API.deletePolicy(polId);
                            this.showToast('Policy deleted', 'info');
                            await this.loadInitialData();
                        } catch (err) {
                            this.showToast(`Failed to delete policy: ${err.message}`, 'error');
                        }
                    }
                });
            });
        });
    }

    openPolicyModal() {
        const bodyHtml = `
            <form id="form-policy">
                <div style="margin-bottom:14px;">
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Policy Name</label>
                    <input type="text" id="pol-name" placeholder="e.g. Block Kids Gaming Bedtime" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);" required>
                </div>
                <div style="margin-bottom:14px;">
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Policy Type Scope</label>
                    <select id="pol-type" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);">
                        <option value="tag">Tag Group Policy</option>
                        <option value="device">Single Device Policy</option>
                    </select>
                </div>
                <div style="margin-bottom:14px;" id="target-container">
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Target Tag Group</label>
                    <select id="pol-target" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);">
                        ${this.tags.map(t => `<option value="${t.id}">${this.escapeHtml(t.name)}</option>`).join('')}
                    </select>
                </div>
                <div style="margin-bottom:14px;">
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Enforcement Action</label>
                    <select id="pol-action" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);">
                        <option value="schedule">Schedule Driven</option>
                        <option value="block">BLOCK Always</option>
                        <option value="allow">ALLOW Always</option>
                    </select>
                </div>
                <div style="margin-bottom:14px;" id="sched-select-container">
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Select Schedule</label>
                    <select id="pol-sched-id" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);">
                        ${this.schedules.map(s => `<option value="${s.id}">${this.escapeHtml(s.name)} (${(s.rules || []).length} rules)</option>`).join('')}
                    </select>
                </div>
            </form>
        `;

        this.openModal('Create Policy Rule', bodyHtml, `
            <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
            <button class="btn btn-primary" id="modal-save-pol">Create Policy</button>
        `);

        const typeSelect = document.getElementById('pol-type');
        const targetContainer = document.getElementById('target-container');

        typeSelect.addEventListener('change', (e) => {
            if (e.target.value === 'device') {
                targetContainer.innerHTML = `
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Target Device</label>
                    <select id="pol-target" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);">
                        ${this.devices.map(d => `<option value="${d.pdid}">${this.escapeHtml(this.getDisplayName(d))}</option>`).join('')}
                    </select>
                `;
            } else {
                targetContainer.innerHTML = `
                    <label style="display:block; font-size:13px; font-weight:600; margin-bottom:4px;">Target Tag Group</label>
                    <select id="pol-target" style="width:100%; padding:10px; border-radius:10px; border:1px solid var(--separator); background:var(--bg-tertiary); color:var(--text-primary);">
                        ${this.tags.map(t => `<option value="${t.id}">${this.escapeHtml(t.name)}</option>`).join('')}
                    </select>
                `;
            }
        });

        const actionSelect = document.getElementById('pol-action');
        const schedContainer = document.getElementById('sched-select-container');

        actionSelect.addEventListener('change', (e) => {
            schedContainer.style.display = e.target.value === 'schedule' ? 'block' : 'none';
        });

        document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-save-pol').addEventListener('click', async () => {
            const name = document.getElementById('pol-name').value.trim();
            const type = document.getElementById('pol-type').value;
            const target_id = document.getElementById('pol-target').value;
            const action = document.getElementById('pol-action').value;
            const schedule_id = action === 'schedule' ? document.getElementById('pol-sched-id').value : undefined;

            if (!name) {
                this.showToast('Policy name is required', 'warning');
                return;
            }

            try {
                await API.savePolicy({
                    name,
                    type,
                    target_id,
                    action,
                    schedule_id,
                    priority: type === 'device' ? 80 : 50
                });
                this.showToast('Policy created', 'info');
                this.closeModal();
                await this.loadInitialData();
            } catch (err) {
                this.showToast(`Failed to create policy: ${err.message}`, 'error');
            }
        });
    }

    // =========================================================================
    // 4. SETTINGS & MAINTENANCE VIEW
    // =========================================================================

    renderSettingsView(container) {
        container.innerHTML = `
            <div class="card">
                <h3 style="font-size:18px; font-weight:700; margin-bottom:12px;">System Architecture & Status</h3>
                <p style="font-size:13px; color:var(--text-secondary); margin-bottom:20px;">
                    LIAS is operating in isolated Netdev Ingress mode on <strong>eth0</strong>. All firewall filtering is executed directly in kernel space without altering routing tables or system sing-box rules.
                </p>

                <div style="display:flex; flex-direction:column; gap:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; padding:12px; background:var(--bg-tertiary); border-radius:10px;">
                        <div>
                            <strong>Flush Nftables Kernel Sets</strong>
                            <p style="font-size:12px; color:var(--text-secondary);">Removes all active allowed and blocked IP/MAC sets from netdev lancontrol table.</p>
                        </div>
                        <button class="btn btn-danger" id="btn-flush-nftables">Flush Table</button>
                    </div>

                    <div style="display:flex; justify-content:space-between; align-items:center; padding:12px; background:var(--bg-tertiary); border-radius:10px;">
                        <div>
                            <strong>Resync DIS Inventory</strong>
                            <p style="font-size:12px; color:var(--text-secondary);">Force an immediate REST polling resync from Discovery Intelligence Service (:8080).</p>
                        </div>
                        <button class="btn btn-secondary" id="btn-force-resync">Force Resync</button>
                    </div>
                </div>
            </div>
        `;

        // Replaced Primitive confirm() with Apple HIG Sheet for Firewall Flushing
        document.getElementById('btn-flush-nftables').addEventListener('click', () => {
            this.openConfirmModal({
                title: 'Flush Firewall Table',
                message: 'Are you sure you want to flush the netdev lancontrol nftables table? Active allowed and blocked kernel set elements will be wiped until the next 10-second sync loop.',
                confirmText: 'Flush Firewall',
                confirmDanger: true,
                onConfirm: async () => {
                    try {
                        await API.flushNftables();
                        this.showToast('nftables table flushed successfully', 'info');
                    } catch (err) {
                        this.showToast(`Failed to flush nftables: ${err.message}`, 'error');
                    }
                }
            });
        });

        document.getElementById('btn-force-resync').addEventListener('click', async () => {
            this.showToast('Triggering DIS inventory resync...', 'info');
            await this.loadInitialData();
            this.showToast('Inventory resync complete', 'info');
        });
    }

    // =========================================================================
    // 5. MODAL, HIG CONFIRMATION SHEET, & TOAST HELPERS
    // =========================================================================

    /**
     * Native Apple HIG Confirmation Sheet replacement for browser confirm() popups.
     */
    openConfirmModal({ title, message, confirmText, confirmDanger = false, onConfirm }) {
        const bodyHtml = `<div style="font-size:14px; line-height:1.5; color:var(--text-primary);">${message}</div>`;
        const footerHtml = `
            <button class="btn btn-secondary" id="modal-confirm-cancel">Cancel</button>
            <button class="btn ${confirmDanger ? 'btn-danger' : 'btn-primary'}" id="modal-confirm-ok">${this.escapeHtml(confirmText || 'Confirm')}</button>
        `;

        this.openModal(title, bodyHtml, footerHtml);

        document.getElementById('modal-confirm-cancel').addEventListener('click', () => this.closeModal());
        document.getElementById('modal-confirm-ok').addEventListener('click', async () => {
            this.closeModal();
            if (onConfirm) await onConfirm();
        });
    }

    openModal(title, bodyHtml, footerHtml) {
        const root = document.getElementById('modal-root');
        const titleEl = document.getElementById('modal-title');
        const bodyEl = document.getElementById('modal-body');
        const footerEl = document.getElementById('modal-footer');

        if (!root || !titleEl || !bodyEl || !footerEl) return;

        titleEl.textContent = title;
        bodyEl.innerHTML = bodyHtml;
        footerEl.innerHTML = footerHtml;

        root.classList.remove('hidden');
    }

    closeModal() {
        const root = document.getElementById('modal-root');
        if (root) {
            root.classList.add('hidden');
        }
    }

    showToast(message, type = 'info') {
        const root = document.getElementById('toast-root');
        if (!root) return;

        const toast = document.createElement('div');
        toast.className = 'toast';
        if (type === 'error') {
            toast.style.borderLeft = '4px solid var(--danger)';
        } else if (type === 'warning') {
            toast.style.borderLeft = '4px solid var(--warning)';
        } else {
            toast.style.borderLeft = '4px solid var(--accent)';
        }

        toast.textContent = message;
        root.appendChild(toast);

        setTimeout(() => {
            toast.remove();
        }, 3500);
    }

    escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new AppController();
});
