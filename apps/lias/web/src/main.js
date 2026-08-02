/*
 * LIAS Control Center - Main Dashboard Application
 * File:    apps/lias/web/src/main.js
 * Version: 2.2 (Restored renderCurrentView Method, Complete Null Safety, Real-Time SSE)
 */

import { API } from './api.js';

class LiasDashboard {
  constructor() {
    this.currentView = 'dashboard';
    this.devices = [];
    this.tags = [];
    this.policies = [];
    this.schedules = [];
    this.searchQuery = '';

    try {
      this.collapsedGroups = JSON.parse(localStorage.getItem('lias_collapsed_groups') || '{}');
    } catch (e) {
      this.collapsedGroups = {};
    }

    this.initDOM();
    this.initEvents();
    this.loadInitialData();
    this.initRealtimeEvents();
  }

  initDOM() {
    this.viewTitle = document.getElementById('view-title');
    this.viewContainer = document.getElementById('view-container');
    this.searchInput = document.querySelector('.search-bar input');
    this.modalRoot = document.getElementById('modal-root');
    this.modalTitle = document.getElementById('modal-title');
    this.modalBody = document.getElementById('modal-body');
    this.modalFooter = document.getElementById('modal-footer');
    this.toastRoot = document.getElementById('toast-root');
  }

  initEvents() {
    document.querySelectorAll('[data-view]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const view = e.currentTarget.getAttribute('data-view');
        this.switchView(view);
      });
    });

    if (this.searchInput) {
      this.searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase();
        if (this.currentView === 'devices') {
          this.renderDevicesView();
        }
      });
    }

    const closeBtn = document.querySelector('.modal-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.hideModal());
    }
  }

  initRealtimeEvents() {
    API.subscribeEvents((evt) => {
      this.loadInitialDataSilently();
    });
  }

  async loadInitialDataSilently() {
    try {
      const [devRes, tagRes, polRes, schedRes] = await Promise.all([
        API.getDevices(),
        API.getTags(),
        API.getPolicies(),
        API.getSchedules(),
      ]);

      this.devices = (devRes && devRes.devices) ? devRes.devices : (Array.isArray(devRes) ? devRes : []);
      this.tags = Array.isArray(tagRes) ? tagRes : [];
      this.policies = Array.isArray(polRes) ? polRes : [];
      this.schedules = Array.isArray(schedRes) ? schedRes : [];

      this.renderCurrentView();
    } catch (err) {
      console.error('Silent refresh error:', err);
      if (this.viewContainer && this.viewContainer.querySelector('.loader')) {
        this.renderErrorState(err);
      }
    }
  }

  async loadInitialData() {
    try {
      await this.loadInitialDataSilently();
    } catch (err) {
      this.showToast('Failed to connect to LIAS backend', 'danger');
      this.renderErrorState(err);
    }
  }

  renderErrorState(err) {
    if (!this.viewContainer) return;
    this.viewContainer.innerHTML = `
      <div class="card" style="text-align: center; padding: 40px 24px; margin-top: 20px;">
        <div style="width: 48px; height: 48px; border-radius: 50%; background: rgba(255, 59, 48, 0.1); color: var(--danger); display: inline-flex; align-items: center; justify-content: center; margin-bottom: 16px;">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        </div>
        <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 8px;">Unable to Connect to LIAS Backend</h3>
        <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px; max-width: 400px; margin-left: auto; margin-right: auto;">
          ${err && err.message ? err.message : 'Check network connection or ensure the lias service is running on port :8081.'}
        </p>
        <button class="btn btn-primary" onclick="window.app.loadInitialData()">Retry Connection</button>
      </div>
    `;
  }

  switchView(view) {
    this.currentView = view;

    document.querySelectorAll('[data-view]').forEach((btn) => {
      btn.classList.toggle('active', btn.getAttribute('data-view') === view);
    });

    const titles = {
      dashboard: 'Dashboard',
      devices: 'Device Groups',
      schedules: 'Schedules',
      policies: 'Policies',
      settings: 'Settings',
    };
    if (this.viewTitle) this.viewTitle.textContent = titles[view] || 'Dashboard';

    this.renderCurrentView();
  }

  // RESTORED METHOD: Renders active view based on currentView property
  renderCurrentView() {
    switch (this.currentView) {
      case 'dashboard':
        this.renderDashboardView();
        break;
      case 'devices':
        this.renderDevicesView();
        break;
      case 'schedules':
        this.renderSchedulesView();
        break;
      case 'policies':
        this.renderPoliciesView();
        break;
      case 'settings':
        this.renderSettingsView();
        break;
      default:
        this.renderDashboardView();
    }
  }

  formatLastSeen(isoStr, isOnline) {
    if (isOnline) return '<span style="color: var(--success); font-weight: 600;">Online Now</span>';
    if (!isoStr) return '<span style="color: var(--text-secondary);">Offline</span>';

    try {
      const date = new Date(isoStr);
      const now = new Date();
      const diffMs = now - date;
      const diffMins = Math.floor(diffMs / 60000);
      const diffHours = Math.floor(diffMins / 60);

      if (diffMins < 1) return 'Offline • Just now';
      if (diffMins < 60) return `Offline • ${diffMins}m ago`;
      if (diffHours < 24) return `Offline • ${diffHours}h ago`;
      return `Offline • ${date.toLocaleDateString()}`;
    } catch (e) {
      return 'Offline';
    }
  }

  ensure24Hour(timeStr) {
    if (!timeStr) return "12:00";
    if (/^\d{2}:\d{2}$/.test(timeStr)) return timeStr;
    if (/^\d{1}:\d{2}$/.test(timeStr)) return "0" + timeStr;

    const match = timeStr.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)?$/i);
    if (match) {
      let hrs = parseInt(match[1], 10);
      const mins = match[2];
      const ampm = match[3] ? match[3].toUpperCase() : '';
      if (ampm === 'PM' && hrs < 12) hrs += 12;
      if (ampm === 'AM' && hrs === 12) hrs = 0;
      return `${hrs.toString().padStart(2, '0')}:${mins}`;
    }
    return timeStr;
  }

  renderDashboardView() {
    if (!this.viewContainer) return;
    const onlineCount = (this.devices || []).filter((d) => d && d.online).length;
    const globalPol = (this.policies || []).find((p) => p && p.id === 'global_default') || { action: 'schedule' };

    this.viewContainer.innerHTML = `
      <div class="global-switch-banner">
        <div>
          <h3 style="font-size: 18px; font-weight: 700;">Global Network Switch</h3>
          <p style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">
            Infrastructure devices (Gateway, Switches) are <strong style="color: var(--success);">IMMUNE</strong> to global block rules.
          </p>
        </div>
        <div class="segmented-control">
          <button class="segmented-btn ${globalPol.action === 'allow' ? 'active' : ''}" data-global-act="allow">Always Allow</button>
          <button class="segmented-btn ${globalPol.action === 'schedule' ? 'active' : ''}" data-global-act="schedule">Scheduled</button>
          <button class="segmented-btn danger ${globalPol.action === 'block' ? 'active' : ''}" data-global-act="block">Block All</button>
        </div>
      </div>

      <div class="card-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px;">
        <div class="card" style="margin: 0;">
          <h4 style="color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Total Devices</h4>
          <p style="font-size: 32px; font-weight: 700; margin-top: 8px;">${this.devices.length}</p>
        </div>
        <div class="card" style="margin: 0;">
          <h4 style="color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Online Now</h4>
          <p style="font-size: 32px; font-weight: 700; margin-top: 8px; color: var(--success);">${onlineCount}</p>
        </div>
        <div class="card" style="margin: 0;">
          <h4 style="color: var(--text-secondary); font-size: 12px; text-transform: uppercase;">Tag Groups</h4>
          <p style="font-size: 32px; font-weight: 700; margin-top: 8px; color: var(--accent);">${this.tags.length}</p>
        </div>
      </div>
    `;

    this.viewContainer.querySelectorAll('[data-global-act]').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        const action = e.currentTarget.getAttribute('data-global-act');
        try {
          await API.createPolicy({
            id: 'global_default',
            name: 'Global Access Switch',
            type: 'global',
            action: action,
            priority: 0,
          });
          const pol = (this.policies || []).find((p) => p && p.id === 'global_default');
          if (pol) pol.action = action;
          else this.policies.push({ id: 'global_default', action });

          this.renderDashboardView();
          this.showToast(`Global switch set to ${action.toUpperCase()} & persisted`, 'success');
        } catch (err) {
          this.showToast('Failed to update global switch', 'danger');
        }
      });
    });
  }

  toggleGroupCollapse(tagId) {
    this.collapsedGroups[tagId] = !this.collapsedGroups[tagId];
    try {
      localStorage.setItem('lias_collapsed_groups', JSON.stringify(this.collapsedGroups));
    } catch (e) {}
    this.renderDevicesView();
  }

  getEffectiveTags() {
    const tagMap = new Map();
    if (Array.isArray(this.tags)) {
      this.tags.forEach((t) => { if (t && t.id) tagMap.set(t.id, t); });
    }

    if (Array.isArray(this.devices)) {
      this.devices.forEach((d) => {
        if (!d) return;
        const tagId = (d.tags && d.tags[0]) || 'generic';
        if (!tagMap.has(tagId)) {
          tagMap.set(tagId, {
            id: tagId,
            name: tagId.charAt(0).toUpperCase() + tagId.slice(1).replace(/_/g, ' '),
            color: '#0071e3',
            precedence: 50,
            builtin: false,
          });
        }
      });
    }

    return Array.from(tagMap.values());
  }

  renderDevicesView() {
    if (!this.viewContainer) return;
    let html = `<div style="display: flex; flex-direction: column; gap: 24px;">`;
    const effectiveTags = this.getEffectiveTags();

    effectiveTags.forEach((tag) => {
      const groupDevs = (this.devices || []).filter((d) => {
        if (!d) return false;
        const devTag = (d.tags && d.tags[0]) || 'generic';
        const matchesGroup = devTag === tag.id;

        const q = this.searchQuery;
        const matchesQuery =
          !q ||
          (d.hostname && d.hostname.toLowerCase().includes(q)) ||
          (d.friendly_name && d.friendly_name.toLowerCase().includes(q)) ||
          (d.current_ip && d.current_ip.toLowerCase().includes(q)) ||
          (d.current_mac && d.current_mac.toLowerCase().includes(q));

        return matchesGroup && matchesQuery;
      });

      const tagPolicies = (this.policies || []).filter((p) => p && p.type === 'tag' && p.target_id === tag.id);
      const isCollapsed = !!this.collapsedGroups[tag.id];

      let tagPolicyBadges = '';
      if (tagPolicies.length > 0) {
        tagPolicyBadges = tagPolicies
          .map((p) => {
            const schedObj = p.schedule_id ? (this.schedules || []).find((s) => s && s.id === p.schedule_id) : null;
            const schedName = schedObj ? schedObj.name : '';
            const label = p.action === 'schedule' ? `SCHEDULE (${schedName})` : p.action.toUpperCase();
            return `
              <span style="display: inline-flex; align-items: center; gap: 6px; font-size: 11px; padding: 4px 10px; border-radius: 6px; background: var(--bg-tertiary); color: var(--accent); font-weight: 600; margin-right: 6px; margin-top: 4px;">
                ${p.name || 'Rule'}: ${label}
                <button data-del-pol="${p.id}" style="border:none; background:none; color:var(--danger); cursor:pointer; font-weight:bold; font-size:14px; line-height:1;">&times;</button>
              </span>
            `;
          })
          .join('');
      } else {
        tagPolicyBadges = `<span style="font-size: 11px; padding: 4px 10px; border-radius: 6px; background: var(--bg-tertiary); color: var(--text-secondary);">Default Inherit</span>`;
      }

      html += `
        <div class="group-card ${isCollapsed ? 'collapsed' : ''}" style="margin: 0;">
          <div class="group-header" data-toggle-group="${tag.id}" style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid var(--separator); padding: 18px 24px; cursor: pointer; user-select: none;">
            <div>
              <div style="display: flex; align-items: center; gap: 10px;">
                <div style="width: 14px; height: 14px; border-radius: 4px; background-color: ${tag.color};"></div>
                <h3 style="font-size: 18px; font-weight: 700;">${tag.name} (${groupDevs.length})</h3>
              </div>
              <div style="margin-top: 8px;">${tagPolicyBadges}</div>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
              ${tag.id !== 'infrastructure' ? `<button class="btn btn-primary" data-add-tag-policy="${tag.id}" style="font-size: 12px;" onclick="event.stopPropagation();">+ Attach Rule / Schedule</button>` : `<span style="font-size: 12px; color: var(--success); font-weight: 600;">Immune to Block Rules</span>`}
              <svg class="group-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:20px; height:20px; color:var(--text-secondary); transition: transform 0.25s ease; ${isCollapsed ? 'transform: rotate(-90deg);' : ''}"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
          </div>

          <div class="group-content" style="padding: 20px 24px; display: ${isCollapsed ? 'none' : 'flex'}; flex-direction: column; gap: 10px;">
      `;

      if (groupDevs.length === 0) {
        html += `<p style="font-size: 13px; color: var(--text-secondary); padding: 8px 0;">No devices in this group.</p>`;
      } else {
        groupDevs.forEach((d) => {
          const vendorName = d.vendor || d.manufacturer || 'Generic Hardware';
          const lastSeenHTML = this.formatLastSeen(d.last_seen, d.online);

          const displayName = (d.hostname && d.hostname.trim()) || 
                              (d.friendly_name && d.friendly_name.trim()) || 
                              'Unknown Device';

          let servicePills = '';
          if (d.services && d.services.length > 0) {
            servicePills = `
              <div class="service-pill-list">
                ${d.services.map((svc) => `<span class="service-pill"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle></svg>${svc}</span>`).join('')}
              </div>
            `;
          }

          html += `
            <div style="display: flex; align-items: center; justify-content: space-between; background: var(--bg-tertiary); padding: 14px 16px; border-radius: 12px; border: 1px solid var(--separator);">
              <div style="display: flex; align-items: flex-start; gap: 14px;">
                <div class="status-indicator ${d.online ? 'online' : 'offline'}" style="margin-top: 4px;" title="${d.online ? 'Online' : 'Offline'}"></div>
                <div>
                  <h4 style="font-size: 15px; font-weight: 600;">${displayName}</h4>
                  <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                    ${d.current_ip || 'No IP'} &bull; ${d.current_mac || 'No MAC'} &bull; ${vendorName}
                  </p>
                  <div style="margin-top: 4px; font-size: 11px;">${lastSeenHTML}</div>
                  ${servicePills ? `<div style="margin-top: 8px;">${servicePills}</div>` : ''}
                </div>
              </div>
              <div>
                <select data-move-pdid="${d.pdid}" style="padding: 6px 10px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-secondary); color: var(--text-primary); font-size: 12px; font-weight: 600;">
                  ${effectiveTags.map((t) => `<option value="${t.id}" ${t.id === tag.id ? 'selected' : ''}>Move to ${t.name}</option>`).join('')}
                </select>
              </div>
            </div>
          `;
        });
      }

      html += `</div></div>`;
    });

    html += `</div>`;
    this.viewContainer.innerHTML = html;

    this.viewContainer.querySelectorAll('[data-toggle-group]').forEach((header) => {
      header.addEventListener('click', (e) => {
        const tagId = e.currentTarget.getAttribute('data-toggle-group');
        this.toggleGroupCollapse(tagId);
      });
    });

    this.viewContainer.querySelectorAll('[data-add-tag-policy]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const tagId = e.currentTarget.getAttribute('data-add-tag-policy');
        this.openTagPolicyModal(tagId);
      });
    });

    this.viewContainer.querySelectorAll('[data-del-pol]').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const polId = e.currentTarget.getAttribute('data-del-pol');
        try {
          await API.deletePolicy(polId);
          this.policies = (this.policies || []).filter((p) => p && p.id !== polId);
          this.renderDevicesView();
          this.showToast('Policy removed from group', 'success');
        } catch (err) {
          this.showToast('Failed to delete policy', 'danger');
        }
      });
    });

    this.viewContainer.querySelectorAll('[data-move-pdid]').forEach((select) => {
      select.addEventListener('change', async (e) => {
        const pdid = e.currentTarget.getAttribute('data-move-pdid');
        const newTagId = e.currentTarget.value;
        try {
          await API.assignDeviceTag(pdid, newTagId);
          const dev = (this.devices || []).find((d) => d && d.pdid === pdid);
          if (dev) dev.tags = [newTagId];
          this.renderDevicesView();
          this.showToast('Device reassigned & saved persistently', 'success');
        } catch (err) {
          this.showToast('Failed to reassign device', 'danger');
        }
      });
    });
  }

  renderSchedulesView() {
    if (!this.viewContainer) return;
    let html = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3>Time Schedules</h3>
        <button class="btn btn-primary" id="add-schedule-btn">+ New Schedule</button>
      </div>
      <div style="display: flex; flex-direction: column; gap: 14px;">
    `;

    if (!this.schedules || this.schedules.length === 0) {
      html += `<div class="card"><p style="color: var(--text-secondary);">No time schedules configured.</p></div>`;
    } else {
      this.schedules.forEach((s) => {
        if (!s) return;
        let rulesSummary = '';
        if (s.rules && s.rules.length > 0) {
          rulesSummary = s.rules
            .map(
              (r) =>
                `<span style="display: inline-block; padding: 4px 10px; border-radius: 6px; background: var(--bg-tertiary); font-size: 12px; margin-right: 6px; margin-top: 6px; font-weight: 600;">
                  ${(r.days || []).join(', ').toUpperCase()}: ${r.start_time} - ${r.end_time} (${(r.action || 'block').toUpperCase()})
                </span>`
            )
            .join('');
        } else {
          rulesSummary = `<span style="font-size: 12px; color: var(--text-secondary);">No rules added yet</span>`;
        }

        html += `
          <div class="card" style="margin: 0; display: flex; justify-content: space-between; align-items: flex-start;">
            <div>
              <h4 style="font-size: 16px; font-weight: 700;">${s.name}</h4>
              <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; background: var(--bg-tertiary); color: var(--accent); font-weight: 600;">Timezone: ${s.timezone}</span>
              </p>
              <div style="margin-top: 10px;">${rulesSummary}</div>
            </div>
            <div style="display: flex; gap: 8px;">
              <button class="btn btn-secondary" data-edit-sched="${s.id}">Edit</button>
              <button class="btn btn-danger" data-del-sched="${s.id}">Delete</button>
            </div>
          </div>
        `;
      });
    }

    html += `</div>`;
    this.viewContainer.innerHTML = html;

    const addBtn = document.getElementById('add-schedule-btn');
    if (addBtn) addBtn.addEventListener('click', () => this.openScheduleModal());

    this.viewContainer.querySelectorAll('[data-edit-sched]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.getAttribute('data-edit-sched');
        this.openScheduleModal(id);
      });
    });

    this.viewContainer.querySelectorAll('[data-del-sched]').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-del-sched');
        try {
          await API.deleteSchedule(id);
          this.schedules = (this.schedules || []).filter((s) => s && s.id !== id);
          this.renderSchedulesView();
          this.showToast('Schedule removed', 'success');
        } catch (err) {
          this.showToast('Failed to delete schedule', 'danger');
        }
      });
    });
  }

  renderPoliciesView() {
    if (!this.viewContainer) return;
    this.viewContainer.innerHTML = `
      <div class="card">
        <h3>Policy Rules Summary</h3>
        <p style="color: var(--text-secondary); margin-top: 8px;">
          Attach schedules directly to Tag Groups under the <strong>Device Groups</strong> tab.
        </p>
      </div>
    `;
  }

  renderSettingsView() {
    if (!this.viewContainer) return;
    this.viewContainer.innerHTML = `
      <div class="card">
        <h3>System Settings</h3>
        <p style="color: var(--text-secondary); margin-top: 8px;">
          LIAS Version: 2.2 &bull; Netfilter Table: <code>netdev lancontrol</code>
        </p>
      </div>
    `;
  }

  openScheduleModal(scheduleId = null) {
    const existingSched = scheduleId ? (this.schedules || []).find((s) => s && s.id === scheduleId) : null;

    let detectedTz = 'UTC';
    try {
      detectedTz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    } catch (e) {
      detectedTz = 'UTC';
    }

    const name = existingSched ? existingSched.name : '';
    const tz = existingSched ? existingSched.timezone : detectedTz;
    const firstRule = existingSched && existingSched.rules && existingSched.rules[0] ? existingSched.rules[0] : { days: ['mon', 'tue', 'wed', 'thu', 'fri'], start_time: '22:00', end_time: '06:00', action: 'block' };

    const startTime24 = this.ensure24Hour(firstRule.start_time);
    const endTime24 = this.ensure24Hour(firstRule.end_time);

    this.modalTitle.textContent = scheduleId ? 'Edit Schedule Window' : 'Create New Schedule Window';
    this.modalBody.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Schedule Name</label>
          <input type="text" id="sched-name" value="${name}" placeholder="e.g. Bedtime Lockout" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
        </div>

        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Timezone</label>
          <select id="sched-tz" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary); font-weight: 600;">
            <option value="${tz}" selected>${tz}</option>
            <option value="UTC">UTC (Coordinated Universal Time)</option>
            <option value="America/New_York">Eastern Time (America/New_York)</option>
            <option value="America/Chicago">Central Time (America/Chicago)</option>
            <option value="America/Denver">Mountain Time (America/Denver)</option>
            <option value="America/Los_Angeles">Pacific Time (America/Los_Angeles)</option>
            <option value="Europe/London">London / GMT (Europe/London)</option>
            <option value="Europe/Paris">Central European (Europe/Paris)</option>
            <option value="Asia/Tokyo">Japan Standard (Asia/Tokyo)</option>
            <option value="Australia/Sydney">Australian Eastern (Australia/Sydney)</option>
          </select>
        </div>

        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Days Active</label>
          <div class="day-chip-group" id="day-selector">
            ${['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'].map((d) => {
              const isSelected = firstRule.days && firstRule.days.includes(d);
              return `<div class="day-chip ${isSelected ? 'selected' : ''}" data-day="${d}">${d.toUpperCase()}</div>`;
            }).join('')}
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
          <div>
            <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Start Time</label>
            <input type="time" id="sched-start" value="${startTime24}" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
          </div>
          <div>
            <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">End Time</label>
            <input type="time" id="sched-end" value="${endTime24}" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
          </div>
        </div>

        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Action Within Window</label>
          <select id="sched-act" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
            <option value="block" ${firstRule.action === 'block' ? 'selected' : ''}>Block Access (Downtime Window)</option>
            <option value="allow" ${firstRule.action === 'allow' ? 'selected' : ''}>Allow Access (Whitelist Window)</option>
          </select>
        </div>
      </div>
    `;

    this.modalBody.querySelectorAll('.day-chip').forEach((chip) => {
      chip.addEventListener('click', (e) => {
        e.currentTarget.classList.toggle('selected');
      });
    });

    this.modalFooter.innerHTML = `<button class="btn btn-primary" id="save-sched-btn">Save Schedule</button>`;

    document.getElementById('save-sched-btn').onclick = async () => {
      const schedName = document.getElementById('sched-name').value.trim();
      const schedTz = document.getElementById('sched-tz').value;
      const startTime = document.getElementById('sched-start').value;
      const endTime = document.getElementById('sched-end').value;
      const action = document.getElementById('sched-act').value;

      const selectedDays = [];
      this.modalBody.querySelectorAll('.day-chip.selected').forEach((chip) => {
        selectedDays.push(chip.getAttribute('data-day'));
      });

      if (!schedName || selectedDays.length === 0) {
        this.showToast('Please enter a schedule name and select days', 'danger');
        return;
      }

      const rule = {
        days: selectedDays,
        start_time: startTime,
        end_time: endTime,
        action: action,
      };

      const payload = {
        name: schedName,
        timezone: schedTz,
        rules: [rule],
      };

      try {
        if (scheduleId) {
          payload.id = scheduleId;
          const updated = await API.updateSchedule(scheduleId, payload);
          const idx = (this.schedules || []).findIndex((s) => s && s.id === scheduleId);
          if (idx !== -1) this.schedules[idx] = updated;
          this.showToast('Schedule updated successfully', 'success');
        } else {
          const created = await API.createSchedule(payload);
          this.schedules.push(created);
          this.showToast(`Schedule created (${schedTz})`, 'success');
        }

        this.hideModal();
        this.renderSchedulesView();
      } catch (err) {
        this.showToast('Failed to save schedule', 'danger');
      }
    };

    this.showModal();
  }

  openTagPolicyModal(tagId) {
    const tag = (this.tags || []).find((t) => t && t.id === tagId);
    if (!tag) return;

    this.modalTitle.textContent = `Attach Policy / Schedule to ${tag.name}`;
    this.modalBody.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Rule Name</label>
          <input type="text" id="tag-pol-name" value="${tag.name} Access Rule" placeholder="Rule Name" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
        </div>

        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Access Action</label>
          <select id="tag-act-select" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
            <option value="allow">Always Allow Group Devices</option>
            <option value="block">Always Block Group Devices</option>
            <option value="schedule">Apply Time Schedule to Group</option>
          </select>
        </div>

        <div id="tag-sched-container" style="display: none;">
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Select Time Schedule</label>
          <select id="tag-sched-select" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
            ${(this.schedules || []).map((s) => `<option value="${s.id}">${s.name} (${s.timezone})</option>`).join('')}
          </select>
        </div>
      </div>
    `;

    const actSelect = document.getElementById('tag-act-select');
    const schedContainer = document.getElementById('tag-sched-container');

    actSelect.addEventListener('change', (e) => {
      schedContainer.style.display = e.target.value === 'schedule' ? 'block' : 'none';
    });

    this.modalFooter.innerHTML = `<button class="btn btn-primary" id="save-tag-pol-btn">Attach Policy</button>`;

    document.getElementById('save-tag-pol-btn').onclick = async () => {
      const polName = document.getElementById('tag-pol-name').value;
      const action = actSelect.value;
      const schedId = document.getElementById('tag-sched-select').value;

      const policyPayload = {
        name: polName || `${tag.name} Access Rule`,
        type: 'tag',
        target_id: tagId,
        action: action,
        priority: 50,
      };

      if (action === 'schedule') {
        policyPayload.schedule_id = schedId;
      }

      try {
        const created = await API.createPolicy(policyPayload);
        this.policies.push(created);
        this.showToast(`Policy attached to ${tag.name}`, 'success');
        this.hideModal();
        this.renderDevicesView();
      } catch (err) {
        this.showToast('Failed to attach policy', 'danger');
      }
    };

    this.showModal();
  }

  showModal() { if (this.modalRoot) this.modalRoot.classList.remove('hidden'); }
  hideModal() { if (this.modalRoot) this.modalRoot.classList.add('hidden'); }

  showToast(message, type = 'info') {
    if (!this.toastRoot) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    this.toastRoot.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 3000);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.app = new LiasDashboard();
});
