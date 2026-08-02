/*
 * LIAS Control Center - Main Dashboard Application
 * File:    apps/lias/web/src/main.js
 * Version: 1.2
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

    this.initDOM();
    this.initEvents();
    this.loadInitialData();
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
    // Navigation routing for desktop sidebar AND mobile bottom bar
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

  async loadInitialData() {
    try {
      const [devRes, tagRes, polRes, schedRes] = await Promise.all([
        API.getDevices(),
        API.getTags(),
        API.getPolicies(),
        API.getSchedules(),
      ]);

      this.devices = devRes.devices || [];
      this.tags = tagRes || [];
      this.policies = polRes || [];
      this.schedules = schedRes || [];

      this.renderCurrentView();
    } catch (err) {
      this.showToast('Failed to load system data', 'danger');
      console.error(err);
    }
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

  // --- Views ---

  renderDashboardView() {
    const onlineCount = this.devices.filter((d) => d.online).length;
    const globalPol = this.policies.find((p) => p.id === 'global_default') || { action: 'allow' };

    this.viewContainer.innerHTML = `
      <!-- Global Access Kill-Switch Banner -->
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

    // Attach Global Switch listeners
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
          const pol = this.policies.find((p) => p.id === 'global_default');
          if (pol) pol.action = action;
          else this.policies.push({ id: 'global_default', action });

          this.renderDashboardView();
          this.showToast(`Global switch set to ${action.toUpperCase()}`, 'success');
        } catch (err) {
          this.showToast('Failed to update global switch', 'danger');
        }
      });
    });
  }

  renderDevicesView() {
    let html = `<div style="display: flex; flex-direction: column; gap: 24px;">`;

    // Group devices by Tag ID
    this.tags.forEach((tag) => {
      const groupDevs = this.devices.filter((d) => {
        const devTag = (d.tags && d.tags[0]) || 'generic';
        const matchesGroup = devTag === tag.id;

        const q = this.searchQuery;
        const matchesQuery =
          !q ||
          (d.hostname && d.hostname.toLowerCase().includes(q)) ||
          (d.current_ip && d.current_ip.toLowerCase().includes(q)) ||
          (d.current_mac && d.current_mac.toLowerCase().includes(q));

        return matchesGroup && matchesQuery;
      });

      const tagPolicy = this.policies.find((p) => p.type === 'tag' && p.target_id === tag.id);
      const tagPolicyBadge = tagPolicy
        ? `<span style="font-size: 12px; padding: 4px 10px; border-radius: 6px; background: var(--bg-tertiary); color: var(--accent); font-weight: 600;">Policy: ${tagPolicy.action.toUpperCase()}</span>`
        : `<span style="font-size: 12px; padding: 4px 10px; border-radius: 6px; background: var(--bg-tertiary); color: var(--text-secondary);">Default Inherit</span>`;

      html += `
        <div class="card" style="margin: 0;">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--separator); padding-bottom: 14px; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 12px;">
              <div style="width: 14px; height: 14px; border-radius: 4px; background-color: ${tag.color};"></div>
              <h3 style="font-size: 18px; font-weight: 700;">${tag.name} (${groupDevs.length})</h3>
              ${tagPolicyBadge}
            </div>
            ${tag.id !== 'infrastructure' ? `<button class="btn btn-ghost" data-tag-policy="${tag.id}" style="font-size: 13px;">Attach Schedule / Policy</button>` : `<span style="font-size: 12px; color: var(--success); font-weight: 600;">Immune to Block Rules</span>`}
          </div>

          <div style="display: flex; flex-direction: column; gap: 10px;">
      `;

      if (groupDevs.length === 0) {
        html += `<p style="font-size: 13px; color: var(--text-secondary); padding: 8px 0;">No devices in this group.</p>`;
      } else {
        groupDevs.forEach((d) => {
          const onlineDot = d.online ? '#34c759' : '#8e8e93';
          const vendorName = d.vendor || d.manufacturer || 'Generic Hardware';

          html += `
            <div style="display: flex; align-items: center; justify-content: space-between; background: var(--bg-tertiary); padding: 12px 16px; border-radius: 12px;">
              <div style="display: flex; align-items: center; gap: 14px;">
                <div style="width: 10px; height: 10px; border-radius: 50%; background-color: ${onlineDot}; flex-shrink: 0;"></div>
                <div>
                  <h4 style="font-size: 15px; font-weight: 600;">${d.friendly_name || d.hostname || 'Unknown Device'}</h4>
                  <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                    ${d.current_ip || 'No IP'} &bull; ${d.current_mac || 'No MAC'} &bull; ${vendorName}
                  </p>
                </div>
              </div>
              <div>
                <select data-move-pdid="${d.pdid}" style="padding: 6px 10px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-secondary); color: var(--text-primary); font-size: 12px; font-weight: 600;">
                  ${this.tags.map((t) => `<option value="${t.id}" ${t.id === tag.id ? 'selected' : ''}>Move to ${t.name}</option>`).join('')}
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

    // Attach Tag Policy Button Listeners
    this.viewContainer.querySelectorAll('[data-tag-policy]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const tagId = e.currentTarget.getAttribute('data-tag-policy');
        this.openTagPolicyModal(tagId);
      });
    });

    // Attach Move Tag Select Listeners
    this.viewContainer.querySelectorAll('[data-move-pdid]').forEach((select) => {
      select.addEventListener('change', async (e) => {
        const pdid = e.currentTarget.getAttribute('data-move-pdid');
        const newTagId = e.currentTarget.value;
        try {
          await API.assignDeviceTag(pdid, newTagId);
          const dev = this.devices.find((d) => d.pdid === pdid);
          if (dev) dev.tags = [newTagId];
          this.renderDevicesView();
          this.showToast('Device moved to new group', 'success');
        } catch (err) {
          this.showToast('Failed to reassign device', 'danger');
        }
      });
    });
  }

  renderSchedulesView() {
    let html = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3>Time Schedules</h3>
        <button class="btn btn-primary" id="add-schedule-btn">+ New Schedule</button>
      </div>
      <div style="display: flex; flex-direction: column; gap: 14px;">
    `;

    if (this.schedules.length === 0) {
      html += `<div class="card"><p style="color: var(--text-secondary);">No time schedules configured.</p></div>`;
    } else {
      this.schedules.forEach((s) => {
        let rulesSummary = '';
        if (s.rules && s.rules.length > 0) {
          rulesSummary = s.rules
            .map(
              (r) =>
                `<span style="display: inline-block; padding: 4px 8px; border-radius: 6px; background: var(--bg-tertiary); font-size: 12px; margin-right: 6px; margin-top: 6px;">
                  ${r.days.join(', ').toUpperCase()}: ${r.start_time} - ${r.end_time} (${r.action.toUpperCase()})
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
              <p style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">Timezone: ${s.timezone}</p>
              <div style="margin-top: 10px;">${rulesSummary}</div>
            </div>
            <button class="btn btn-danger" data-del-sched="${s.id}">Delete</button>
          </div>
        `;
      });
    }

    html += `</div>`;
    this.viewContainer.innerHTML = html;

    const addBtn = document.getElementById('add-schedule-btn');
    if (addBtn) addBtn.addEventListener('click', () => this.openAddScheduleModal());

    this.viewContainer.querySelectorAll('[data-del-sched]').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        const id = e.currentTarget.getAttribute('data-del-sched');
        try {
          await API.deleteSchedule(id);
          this.schedules = this.schedules.filter((s) => s.id !== id);
          this.renderSchedulesView();
          this.showToast('Schedule removed', 'success');
        } catch (err) {
          this.showToast('Failed to delete schedule', 'danger');
        }
      });
    });
  }

  renderPoliciesView() {
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
    this.viewContainer.innerHTML = `
      <div class="card">
        <h3>System Settings</h3>
        <p style="color: var(--text-secondary); margin-top: 8px;">
          LIAS Version: 1.5 &bull; Netfilter Table: <code>netdev lancontrol</code>
        </p>
      </div>
    `;
  }

  // --- Modals ---

  openAddScheduleModal() {
    this.modalTitle.textContent = 'Create New Schedule Window';
    this.modalBody.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Schedule Name</label>
          <input type="text" id="sched-name" placeholder="e.g. Bedtime Schedule" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
        </div>

        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Timezone</label>
          <input type="text" id="sched-tz" value="UTC" placeholder="e.g. UTC, America/Los_Angeles" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
        </div>

        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Days Active</label>
          <div class="day-chip-group" id="day-selector">
            <div class="day-chip selected" data-day="mon">Mon</div>
            <div class="day-chip selected" data-day="tue">Tue</div>
            <div class="day-chip selected" data-day="wed">Wed</div>
            <div class="day-chip selected" data-day="thu">Thu</div>
            <div class="day-chip selected" data-day="fri">Fri</div>
            <div class="day-chip" data-day="sat">Sat</div>
            <div class="day-chip" data-day="sun">Sun</div>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
          <div>
            <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Start Time</label>
            <input type="time" id="sched-start" value="22:00" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
          </div>
          <div>
            <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">End Time</label>
            <input type="time" id="sched-end" value="06:00" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
          </div>
        </div>

        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Action Within Window</label>
          <select id="sched-act" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
            <option value="block">Block Access (Downtime)</option>
            <option value="allow">Allow Access (Whitelist Window)</option>
          </select>
        </div>
      </div>
    `;

    // Attach Day Chip Selection Handler
    this.modalBody.querySelectorAll('.day-chip').forEach((chip) => {
      chip.addEventListener('click', (e) => {
        e.currentTarget.classList.toggle('selected');
      });
    });

    this.modalFooter.innerHTML = `<button class="btn btn-primary" id="save-sched-btn">Save Schedule</button>`;

    document.getElementById('save-sched-btn').onclick = async () => {
      const name = document.getElementById('sched-name').value;
      const tz = document.getElementById('sched-tz').value;
      const startTime = document.getElementById('sched-start').value;
      const endTime = document.getElementById('sched-end').value;
      const action = document.getElementById('sched-act').value;

      const selectedDays = [];
      this.modalBody.querySelectorAll('.day-chip.selected').forEach((chip) => {
        selectedDays.push(chip.getAttribute('data-day'));
      });

      if (!name || selectedDays.length === 0) {
        this.showToast('Please enter a schedule name and select days', 'danger');
        return;
      }

      const rule = {
        days: selectedDays,
        start_time: startTime,
        end_time: endTime,
        action: action,
      };

      try {
        const created = await API.createSchedule({
          name: name,
          timezone: tz,
          rules: [rule],
        });
        this.schedules.push(created);
        this.hideModal();
        this.renderSchedulesView();
        this.showToast('Schedule created successfully', 'success');
      } catch (err) {
        this.showToast('Failed to create schedule', 'danger');
      }
    };

    this.showModal();
  }

  openTagPolicyModal(tagId) {
    const tag = this.tags.find((t) => t.id === tagId);
    if (!tag) return;

    this.modalTitle.textContent = `Group Policy: ${tag.name}`;
    this.modalBody.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div>
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Access Action</label>
          <select id="tag-act-select" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
            <option value="allow">Always Allow Group Devices</option>
            <option value="block">Always Block Group Devices</option>
            <option value="schedule">Apply Time Schedule to Group</option>
          </select>
        </div>

        <div id="tag-sched-container" style="display: none;">
          <label style="font-size: 12px; font-weight: 600; color: var(--text-secondary); text-transform: uppercase;">Select Schedule</label>
          <select id="tag-sched-select" style="width: 100%; padding: 10px; margin-top: 4px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
            ${this.schedules.map((s) => `<option value="${s.id}">${s.name} (${s.timezone})</option>`).join('')}
          </select>
        </div>
      </div>
    `;

    const actSelect = document.getElementById('tag-act-select');
    const schedContainer = document.getElementById('tag-sched-container');

    actSelect.addEventListener('change', (e) => {
      schedContainer.style.display = e.target.value === 'schedule' ? 'block' : 'none';
    });

    this.modalFooter.innerHTML = `<button class="btn btn-primary" id="save-tag-pol-btn">Apply Policy</button>`;

    document.getElementById('save-tag-pol-btn').onclick = async () => {
      const action = actSelect.value;
      const schedId = document.getElementById('tag-sched-select').value;

      const policyPayload = {
        name: `${tag.name} Group Policy`,
        type: 'tag',
        target_id: tagId,
        action: action,
        priority: 50,
      };

      if (action === 'schedule') {
        policyPayload.schedule_id = schedId;
      }

      try {
        await API.createPolicy(policyPayload);
        this.showToast(`Policy updated for ${tag.name}`, 'success');
        this.hideModal();
        await this.loadInitialData();
      } catch (err) {
        this.showToast('Failed to apply tag policy', 'danger');
      }
    };

    this.showModal();
  }

  showModal() { this.modalRoot.classList.remove('hidden'); }
  hideModal() { this.modalRoot.classList.add('hidden'); }

  showToast(message, type = 'info') {
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
