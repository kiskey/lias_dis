/*
 * LIAS Control Center - Main Dashboard Application
 * File:    apps/lias/web/src/main.js
 * Version: 1.0
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
    // Navigation routing listeners
    document.querySelectorAll('[data-view]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const view = e.currentTarget.getAttribute('data-view');
        this.switchView(view);
      });
    });

    // Search bar live filtering
    if (this.searchInput) {
      this.searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase();
        if (this.currentView === 'devices') {
          this.renderDevicesView();
        }
      });
    }

    // Modal close button
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

    // Update nav active states
    document.querySelectorAll('[data-view]').forEach((btn) => {
      btn.classList.toggle('active', btn.getAttribute('data-view') === view);
    });

    const titles = {
      dashboard: 'Dashboard',
      devices: 'Devices',
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
    const totalCount = this.devices.length;

    this.viewContainer.innerHTML = `
      <div class="card-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px;">
        <div class="card" style="margin: 0;">
          <h4 style="color: var(--text-secondary); font-size: 13px; text-transform: uppercase;">Total Devices</h4>
          <p style="font-size: 32px; font-weight: 700; margin-top: 8px;">${totalCount}</p>
        </div>
        <div class="card" style="margin: 0;">
          <h4 style="color: var(--text-secondary); font-size: 13px; text-transform: uppercase;">Online Now</h4>
          <p style="font-size: 32px; font-weight: 700; margin-top: 8px; color: var(--success);">${onlineCount}</p>
        </div>
        <div class="card" style="margin: 0;">
          <h4 style="color: var(--text-secondary); font-size: 13px; text-transform: uppercase;">Active Schedules</h4>
          <p style="font-size: 32px; font-weight: 700; margin-top: 8px; color: var(--accent);">${this.schedules.length}</p>
        </div>
      </div>

      <div class="card">
        <h3>System Overview</h3>
        <p style="color: var(--text-secondary); margin-top: 8px;">
          LIAS Network Control active. Isolated <code>netdev lancontrol</code> table operating on LAN ingress.
        </p>
      </div>
    `;
  }

  renderDevicesView() {
    const filtered = this.devices.filter((d) => {
      const q = this.searchQuery;
      return (
        !q ||
        (d.hostname && d.hostname.toLowerCase().includes(q)) ||
        (d.current_ip && d.current_ip.toLowerCase().includes(q)) ||
        (d.current_mac && d.current_mac.toLowerCase().includes(q)) ||
        (d.vendor && d.vendor.toLowerCase().includes(q))
      );
    });

    let html = `<div style="display: flex; flex-direction: column; gap: 12px;">`;

    if (filtered.length === 0) {
      html += `<div class="card"><p style="color: var(--text-secondary);">No matching devices found.</p></div>`;
    } else {
      filtered.forEach((d) => {
        const onlineDot = d.online ? '#34c759' : '#8e8e93';
        const vendorName = d.vendor || d.manufacturer || 'Generic Hardware';
        const devType = d.device_type || 'unclassified';

        html += `
          <div class="card" style="margin: 0; display: flex; align-items: center; justify-content: space-between; padding: 16px 24px;">
            <div style="display: flex; align-items: center; gap: 16px;">
              <div style="width: 12px; height: 12px; border-radius: 50%; background-color: ${onlineDot}; flex-shrink: 0;"></div>
              <div>
                <h4 style="font-size: 16px; font-weight: 600;">${d.friendly_name || d.hostname || 'Unknown Device'}</h4>
                <p style="font-size: 13px; color: var(--text-secondary); margin-top: 2px;">
                  ${d.current_ip || 'No IP'} &bull; ${d.current_mac || 'No MAC'} &bull; ${vendorName} (${devType})
                </p>
              </div>
            </div>
            <button class="btn btn-ghost" data-pdid="${d.pdid}">Manage</button>
          </div>
        `;
      });
    }

    html += `</div>`;
    this.viewContainer.innerHTML = html;

    // Attach click listeners for device management
    this.viewContainer.querySelectorAll('button[data-pdid]').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.getAttribute('data-pdid');
        this.openDeviceModal(pdid);
      });
    });
  }

  renderSchedulesView() {
    let html = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3>Configured Schedules</h3>
        <button class="btn btn-primary" id="add-schedule-btn">+ Add Schedule</button>
      </div>
      <div style="display: flex; flex-direction: column; gap: 12px;">
    `;

    if (this.schedules.length === 0) {
      html += `<div class="card"><p style="color: var(--text-secondary);">No time schedules configured.</p></div>`;
    } else {
      this.schedules.forEach((s) => {
        html += `
          <div class="card" style="margin: 0; display: flex; justify-content: space-between; align-items: center;">
            <div>
              <h4>${s.name}</h4>
              <p style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">
                Timezone: ${s.timezone} &bull; ${s.rules ? s.rules.length : 0} rules
              </p>
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
        <h3>Access Control Policies</h3>
        <p style="color: var(--text-secondary); margin-top: 8px;">
          Precedence Order: <code>Infrastructure Override</code> &gt; <code>Device Rules</code> &gt; <code>Tag Rules</code> &gt; <code>Global Default</code>.
        </p>
      </div>
    `;
  }

  renderSettingsView() {
    this.viewContainer.innerHTML = `
      <div class="card">
        <h3>System Settings</h3>
        <p style="color: var(--text-secondary); margin-top: 8px;">
          LIAS Version: 1.4 &bull; Isolated Firewall Table: <code>lancontrol</code> &bull; Network Hook: <code>netdev ingress</code>
        </p>
      </div>
    `;
  }

  // --- Modals & Toasts ---

  openDeviceModal(pdid) {
    const dev = this.devices.find((d) => d.pdid === pdid);
    if (!dev) return;

    this.modalTitle.textContent = `Manage: ${dev.friendly_name || dev.hostname || pdid}`;
    this.modalBody.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 16px;">
        <div>
          <label style="font-size: 12px; color: var(--text-secondary); text-transform: uppercase;">Tag Assignment</label>
          <select id="modal-tag-select" style="width: 100%; padding: 10px; margin-top: 6px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
            ${this.tags.map((t) => `<option value="${t.id}">${t.name}</option>`).join('')}
          </select>
        </div>
      </div>
    `;

    this.modalFooter.innerHTML = `<button class="btn btn-primary" id="modal-save-dev">Save Changes</button>`;

    document.getElementById('modal-save-dev').onclick = async () => {
      const tagId = document.getElementById('modal-tag-select').value;
      try {
        await API.assignDeviceTag(pdid, tagId);
        this.showToast('Device rules updated', 'success');
        this.hideModal();
        await this.loadInitialData();
      } catch (err) {
        this.showToast('Failed to update device', 'danger');
      }
    };

    this.showModal();
  }

  openAddScheduleModal() {
    this.modalTitle.textContent = 'Add Schedule';
    this.modalBody.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 12px;">
        <input type="text" id="sched-name" placeholder="Schedule Name (e.g. Bedtime)" style="padding: 10px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
        <input type="text" id="sched-tz" value="UTC" placeholder="Timezone (e.g. UTC)" style="padding: 10px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary);">
      </div>
    `;

    this.modalFooter.innerHTML = `<button class="btn btn-primary" id="save-sched-btn">Create</button>`;

    document.getElementById('save-sched-btn').onclick = async () => {
      const name = document.getElementById('sched-name').value;
      const tz = document.getElementById('sched-tz').value;
      if (!name) return;

      try {
        const created = await API.createSchedule({ name, timezone: tz, rules: [] });
        this.schedules.push(created);
        this.hideModal();
        this.renderSchedulesView();
        this.showToast('Schedule created', 'success');
      } catch (err) {
        this.showToast('Failed to create schedule', 'danger');
      }
    };

    this.showModal();
  }

  showModal() {
    this.modalRoot.classList.remove('hidden');
  }

  hideModal() {
    this.modalRoot.classList.add('hidden');
  }

  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    this.toastRoot.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 3000);
  }
}

// Instantiate SPA on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  window.app = new LiasDashboard();
});
