// LIAS Dashboard SPA Controller
//
// File:    apps/lias/web/src/main.js
// Version: 4.0 (Added Extend Access UI, Minute Picker, Effective Status polling)
import { API } from './api.js';
import { projectSchedule, detectConflicts, expandDayRange } from './scheduleConflict.js';

class App {
  constructor() {
    this.currentView = 'dashboard';
    this.devices = [];
    this.tags = [];
    this.policies = [];
    this.schedules = [];
    this.searchQuery = '';
    this.wizardState = {};
    this.timezones = this.generateIANATimezones();
    this.statusReloadTimer = null;

    this.initRouter();
    this.initSSE();
    this.loadData();

    if (!localStorage.getItem('lias_onboarded')) {
      this.openOnboardingWizard();
    }

    setInterval(() => {
      if (this.currentView === 'dashboard') {
        this.renderCurrentView();
      }
    }, 60000);
  }

  openOnboardingWizard() {
    this.openModal('Welcome to LIAS', `
      <div style="text-align: center; padding: 10px;">
        <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
        <h3 style="font-size: 20px; font-weight: 700; margin-bottom: 12px;">Secure Your Network in 3 Steps</h3>
        <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 24px;">LIAS protects your family's internet access. Let's get started!</p>
        <div style="text-align: left; background: var(--bg-tertiary); padding: 16px; border-radius: 12px; margin-bottom: 16px;">
          <p style="font-weight: 600; margin-bottom: 4px;">1. Tag Your Router</p>
          <p style="font-size: 13px; color: var(--text-secondary);">Assign the "Infrastructure" tag to your router/gateway to prevent accidental lockouts.</p>
        </div>
        <div style="text-align: left; background: var(--bg-tertiary); padding: 16px; border-radius: 12px; margin-bottom: 16px;">
          <p style="font-weight: 600; margin-bottom: 4px;">2. Create a Schedule</p>
          <p style="font-size: 13px; color: var(--text-secondary);">Set up a "Bedtime" schedule (e.g., Block 22:00 to 06:00).</p>
        </div>
        <div style="text-align: left; background: var(--bg-tertiary); padding: 16px; border-radius: 12px; margin-bottom: 24px;">
          <p style="font-weight: 600; margin-bottom: 4px;">3. Apply to Devices</p>
          <p style="font-size: 13px; color: var(--text-secondary);">Tag your kids' devices as "Kids" and attach the schedule policy.</p>
        </div>
      </div>
    `, `<button class="btn btn-primary" id="onboarding-done" style="width: 100%;">Got It!</button>`);
    
    document.getElementById('onboarding-done').addEventListener('click', () => {
      localStorage.setItem('lias_onboarded', 'true');
      this.closeModal();
    });
  }

  generateIANATimezones() {
    try {
      const timezones = Intl.supportedValuesOf('timeZone');
      return timezones.map(tz => {
        const parts = tz.split('/');
        const region = parts[0].replace(/_/g, ' ');
        const city = parts.slice(1).join(' / ').replace(/_/g, ' ');
        return { label: `(${region}) ${city}`, value: tz };
      }).sort((a, b) => a.label.localeCompare(b.label));
    } catch (e) {
      return [
        { label: '(UTC-08:00) Pacific Time (PT)', value: 'America/Los_Angeles' },
        { label: '(UTC-05:00) Eastern Time (ET)', value: 'America/New_York' },
        { label: '(UTC+00:00) Coordinated Universal Time (UTC)', value: 'UTC' },
        { label: '(UTC+05:30) India Standard Time (IST)', value: 'Asia/Kolkata' }
      ];
    }
  }

  initRouter() {
    document.querySelectorAll('.nav-item, .mob-nav-item').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.navigateTo(e.currentTarget.dataset.view);
      });
    });

    const searchInput = document.getElementById('global-search');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.renderCurrentView();
      });
    }

    const modalCloseX = document.getElementById('modal-close-x');
    if (modalCloseX) {
      modalCloseX.addEventListener('click', () => this.closeModal());
    }
  }

  initSSE() {
    API.subscribeEvents((event) => {
      this.handleRealtimeEvent(event);
    });
  }

  handleRealtimeEvent(event) {
    const pdid = (event.payload && event.payload.pdid) || event.device_id || 'device';
    
    if (event.type === 'device.added') {
      this.showToast(`✨ New Device Discovered: ${pdid}`);
    } else if (event.type === 'device.online') {
      this.showToast(`🟢 Device Online: ${pdid}`);
    } else if (event.type === 'device.offline') {
      this.showToast(`🔴 Device Offline: ${pdid}`);
    } else if (event.type === 'device.reidentified') {
      const payload = event.payload || {};
      this.showToast(`🔄 Device identified: ${payload.new_pdid || 'device'}`);
    } else if (event.type === 'security.alert') {
      this.showToast(`🚨 Security Alert: ${event.payload.details || 'Unknown alert'}`, 'danger');
    }

    // V4.0: Debounce rapid status updates to prevent flooding the API
    if (event.type === 'effective.status_changed' || event.type.startsWith('device.') || event.type === 'policy.updated') {
      clearTimeout(this.statusReloadTimer);
      this.statusReloadTimer = setTimeout(() => this.loadData(), 250);
    } else {
      this.loadData();
    }
  }

  async loadData() {
    try {
      const [devsResp, tags, policies, schedules] = await Promise.all([
        API.getDevices(),
        API.getTags(),
        API.getPolicies(),
        API.getSchedules()
      ]);
      this.devices = devsResp.devices || [];
      this.tags = tags || [];
      this.policies = policies || [];
      this.schedules = schedules || [];

      // V4.0: Fetch effective statuses in parallel to drive Extend/Pause UI availability
      const [devStatuses, tagStatuses] = await Promise.all([
        Promise.all(this.devices.map(d => API.getDeviceEffectiveStatus(d.pdid).catch(() => null))),
        Promise.all(this.tags.map(t => API.getTagEffectiveStatus(t.id).catch(() => null)))
      ]);

      this.devices.forEach((d, i) => {
        d.effective_status = devStatuses[i];
      });
      this.tags.forEach((t, i) => {
        t.effective_status = tagStatuses[i];
      });

      this.renderCurrentView();
    } catch (err) {
      this.showToast(`Error loading data: ${err.message}`, 'danger');
    }
  }

  navigateTo(view) {
    this.currentView = view;
    document.querySelectorAll('.nav-item, .mob-nav-item').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === view);
    });

    const titleMap = {
      dashboard: 'Dashboard', devices: 'Tag Groups', schedules: 'Schedules',
      policies: 'Policies', analytics: 'Analytics', settings: 'Settings'
    };
    document.getElementById('view-title').textContent = titleMap[view] || 'Dashboard';
    this.renderCurrentView();
  }

  renderCurrentView() {
    const container = document.getElementById('view-container');
    if (!container) return;

    switch (this.currentView) {
      case 'dashboard': this.renderDashboardView(container); break;
      case 'devices': this.renderTagGroupsView(container); break;
      case 'schedules': this.renderSchedulesView(container); break;
      case 'policies': this.renderPoliciesView(container); break;
      case 'analytics': this.renderAnalyticsView(container); break;
      case 'settings': this.renderSettingsView(container); break;
      default: container.innerHTML = '<p>View not found</p>';
    }
  }

  // Dashboard View & Active Enforcements omitted for brevity (unchanged from V3.9) ...

  renderTagGroupsView(container) {
    const grouped = {};
    this.tags.forEach(t => { grouped[t.id] = []; });

    this.devices.forEach(d => {
      if (d.tags && d.tags.length > 0) {
        d.tags.forEach(tagId => {
          if (!grouped[tagId]) grouped[tagId] = [];
          grouped[tagId].push(d);
        });
      } else {
        if (!grouped['generic']) grouped['generic'] = [];
        grouped['generic'].push(d);
      }
    });

    let html = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <h3>Tag Groups (${this.tags.length})</h3>
        <button class="btn btn-primary" id="btn-add-tag">+ New Tag Group</button>
      </div>
    `;

    this.tags.forEach(t => {
      const devs = (grouped[t.id] || []).filter(d => {
        if (!this.searchQuery) return true;
        return (d.hostname || '').toLowerCase().includes(this.searchQuery) ||
               (d.current_mac || '').toLowerCase().includes(this.searchQuery) ||
               (d.current_ip || '').toLowerCase().includes(this.searchQuery);
      });

      // V4.0: Tag-level Extend Access button
      const tagExtended = t.effective_status?.active_extension?.reason_tag === 'extend_access';
      let tagActionHtml = '';
      if (tagExtended) {
          tagActionHtml = `<button class="btn btn-secondary btn-cancel-extend-tag" data-tag-id="${t.id}" data-tag-name="${t.name}" style="padding: 6px 10px; font-size: 12px;">✕ Cancel Extension (${t.effective_status.active_extension.minutes_left}m)</button>`;
      } else if (t.effective_status?.action === 'block' && t.effective_status?.extend_available) {
          tagActionHtml = `<button class="btn btn-success btn-extend-tag" data-tag-id="${t.id}" data-tag-name="${t.name}" style="padding: 6px 10px; font-size: 12px;">⏱ Extend All</button>`;
      }

      html += `
        <div class="group-card" data-tag-id="${t.id}">
          <div class="group-header">
            <div class="group-header-title">
              <span class="group-tag-badge" style="background:${t.color}">${t.name}</span>
              ${t.id === 'infrastructure' ? '<span style="font-size:12px; font-weight:700; color:var(--text-secondary);">🔒 IMMUNE</span>' : ''}
              <span class="group-count">(${devs.length} devices)</span>
            </div>
            <div style="display:flex; align-items:center; gap:12px;">
              ${tagActionHtml}
              <svg class="group-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
            </div>
          </div>
          <div class="group-content">
            <div class="device-grid">
              ${devs.map(d => this.renderDeviceCard(d)).join('')}
            </div>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;

    document.querySelectorAll('.group-header').forEach(hdr => {
      hdr.addEventListener('click', (e) => {
        if (e.target.closest('button')) return; // Don't collapse if clicking the action button
        e.currentTarget.closest('.group-card').classList.toggle('collapsed');
      });
    });

    const addBtn = document.getElementById('btn-add-tag');
    if (addBtn) addBtn.addEventListener('click', () => this.openTagModal());

    this.bindDeviceTagDropdowns();
    this.bindTagExtendButtons();
  }

  bindTagExtendButtons() {
    document.querySelectorAll('.btn-extend-tag').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const tagId = e.currentTarget.dataset.tagId;
        const tagName = e.currentTarget.dataset.tagName;
        this.openMinutePickerModal(`Extend Access: ${tagName}`, async (mins) => {
          try {
            await API.extendTagAccess(tagId, mins);
            this.showToast(`Access extended for ${tagName} (${mins}m)`);
            this.loadData();
          } catch (err) {
            this.showToast(`Failed to extend: ${err.message}`, 'danger');
          }
        });
      });
    });

    document.querySelectorAll('.btn-cancel-extend-tag').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const tagId = e.currentTarget.dataset.tagId;
        const tagName = e.currentTarget.dataset.tagName;
        this.openConfirmModal('Cancel Extension', `Revoke extended access for ${tagName}?`, 'Cancel Extension', async () => {
          try {
            await API.cancelTagExtension(tagId);
            this.showToast(`Extension cancelled for ${tagName}`);
            this.loadData();
          } catch (err) {
            this.showToast(`Failed to cancel: ${err.message}`, 'danger');
          }
        });
      });
    });
  }

  renderDeviceCard(d) {
    const dispName = d.friendly_name || d.hostname || `${d.vendor || ''} ${d.model || ''}`.trim() || d.current_mac || d.pdid;
    const tags = (d.tags && d.tags.length > 0) ? d.tags : ['generic'];
    const isInfra = tags.includes('infrastructure');
    
    const isPaused = this.policies.some(p => p.id === `pol_pause_${d.pdid}`);
    const isExtended = d.effective_status?.active_extension?.reason_tag === 'extend_access';

    const tagCheckboxes = this.tags.map(t => `
      <label style="display:flex; align-items:center; gap:6px; font-size:12px; padding:4px 0;">
        <input type="checkbox" class="device-tag-checkbox" value="${t.id}" ${tags.includes(t.id) ? 'checked' : ''}>
        ${t.name}
      </label>
    `).join('');

    // V4.0: Action button state logic driven by effective_status
    let actionBtnHtml = '';
    if (!isInfra) {
      if (isExtended) {
          actionBtnHtml = `<button class="btn btn-secondary btn-cancel-extend-device" data-pdid="${d.pdid}" data-name="${dispName}" style="flex:1; padding: 6px 10px; font-size: 12px;">✕ Cancel (${d.effective_status.active_extension.minutes_left}m)</button>`;
      } else if (isPaused) {
          actionBtnHtml = `<button class="btn btn-success btn-unpause-device" data-pdid="${d.pdid}" data-name="${dispName}" style="flex:1; padding: 6px 10px; font-size: 12px;">▶ Unpause</button>`;
      } else {
          if (d.effective_status?.action === 'block' && d.effective_status?.extend_available) {
              actionBtnHtml += `<button class="btn btn-success btn-extend-device" data-pdid="${d.pdid}" data-name="${dispName}" style="flex:1; padding: 6px 10px; font-size: 12px; margin-right:4px;">⏱ Extend</button>`;
          }
          actionBtnHtml += `<button class="btn btn-danger btn-pause-device" data-pdid="${d.pdid}" data-name="${dispName}" style="flex:1; padding: 6px 10px; font-size: 12px;">⏸ Pause</button>`;
      }
    }

    return `
      <div class="device-item">
        <div>
          <div class="device-item-header">
            <div class="device-name">${dispName}</div>
            <div style="display:flex; align-items:center; gap:6px;">
              <span class="status-indicator ${d.online ? 'online' : 'offline'}"></span>
              <span style="font-size:11px; font-weight:700; color:${d.online ? 'var(--success)' : 'var(--text-secondary)'}; text-transform:uppercase;">${d.online ? 'Online' : 'Offline'}</span>
            </div>
          </div>
          <div class="device-meta">
            <div>MAC: ${d.current_mac || 'N/A'}</div>
            <div>IP: ${d.current_ip || 'N/A'}</div>
            <div>Type: ${d.device_type || 'Unclassified'}</div>
          </div>
        </div>
        <div style="margin-top:12px; display:flex; flex-direction:column; gap:8px;">
          <details style="background: var(--bg-tertiary); padding: 8px 12px; border-radius: 8px; cursor: pointer;">
            <summary style="font-size: 12px; font-weight: 600;">Assign Tags (${tags.length})</summary>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:4px; margin-top:8px;">
              ${tagCheckboxes}
            </div>
          </details>
          <div style="display:flex; gap: 8px; flex-wrap: wrap;">
            ${actionBtnHtml}
            <button class="btn btn-secondary btn-rename-device" data-pdid="${d.pdid}" data-name="${dispName}" style="padding: 6px 10px; font-size: 12px;">✏️</button>
            <button class="btn btn-secondary btn-details-device" data-pdid="${d.pdid}" style="padding: 6px 10px; font-size: 12px;">📋</button>
          </div>
        </div>
      </div>
    `;
  }

  bindDeviceTagDropdowns() {
    document.querySelectorAll('.device-tag-checkbox').forEach(chk => {
      chk.addEventListener('change', async (e) => {
        const deviceItem = e.target.closest('.device-item');
        const pdid = deviceItem.querySelector('.btn-details-device').dataset.pdid;
        const selectedTags = Array.from(deviceItem.querySelectorAll('.device-tag-checkbox:checked')).map(c => c.value);
        if (selectedTags.length === 0) selectedTags.push('generic');
        
        try {
          await API.assignDeviceTag(pdid, selectedTags);
          this.showToast(`Tags updated successfully`);
          this.loadData();
        } catch (err) {
          this.showToast(`Failed to assign tags: ${err.message}`, 'danger');
        }
      });
    });

    document.querySelectorAll('.btn-pause-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.dataset.pdid;
        const name = e.currentTarget.dataset.name;
        this.openConfirmModal('Pause Internet', `Pause internet for ${name} for 1 hour?`, 'Pause', async () => {
          try {
            await API.pauseDeviceInternet(pdid);
            this.showToast(`Internet paused for ${name}`);
            this.loadData();
          } catch (err) {
            this.showToast(`Failed to pause: ${err.message}`, 'danger');
          }
        });
      });
    });

    document.querySelectorAll('.btn-unpause-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.dataset.pdid;
        const name = e.currentTarget.dataset.name;
        this.openConfirmModal('Resume Internet', `Resume internet for ${name}?`, 'Unpause', async () => {
          try {
            await API.unpauseDeviceInternet(pdid);
            this.showToast(`Internet resumed for ${name}`);
            this.loadData();
          } catch (err) {
            this.showToast(`Failed to unpause: ${err.message}`, 'danger');
          }
        });
      });
    });

    // V4.0: Bind Extend Access and Cancel Extension
    document.querySelectorAll('.btn-extend-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.dataset.pdid;
        const name = e.currentTarget.dataset.name;
        this.openMinutePickerModal(`Extend Access: ${name}`, async (mins) => {
          try {
            await API.extendDeviceAccess(pdid, mins);
            this.showToast(`Access extended for ${name} (${mins}m)`);
            this.loadData();
          } catch (err) {
            this.showToast(`Failed to extend: ${err.message}`, 'danger');
          }
        });
      });
    });

    document.querySelectorAll('.btn-cancel-extend-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.dataset.pdid;
        const name = e.currentTarget.dataset.name;
        this.openConfirmModal('Cancel Extension', `Revoke extended access for ${name}?`, 'Cancel Extension', async () => {
          try {
            await API.cancelDeviceExtension(pdid);
            this.showToast(`Extension cancelled for ${name}`);
            this.loadData();
          } catch (err) {
            this.showToast(`Failed to cancel: ${err.message}`, 'danger');
          }
        });
      });
    });

    document.querySelectorAll('.btn-rename-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.dataset.pdid;
        const currentName = e.currentTarget.dataset.name;
        this.openPromptModal('Rename Device', `Enter a new name for ${currentName}:`, currentName, 'Save', async (newName) => {
          if (newName && newName !== currentName) {
            try {
              await API.renameDevice(pdid, newName);
              this.showToast(`Device renamed to ${newName}`);
              this.loadData();
            } catch (err) {
              this.showToast(`Failed to rename: ${err.message}`, 'danger');
            }
          }
        });
      });
    });

    document.querySelectorAll('.btn-details-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.openDeviceModal(e.currentTarget.dataset.pdid);
      });
    });
  }

  // V4.0: HIG-flavored Minute Picker Modal
  openMinutePickerModal(title, onConfirm) {
    this.openModal(title, `
      <div style="text-align: center; padding: 10px 0;">
        <div class="minute-chip-group">
          <div class="minute-chip" data-mins="15">15m</div>
          <div class="minute-chip" data-mins="30">30m</div>
          <div class="minute-chip" data-mins="60">60m</div>
          <div class="minute-chip" data-mins="120">120m</div>
        </div>
        <div class="minute-slider-container">
          <input type="range" id="minute-slider" min="1" max="120" step="1" value="15" class="minute-slider">
          <div class="minute-readout"><span id="minute-val">15</span> minutes</div>
        </div>
      </div>
    `, `
      <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
      <button class="btn btn-success" id="modal-confirm">Allow Access</button>
    `);

    let selectedMins = 15;
    const slider = document.getElementById('minute-slider');
    const valSpan = document.getElementById('minute-val');
    
    slider.addEventListener('input', (e) => {
      selectedMins = parseInt(e.target.value, 10);
      valSpan.textContent = selectedMins;
      document.querySelectorAll('.minute-chip').forEach(c => c.classList.remove('selected'));
    });

    document.querySelectorAll('.minute-chip').forEach(chip => {
      chip.addEventListener('click', (e) => {
        selectedMins = parseInt(e.target.dataset.mins, 10);
        slider.value = selectedMins;
        valSpan.textContent = selectedMins;
        document.querySelectorAll('.minute-chip').forEach(c => c.classList.remove('selected'));
        e.target.classList.add('selected');
      });
    });

    document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
    document.getElementById('modal-confirm').addEventListener('click', () => {
      this.closeModal();
      onConfirm(selectedMins);
    });
  }

  // ... (openDeviceModal, renderPoliciesView, renderSchedulesView, openScheduleModal, etc. omitted for brevity - unchanged) ...

  openConfirmModal(title, messageHtml, confirmText, onConfirm) {
    this.openModal(title, `
      <div class="modal-warning-icon">⚠️</div>
      <p style="text-align: center; font-size: 15px; margin-bottom: 8px;">${messageHtml}</p>
    `, `
      <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
      <button class="btn btn-danger" id="modal-confirm">${confirmText}</button>
    `);
    document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
    document.getElementById('modal-confirm').addEventListener('click', () => {
      this.closeModal();
      onConfirm();
    });
  }

  openPromptModal(title, messageHtml, defaultValue, confirmText, onConfirm) {
    this.openModal(title, `
      <p style="text-align: center; font-size: 15px; margin-bottom: 12px;">${messageHtml}</p>
      <input type="text" id="modal-prompt-input" value="${defaultValue}" style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid var(--separator); background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px;">
    `, `
      <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
      <button class="btn btn-primary" id="modal-confirm">${confirmText}</button>
    `);
    document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
    document.getElementById('modal-confirm').addEventListener('click', () => {
      const val = document.getElementById('modal-prompt-input').value;
      this.closeModal();
      onConfirm(val);
    });
  }

  openModal(title, bodyHtml, footerHtml = '') {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = bodyHtml;
    document.getElementById('modal-footer').innerHTML = footerHtml;
    document.getElementById('modal-root').classList.remove('hidden');
  }

  closeModal() {
    document.getElementById('modal-root').classList.add('hidden');
  }

  showToast(msg, type = 'info') {
    const root = document.getElementById('toast-root');
    if (!root) return;
    const toast = document.createElement('div');
    toast.className = 'toast';
    if (type === 'danger') toast.style.backgroundColor = 'var(--danger)';
    toast.innerHTML = msg;
    root.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.app = new App();
});
