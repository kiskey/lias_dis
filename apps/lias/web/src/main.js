// LIAS Dashboard SPA Controller
//
// File:    apps/lias/web/src/main.js
// Version: 3.3 (Added Explicit Online/Offline Text)
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

    // UI-FN-11 Fix: Generate full IANA timezone list dynamically
    this.timezones = this.generateIANATimezones();

    this.initRouter();
    this.initSSE();
    this.loadData();

    // UI-UX-05 Fix: First-run onboarding wizard
    if (!localStorage.getItem('lias_onboarded')) {
      this.openOnboardingWizard();
    }

    // Auto-refresh dashboard view every minute to update live enforcements dynamically
    setInterval(() => {
      if (this.currentView === 'dashboard') {
        this.renderCurrentView();
      }
    }, 60000);
  }

  // UI-UX-05 Fix: Onboarding Wizard
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

  // UI-FN-11 Fix: Generates a comprehensive list of IANA timezones
  generateIANATimezones() {
    try {
      const timezones = Intl.supportedValuesOf('timeZone');
      return timezones.map(tz => {
        const parts = tz.split('/');
        const region = parts[0].replace(/_/g, ' ');
        const city = parts.slice(1).join(' / ').replace(/_/g, ' ');
        return {
          label: `(${region}) ${city}`,
          value: tz
        };
      }).sort((a, b) => a.label.localeCompare(b.label));
    } catch (e) {
      console.warn("Intl.supportedValuesOf not supported, falling back to hardcoded list");
      return [
        { label: '(UTC-08:00) Pacific Time (PT)', value: 'America/Los_Angeles' },
        { label: '(UTC-07:00) Mountain Time (MT)', value: 'America/Denver' },
        { label: '(UTC-06:00) Central Time (CT)', value: 'America/Chicago' },
        { label: '(UTC-05:00) Eastern Time (ET)', value: 'America/New_York' },
        { label: '(UTC+00:00) Coordinated Universal Time (UTC)', value: 'UTC' },
        { label: '(UTC+05:30) India Standard Time (IST)', value: 'Asia/Kolkata' }
      ];
    }
  }

  initRouter() {
    document.querySelectorAll('.nav-item, .mob-nav-item').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const view = e.currentTarget.dataset.view;
        this.navigateTo(view);
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
    
    const confirmedBy = event.payload?.confirmed_by || [];
    const verifiedBadge = confirmedBy.length > 0
        ? ` <span class="verified-badge">✓ ${confirmedBy.length} sources</span>`
        : '';

    if (event.type === 'device.added') {
      this.showToast(`✨ New Device Discovered: ${pdid}${verifiedBadge}`);
    } else if (event.type === 'device.online') {
      this.showToast(`🟢 Device Online: ${pdid}${verifiedBadge}`);
    } else if (event.type === 'device.offline') {
      this.showToast(`🔴 Device Offline: ${pdid}`);
    } else if (event.type === 'device.reidentified') {
      const payload = event.payload || {};
      this.showToast(`🔄 Device identified: ${payload.new_pdid || 'device'} (promoted from ${payload.reason || 'tentative'})`);
    } else if (event.type === 'security.alert') {
      this.showToast(`🚨 Security Alert: ${event.payload.details || 'Unknown alert'}`, 'danger');
    }
    this.loadData();
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
      dashboard: 'Dashboard',
      devices: 'Tag Groups',
      schedules: 'Schedules',
      policies: 'Policies',
      analytics: 'Analytics', // UI-FN-08
      settings: 'Settings'
    };
    document.getElementById('view-title').textContent = titleMap[view] || 'Dashboard';

    this.renderCurrentView();
  }

  renderCurrentView() {
    const container = document.getElementById('view-container');
    if (!container) return;

    switch (this.currentView) {
      case 'dashboard':
        this.renderDashboardView(container);
        break;
      case 'devices':
        this.renderTagGroupsView(container);
        break;
      case 'schedules':
        this.renderSchedulesView(container);
        break;
      case 'policies':
        this.renderPoliciesView(container);
        break;
      case 'analytics': // UI-FN-08
        this.renderAnalyticsView(container);
        break;
      case 'settings':
        this.renderSettingsView(container);
        break;
      default:
        container.innerHTML = '<p>View not found</p>';
    }
  }

  // Dashboard Live Enforcements Helper Methods
  getActiveScheduleAction(schedule) {
    if (!schedule || !schedule.rules || schedule.rules.length === 0) return null;
    try {
      const tz = schedule.timezone || 'UTC';
      const fmt = new Intl.DateTimeFormat('en-US', {
        timeZone: tz,
        weekday: 'Short',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      });
      const parts = fmt.formatToParts(new Date());
      let weekday = '', hour = 0, minute = 0;
      for (const p of parts) {
        if (p.type === 'weekday') weekday = p.value.toLowerCase();
        else if (p.type === 'hour') hour = parseInt(p.value, 10) % 24;
        else if (p.type === 'minute') minute = parseInt(p.value, 10);
      }
      const dayMap = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
      if (!(weekday in dayMap)) return null;
      
      const currentMin = dayMap[weekday] * 1440 + hour * 60 + minute;
      const segments = projectSchedule(schedule);
      
      for (const seg of segments) {
        if (currentMin >= seg.start && currentMin < seg.end) {
          return seg.action;
        }
      }
    } catch (e) {
      console.error("Failed to evaluate schedule active state", e);
    }
    return null;
  }

  isTimezoneInDST(tz) {
    try {
      const now = new Date();
      const fmtLong = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'short' });
      const parts = fmtLong.formatToParts(now);
      const tzName = parts.find(p => p.type === 'timeZoneName')?.value || '';
      return tzName.includes('DT') || tzName.includes('DST');
    } catch {
      return false;
    }
  }

  renderActiveEnforcementsHtml() {
    const activeItems = [];
    
    this.policies.forEach(p => {
      if (p.action === 'schedule' && p.type !== 'global') {
        const targetTag = this.tags.find(t => t.id === p.target_id);
        const targetName = p.type === 'tag' 
            ? (targetTag?.name || p.target_id) 
            : (this.devices.find(d => d.pdid === p.target_id)?.hostname || p.target_id);
        const targetColor = p.type === 'tag' 
            ? (targetTag?.color || '#8e8e93') 
            : '#8e8e93';

        const scheds = this.resolvePolicySchedules(p);
        for (const s of scheds) {
          const activeAction = this.getActiveScheduleAction(s);
          if (activeAction) {
            activeItems.push({
              policyName: p.name,
              targetName: targetName,
              targetColor: targetColor,
              scheduleName: s.name,
              action: activeAction,
              timezone: s.timezone,
              isDST: this.isTimezoneInDST(s.timezone)
            });
            break; // One active schedule per policy is enough to show
          }
        }
      }
    });

    if (activeItems.length === 0) {
      return `
        <div class="card" style="margin-bottom: 24px; background: var(--bg-secondary); border: 1px dashed var(--separator);">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div class="active-empty-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            </div>
            <div>
              <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 2px;">No Active Schedules</h3>
              <p style="font-size: 13px; color: var(--text-secondary);">All devices are currently operating under their default policies.</p>
            </div>
          </div>
        </div>
      `;
    }

    return `
      <div class="active-enforcements-container">
        ${activeItems.map(item => `
          <div class="live-activity-card ${item.action === 'block' ? 'is-blocking' : 'is-allowing'}">
            <div class="live-activity-icon">
              ${item.action === 'block' 
                ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>'
                : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>'
              }
            </div>
            <div class="live-activity-content">
              <div class="live-activity-status">${item.action === 'block' ? 'Internet Blocked' : 'Internet Allowed'}</div>
              <div class="live-activity-details">
                <span class="group-dot" style="background-color: ${item.targetColor};"></span>
                <strong>${item.targetName}</strong> 
                <span style="color: var(--text-secondary); margin-left: 4px;">${item.scheduleName}</span>
              </div>
            </div>
            ${item.isDST ? '<div class="dst-pill">DST Active</div>' : ''}
          </div>
        `).join('')}
      </div>
    `;
  }

  renderDashboardView(container) {
    const total = this.devices.length;
    const online = this.devices.filter(d => d.online).length;
    const offline = total - online;

    container.innerHTML = `
      <div style="margin-bottom: 20px;">
        <h3 style="font-size: 20px; font-weight: 800; letter-spacing: -0.5px;">Active Enforcements</h3>
        <p style="font-size: 13px; color: var(--text-secondary); margin-top: 2px;">Live status of scheduled policies currently in effect.</p>
      </div>
      ${this.renderActiveEnforcementsHtml()}

      <div class="global-switch-banner">
        <div class="global-switch-top">
          <div>
            <h3>Global Access Switch</h3>
            <p style="font-size:13px; color:var(--text-secondary);">Master internet access control across all managed devices</p>
          </div>
          <div>${this.renderGlobalSwitchControls()}</div>
        </div>
        <div id="global-switch-drawer-container">
          ${this.renderGlobalSwitchDrawerHtml()}
        </div>
      </div>

      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:16px; margin-bottom:24px;">
        <div class="card">
          <div style="font-size:13px; color:var(--text-secondary); font-weight:600;">TOTAL DEVICES</div>
          <div style="font-size:28px; font-weight:800; margin-top:4px;">${total}</div>
        </div>
        <div class="card">
          <div style="font-size:13px; color:var(--success); font-weight:600;">ONLINE</div>
          <div style="font-size:28px; font-weight:800; margin-top:4px; color:var(--success);">${online}</div>
        </div>
        <div class="card">
          <div style="font-size:13px; color:var(--text-secondary); font-weight:600;">OFFLINE</div>
          <div style="font-size:28px; font-weight:800; margin-top:4px;">${offline}</div>
        </div>
      </div>

      <h3>Recent Activity & Inventory</h3>
      <div class="device-grid" style="margin-top:16px;">
        ${this.devices.slice(0, 12).map(d => this.renderDeviceCard(d)).join('')}
      </div>
    `;

    this.bindGlobalSwitchEvents();
  }

  renderGlobalSwitchControls() {
    const globalPol = this.policies.find(p => p.id === 'global_default') || { action: 'schedule' };
    const act = globalPol.action;

    return `
      <div class="segmented-control">
        <button class="segmented-btn ${act === 'allow' ? 'active' : ''}" data-action="allow">Allow All</button>
        <button class="segmented-btn ${act === 'schedule' ? 'active' : ''}" data-action="schedule">Schedule</button>
        <button class="segmented-btn danger ${act === 'block' ? 'active' : ''}" data-action="block">Block All</button>
      </div>
    `;
  }

  renderGlobalSwitchDrawerHtml() {
    const globalPol = this.policies.find(p => p.id === 'global_default');
    if (!globalPol || globalPol.action !== 'schedule') return '';

    const selectedScheds = this.resolvePolicySchedules(globalPol);

    return `
      <div class="global-switch-drawer">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong style="font-size:13px;">Global Schedule Bundle (${selectedScheds.length} attached)</strong>
          <button class="btn btn-secondary" id="btn-edit-global-bundle" style="padding:4px 10px; font-size:12px;">Manage Schedules</button>
        </div>
        ${this.renderWeeklyTimeline(selectedScheds)}
      </div>
    `;
  }

  bindGlobalSwitchEvents() {
    document.querySelectorAll('.global-switch-banner .segmented-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const action = e.currentTarget.dataset.action;
        let globalPol = this.policies.find(p => p.id === 'global_default') || {
          id: 'global_default',
          name: 'Global Access Switch',
          type: 'global',
          target_id: '',
          priority: 0
        };

        globalPol.action = action;
        try {
          await API.savePolicy(globalPol);
          this.showToast(`Global Switch set to: ${action.toUpperCase()}`);
          this.loadData();
        } catch (err) {
          this.showToast(`Failed to update global switch: ${err.message}`, 'danger');
        }
      });
    });

    const manageBtn = document.getElementById('btn-edit-global-bundle');
    if (manageBtn) {
      manageBtn.addEventListener('click', () => {
        let globalPol = this.policies.find(p => p.id === 'global_default') || {
          id: 'global_default',
          name: 'Global Access Switch',
          type: 'global',
          target_id: '',
          action: 'schedule',
          priority: 0
        };
        this.openPolicyWizard(globalPol);
      });
    }
  }

  renderTagGroupsView(container) {
    const grouped = {};
    this.tags.forEach(t => { grouped[t.id] = []; });

    this.devices.forEach(d => {
      // LIAS-TAG-01 Fix: Handle multiple tags per device
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

      html += `
        <div class="group-card" data-tag-id="${t.id}">
          <div class="group-header">
            <div class="group-header-title">
              <span class="group-tag-badge" style="background:${t.color}">${t.name}</span>
              ${t.id === 'infrastructure' ? '<span style="font-size:12px; font-weight:700; color:var(--text-secondary);">🔒 IMMUNE</span>' : ''}
              <span class="group-count">(${devs.length} devices)</span>
            </div>
            <svg class="group-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
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
        const card = e.currentTarget.closest('.group-card');
        card.classList.toggle('collapsed');
      });
    });

    const addBtn = document.getElementById('btn-add-tag');
    if (addBtn) {
      addBtn.addEventListener('click', () => this.openTagModal());
    }

    this.bindDeviceTagDropdowns();
  }

  renderDeviceCard(d) {
    const dispName = d.friendly_name || d.hostname || `${d.vendor || ''} ${d.model || ''}`.trim() || d.current_mac || d.pdid;
    const tags = (d.tags && d.tags.length > 0) ? d.tags : ['generic'];
    const isInfra = tags.includes('infrastructure');
    
    // Fix 1: Check if device is currently paused to render Unpause button
    const isPaused = this.policies.some(p => p.id === `pol_pause_${d.pdid}`);

    // LIAS-TAG-01 Fix: Render multi-select for tags
    const tagCheckboxes = this.tags.map(t => `
      <label style="display:flex; align-items:center; gap:6px; font-size:12px; padding:4px 0;">
        <input type="checkbox" class="device-tag-checkbox" value="${t.id}" ${tags.includes(t.id) ? 'checked' : ''}>
        ${t.name}
      </label>
    `).join('');

    // FIX: Hide Pause button for Infrastructure devices. Show Unpause if paused.
    let actionBtnHtml = '';
    if (!isInfra) {
      if (isPaused) {
        actionBtnHtml = `<button class="btn btn-success btn-unpause-device" data-pdid="${d.pdid}" data-name="${dispName}" style="flex:1; padding: 6px 10px; font-size: 12px;">▶ Unpause</button>`;
      } else {
        actionBtnHtml = `<button class="btn btn-danger btn-pause-device" data-pdid="${d.pdid}" data-name="${dispName}" style="flex:1; padding: 6px 10px; font-size: 12px;">⏸ Pause</button>`;
      }
    }

    // V3.3 FIX: Added explicit text label next to the status dot
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
          ${(d.services && d.services.length > 0) ? `
            <div class="service-pill-list">
              ${d.services.map(s => `<span class="service-pill">${s}</span>`).join('')}
            </div>
          ` : ''}
        </div>
        <div style="margin-top:12px; display:flex; flex-direction:column; gap:8px;">
          <details style="background: var(--bg-tertiary); padding: 8px 12px; border-radius: 8px; cursor: pointer;">
            <summary style="font-size: 12px; font-weight: 600;">Assign Tags (${tags.length})</summary>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:4px; margin-top:8px;">
              ${tagCheckboxes}
            </div>
          </details>
          <div style="display:flex; justify-content:space-between; align-items:center; gap: 8px;">
            ${actionBtnHtml}
            <button class="btn btn-secondary btn-rename-device" data-pdid="${d.pdid}" data-name="${dispName}" style="padding: 6px 10px; font-size: 12px;">✏️</button>
            <button class="btn btn-secondary btn-details-device" data-pdid="${d.pdid}" style="padding: 6px 10px; font-size: 12px;">📋</button>
          </div>
        </div>
      </div>
    `;
  }

  bindDeviceTagDropdowns() {
    // LIAS-TAG-01 Fix: Save tags on checkbox change
    document.querySelectorAll('.device-tag-checkbox').forEach(chk => {
      chk.addEventListener('change', async (e) => {
        const deviceItem = e.target.closest('.device-item');
        const pdid = deviceItem.querySelector('.btn-details-device').dataset.pdid;
        const selectedTags = Array.from(deviceItem.querySelectorAll('.device-tag-checkbox:checked')).map(c => c.value);
        
        // If no tags selected, default to generic
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

    // UI-FN-06: Bind Pause Internet (HIG Modal)
    document.querySelectorAll('.btn-pause-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.dataset.pdid;
        const name = e.currentTarget.dataset.name;
        this.openConfirmModal('Pause Internet', `Are you sure you want to pause the internet for ${name} for 1 hour?`, 'Pause', async () => {
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

    // Fix 1: Bind Unpause Internet (HIG Modal)
    document.querySelectorAll('.btn-unpause-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const pdid = e.currentTarget.dataset.pdid;
        const name = e.currentTarget.dataset.name;
        this.openConfirmModal('Resume Internet', `Are you sure you want to resume the internet for ${name}?`, 'Unpause', async () => {
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

    // UI-FN-12: Bind Rename (HIG Modal)
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

    // UI-FN-01: Bind Device Details Modal
    document.querySelectorAll('.btn-details-device').forEach(btn => {
      btn.addEventListener('click', (e) => {
        this.openDeviceModal(e.currentTarget.dataset.pdid);
      });
    });
  }

  // UI-FN-01 Fix: Device Details Modal with Activity History
  async openDeviceModal(pdid) {
    this.openModal('Device Details', `<div class="loader"><div class="spinner"></div></div>`, '');
    try {
      const [device, logs] = await Promise.all([API.getDevice(pdid), API.getDeviceLogs(pdid)]);
      
      const logHtml = logs && logs.length > 0 ? `
        <h4 style="margin-top:24px; font-size:12px; text-transform:uppercase; color:var(--text-secondary);">Activity History (Last 100 Events)</h4>
        <div style="max-height:200px; overflow-y:auto; margin-top:8px; border:1px solid var(--separator); border-radius:8px;">
          ${logs.map(l => `<div style="padding:8px 12px; border-bottom:1px solid var(--separator); font-size:12px; ${l.action === 'block' ? 'color:var(--danger);' : ''}"><strong>${new Date(l.timestamp).toLocaleString()}</strong> - ${l.action.toUpperCase()} ${l.bytes ? `(${l.bytes} bytes)` : ''}</div>`).join('')}
        </div>
      ` : '<p style="margin-top:24px; font-size:13px; color:var(--text-secondary);">No recent activity logged.</p>';

      const bodyHtml = `
        <div style="margin-bottom: 16px;">
          <h4 style="color:var(--text-secondary); font-size:12px; text-transform:uppercase; margin-bottom:8px;">Identity</h4>
          <p style="margin-bottom:4px;"><strong>Hostname:</strong> ${device.hostname || 'N/A'}</p>
          <p style="margin-bottom:4px;"><strong>Friendly Name:</strong> ${device.friendly_name || 'N/A'}</p>
          <p style="margin-bottom:4px;"><strong>MAC:</strong> ${device.current_mac || 'N/A'}</p>
          <p style="margin-bottom:4px;"><strong>IP:</strong> ${device.current_ip || 'N/A'}</p>
          <p style="margin-bottom:4px;"><strong>Vendor:</strong> ${device.vendor || 'N/A'}</p>
          <p style="margin-bottom:4px;"><strong>Model:</strong> ${device.model || 'N/A'}</p>
          <p><strong>Type:</strong> ${device.device_type || 'Unclassified'}</p>
        </div>
        <div>
          <h4 style="color:var(--text-secondary); font-size:12px; text-transform:uppercase; margin-bottom:8px;">Network Services</h4>
          ${device.services && device.services.length > 0 ? `<div class="service-pill-list">${device.services.map(s => `<span class="service-pill">${s}</span>`).join('')}</div>` : '<p style="font-size:13px; color:var(--text-secondary);">No services discovered.</p>'}
        </div>
        ${logHtml}
      `;
      
      this.openModal(device.friendly_name || device.hostname || 'Device Details', bodyHtml, `<button class="btn btn-secondary" id="modal-close-btn">Close</button>`);
      document.getElementById('modal-close-btn').addEventListener('click', () => this.closeModal());

    } catch (err) {
      this.openModal('Error', `<p>Failed to load device details.</p>`, `<button class="btn btn-secondary" id="modal-close-btn">Close</button>`);
      document.getElementById('modal-close-btn').addEventListener('click', () => this.closeModal());
    }
  }

  renderPoliciesView(container) {
    let html = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <h3>Access Policies (${this.policies.length})</h3>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-secondary" id="btn-import-pol">Import</button>
          <button class="btn btn-secondary" id="btn-export-pol">Export</button>
          <button class="btn btn-primary" id="btn-add-policy">+ New Policy</button>
        </div>
      </div>
      <input type="file" id="file-import-pol" accept=".json" style="display:none;">
      <div style="display:flex; flex-direction:column; gap:16px;">
        ${this.policies.map(p => {
          const isInfra = p.target_id === 'infrastructure';
          const schedSummary = this.getScheduleSummary(p);
          const scheds = this.resolvePolicySchedules(p);
          
          const isEmptySchedule = p.action === 'schedule' && scheds.length === 0;
          const emptySchedWarning = isEmptySchedule ? `
            <div class="hig-callout-warning" style="margin-top:8px; padding:8px 12px; font-size:12px;">
              ⚠️ <strong>Warning:</strong> No schedules attached. Policy currently defaults to <strong>ALLOW ALL</strong>.
            </div>
          ` : '';

          return `
            <div class="card" style="margin-bottom:0;">
              <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                <div>
                  <div style="font-size:16px; font-weight:700;">${p.name} ${isInfra ? '🔒' : ''} ${!p.enabled ? '<span style="color:var(--text-secondary); font-size:12px;">(Disabled)</span>' : ''}</div>
                  <div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">
                    Scope: <strong style="text-transform:capitalize;">${p.type}</strong> | Target: <strong>${p.target_id || 'Global'}</strong> | Priority: <strong>${p.priority}</strong>
                  </div>
                </div>
                <div style="display:flex; gap:8px;">
                  <button class="btn btn-secondary btn-edit-policy" data-id="${p.id}" ${isInfra ? 'disabled' : ''}>Edit</button>
                  <button class="btn btn-danger btn-delete-policy" data-id="${p.id}">Delete</button>
                </div>
              </div>
              ${isInfra ? `
                <div style="font-size:12px; color:var(--warning); margin-top:8px;">
                  🔒 Infrastructure devices always have unrestricted access — this policy has no effect and can be safely deleted.
                </div>
              ` : `
                <div style="margin-top:12px; font-size:13px; font-weight:600;">
                  Action: <span style="color:${p.action === 'allow' ? 'var(--success)' : p.action === 'block' ? 'var(--danger)' : 'var(--accent)'}">${p.action.toUpperCase()}</span>
                  ${schedSummary ? `<div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">${schedSummary}</div>` : ''}
                </div>
                ${emptySchedWarning}
                ${(p.action === 'schedule' && scheds.length > 0) ? this.renderWeeklyTimeline(scheds) : ''}
              `}
            </div>
          `;
        }).join('')}
      </div>
    `;

    container.innerHTML = html;

    const addBtn = document.getElementById('btn-add-policy');
    if (addBtn) addBtn.addEventListener('click', () => this.openPolicyWizard());

    document.querySelectorAll('.btn-edit-policy:not([disabled])').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.dataset.id;
        const p = this.policies.find(item => item.id === id);
        if (p) this.openPolicyWizard(p);
      });
    });

    document.querySelectorAll('.btn-delete-policy').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.dataset.id;
        const p = this.policies.find(item => item.id === id);
        if (!p) return;
        
        this.openConfirmModal('Delete Policy', `Are you sure you want to delete the policy <strong>${p.name}</strong>?<br><br>This action cannot be undone. Devices affected by this policy will revert to the global default rules.`, 'Delete', async () => {
          try {
            await API.deletePolicy(id);
            this.showToast('Policy deleted');
            this.closeModal();
            this.loadData();
          } catch (err) {
            this.showToast(`Failed to delete policy: ${err.message}`, 'danger');
          }
        });
      });
    });

    // LIAS-POL-08 Fix: Import/Export Buttons
    document.getElementById('btn-export-pol').addEventListener('click', async () => {
      try {
        const blob = await API.exportPolicies();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'lias_policies_export.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.showToast('Policies exported successfully');
      } catch (err) {
        this.showToast(`Export failed: ${err.message}`, 'danger');
      }
    });

    document.getElementById('btn-import-pol').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      try {
        await API.importPolicies(file);
        this.showToast('Policies imported successfully');
        this.loadData();
      } catch (err) {
        this.showToast(`Import failed: ${err.message}`, 'danger');
      }
      e.target.value = ''; // Reset input
    });
    
    document.getElementById('btn-import-pol').addEventListener('click', (e) => {
      e.stopPropagation();
      document.getElementById('file-import-pol').click();
    });
  }

  getScheduleSummary(p) {
    if (p.action !== 'schedule') return '';
    const schedIds = p.schedule_ids || (p.schedule_id ? [p.schedule_id] : []);
    if (schedIds.length === 0) return '<span class="badge-missing-sched">⚠️ No Schedule Attached</span>';

    const missing = [];
    const names = [];

    schedIds.forEach(id => {
      const s = this.schedules.find(item => item.id === id);
      if (s) {
        names.push(s.name);
      } else {
        missing.push(id);
      }
    });

    if (missing.length > 0) {
      return `<span class="badge-missing-sched">⚠️ Missing Schedule(s): ${missing.join(', ')} (Fails Closed: BLOCK)</span>`;
    }

    return `Attached Schedules (${names.length}): ${names.join(', ')}`;
  }

  resolvePolicySchedules(p) {
    const schedIds = p.schedule_ids || (p.schedule_id ? [p.schedule_id] : []);
    return schedIds.map(id => this.schedules.find(s => s.id === id)).filter(Boolean);
  }

  renderSchedulesView(container) {
    let html = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <h3>Time Schedules (${this.schedules.length})</h3>
        <button class="btn btn-primary" id="btn-add-schedule">+ New Schedule</button>
      </div>

      <div style="display:flex; flex-direction:column; gap:16px;">
        ${this.schedules.map(s => `
          <div class="card" style="margin-bottom:0;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start;">
              <div>
                <div style="font-size:16px; font-weight:700;">${s.name}</div>
                <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">
                  Mode: <strong style="text-transform:uppercase;">${s.mode || 'downtime'}</strong> | Timezone: <strong>${s.timezone}</strong>
                </div>
              </div>
              <div style="display:flex; gap:8px;">
                <button class="btn btn-secondary btn-edit-schedule" data-id="${s.id}">Edit</button>
                <button class="btn btn-danger btn-delete-schedule" data-id="${s.id}">Delete</button>
              </div>
            </div>
            ${this.renderWeeklyTimeline([s])}
          </div>
        `).join('')}
      </div>
    `;

    container.innerHTML = html;

    const addBtn = document.getElementById('btn-add-schedule');
    if (addBtn) addBtn.addEventListener('click', () => this.openScheduleModal());

    document.querySelectorAll('.btn-edit-schedule').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.dataset.id;
        const s = this.schedules.find(item => item.id === id);
        if (s) this.openScheduleModal(s);
      });
    });

    document.querySelectorAll('.btn-delete-schedule').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const id = e.currentTarget.dataset.id;
        this.confirmDeleteSchedule(id);
      });
    });
  }

  confirmDeleteSchedule(schedId) {
    const impactedPolicies = this.policies.filter(p => {
      const ids = p.schedule_ids || (p.schedule_id ? [p.schedule_id] : []);
      return ids.includes(schedId);
    });

    let warningHtml = '';
    if (impactedPolicies.length > 0) {
      warningHtml = `
        <div class="hig-callout-warning">
          <strong>⚠️ Warning: Impacted Policies</strong>
          <p style="margin-top:4px;">Deleting this schedule will impact ${impactedPolicies.length} policy/policies, causing them to fail closed (BLOCK):</p>
          <ul>
            ${impactedPolicies.map(p => `<li><strong>${p.name}</strong> (${p.target_id || 'Global'})</li>`).join('')}
          </ul>
        </div>
      `;
    }

    this.openConfirmModal('Delete Schedule', `<p>Are you sure you want to delete this schedule?</p>${warningHtml}`, 'Delete Schedule', async () => {
      try {
        await API.deleteSchedule(schedId);
        this.showToast('Schedule deleted');
        this.closeModal();
        this.loadData();
      } catch (err) {
        this.showToast(`Failed to delete schedule: ${err.message}`, 'danger');
      }
    });
  }

  // HIG Time Formatter Helper
  formatTimeTo12hr(timeStr) {
    if (!timeStr) return '';
    const parts = timeStr.split(':');
    const h = parseInt(parts[0], 10);
    const m = parseInt(parts[1], 10);
    const period = h >= 12 ? 'PM' : 'AM';
    let hour12 = h % 12;
    if (hour12 === 0) hour12 = 12;
    return `${hour12}:${String(m).padStart(2, '0')} ${period}`;
  }

  renderWeeklyTimeline(schedules) {
    if (!schedules || schedules.length === 0) return '';

    const colors = ['#0071e3', '#34c759', '#ff9500', '#af52de', '#5856d6', '#00c7be'];
    const conflicts = detectConflicts(schedules);

    const timezones = new Set(schedules.map(s => s.timezone).filter(Boolean));
    let tzWarningHtml = '';
    if (timezones.size > 1) {
      tzWarningHtml = `
        <div class="hig-callout-warning" style="margin-top:0; margin-bottom:8px;">
          <strong>⚠️ Mixed Timezones</strong>
          <p>Schedules in this bundle use different timezones (${[...timezones].join(', ')}). This can be confusing — consider aligning timezones.</p>
        </div>
      `;
    }

    let allSegments = [];
    schedules.forEach((s, sIdx) => {
      const segs = projectSchedule(s);
      segs.forEach(seg => {
        seg.color = colors[sIdx % colors.length];
        seg.scheduleName = s.name;
      });
      allSegments = allSegments.concat(segs);
    });

    const days = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
    const dayIndices = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };

    let html = `<div class="weekly-timeline">`;
    html += tzWarningHtml;

    if (conflicts.length > 0) {
      html += `
        <div class="hig-callout-warning" style="margin-top:0; margin-bottom:8px;">
          <strong>⚠️ Schedule Contradiction Detected</strong>
          <ul>
            ${conflicts.map(c => `<li>${c.schedule_a_name} (${c.action_a.toUpperCase()}) vs ${c.schedule_b_name} (${c.action_b.toUpperCase()}) on ${c.day} ${this.formatTimeTo12hr(c.overlap_start)} - ${this.formatTimeTo12hr(c.overlap_end)}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    html += `
      <div class="timeline-axis">
        <div class="timeline-day-label"></div>
        <div class="timeline-axis-track">
          <div class="axis-mark" style="left: 0%; transform: translateX(0);">12 AM</div>
          <div class="axis-mark" style="left: 25%;">6 AM</div>
          <div class="axis-mark" style="left: 50%;">12 PM</div>
          <div class="axis-mark" style="left: 75%;">6 PM</div>
          <div class="axis-mark" style="left: 100%; transform: translateX(-100%);">12 AM</div>
        </div>
      </div>
    `;

    days.forEach((day) => {
      const dayIdx = dayIndices[day];
      html += `
        <div class="timeline-day-row">
          <div class="timeline-day-label">${day}</div>
          <div class="timeline-track">
      `;

      const daySegments = allSegments.filter(seg => {
        const segDayIdx = Math.floor(seg.start / 1440);
        return segDayIdx === dayIdx;
      });

      daySegments.forEach(seg => {
        const startMin = seg.start % 1440;
        let endMin = seg.end % 1440;
        if (endMin === 0 && seg.end > seg.start) {
            endMin = 1440;
        }
        
        const startH = Math.floor(startMin / 60);
        const startM = startMin % 60;
        const endH = Math.floor(endMin / 60);
        const endM = endMin % 60;
        
        const startStr = this.formatTimeTo12hr(`${String(startH).padStart(2,'0')}:${String(startM).padStart(2,'0')}`);
        const endStr = this.formatTimeTo12hr(`${String(endH).padStart(2,'0')}:${String(endM).padStart(2,'0')}`);

        const leftPct = ((startMin / 1440) * 100).toFixed(1);
        const widthPct = (((endMin - startMin) / 1440) * 100).toFixed(1);
        
        html += `<div class="timeline-band" style="left:${leftPct}%; width:${widthPct}%; background:${seg.color};" title="${seg.scheduleName}: ${startStr} - ${endStr} (${seg.action})"></div>`;
      });

      conflicts.forEach(c => {
        if (c.day.substring(0, 3).toLowerCase() === day) {
          const startParts = c.overlap_start.split(':');
          const endParts = c.overlap_end.split(':');
          const startMin = parseInt(startParts[0], 10) * 60 + parseInt(startParts[1], 10);
          const endMin = parseInt(endParts[0], 10) * 60 + parseInt(endParts[1], 10);
          
          if (startMin < endMin) {
            const leftPct = ((startMin / 1440) * 100).toFixed(1);
            const widthPct = (((endMin - startMin) / 1440) * 100).toFixed(1);
            html += `<div class="timeline-band conflict" style="left:${leftPct}%; width:${widthPct}%;" title="CONFLICT: ${c.schedule_a_name} vs ${c.schedule_b_name}"></div>`;
          }
        }
      });

      html += `</div></div>`;
    });

    html += `</div>`;
    return html;
  }

  openPolicyWizard(existingPolicy = null) {
    this.wizardState = {
      step: 1,
      policy: existingPolicy ? JSON.parse(JSON.stringify(existingPolicy)) : {
        name: '',
        type: 'tag',
        target_id: '',
        action: 'schedule',
        schedule_ids: [],
        priority: 50
      }
    };

    if (!this.wizardState.policy.schedule_ids && this.wizardState.policy.schedule_id) {
      this.wizardState.policy.schedule_ids = [this.wizardState.policy.schedule_id];
    }

    this.renderPolicyWizardStep();
  }

  renderPolicyWizardStep() {
    const { step, policy } = this.wizardState;
    const title = policy.id ? 'Edit Access Policy' : 'New Access Policy Wizard';

    let bodyHtml = `
      <div class="wizard-steps">
        <div class="wizard-step ${step === 1 ? 'active' : ''}">
          <span class="wizard-step-num">1</span> Target
        </div>
        <div class="wizard-step ${step === 2 ? 'active' : ''}">
          <span class="wizard-step-num">2</span> Enforcement
        </div>
        <div class="wizard-step ${step === 3 ? 'active' : ''}">
          <span class="wizard-step-num">3</span> Schedules
        </div>
      </div>
    `;

    if (step === 1) {
      bodyHtml += `
        <div style="display:flex; flex-direction:column; gap:16px;">
          <div>
            <label style="font-size:12px; font-weight:700;">Policy Name</label>
            <input type="text" id="wiz-name" value="${policy.name}" placeholder="e.g. Kids Bedtime & Homework" style="width:100%; margin-top:4px;">
          </div>
          <div>
            <label style="font-size:12px; font-weight:700;">Scope / Type</label>
            <select id="wiz-type" style="width:100%; margin-top:4px;">
              <option value="tag" ${policy.type === 'tag' ? 'selected' : ''}>Tag Group</option>
              <option value="device" ${policy.type === 'device' ? 'selected' : ''}>Single Device</option>
              <option value="global" ${policy.type === 'global' ? 'selected' : ''}>Global Default</option>
            </select>
          </div>
          <div id="wiz-target-container">
            ${this.renderWizardTargetDropdown(policy.type, policy.target_id)}
          </div>
          <div id="wiz-shadow-warning"></div>
        </div>
      `;
    } else if (step === 2) {
      bodyHtml += `
        <div style="display:flex; flex-direction:column; gap:16px;">
          <div>
            <label style="font-size:12px; font-weight:700;">Enforcement Action</label>
            <select id="wiz-action" style="width:100%; margin-top:4px;">
              <option value="schedule" ${policy.action === 'schedule' ? 'selected' : ''}>Schedule-Driven (Multi-Schedule)</option>
              <option value="allow" ${policy.action === 'allow' ? 'selected' : ''}>Allow Always</option>
              <option value="block" ${policy.action === 'block' ? 'selected' : ''}>Block Always</option>
            </select>
          </div>
          <div>
            <label style="font-size:12px; font-weight:700;">Priority (Higher numbers win precedence)</label>
            <input type="number" id="wiz-priority" value="${policy.priority || 50}" style="width:100%; margin-top:4px;">
          </div>
        </div>
      `;
    } else if (step === 3) {
      const selectedScheds = (policy.schedule_ids || []).map(id => this.schedules.find(s => s.id === id)).filter(Boolean);
      const noSchedsSelected = (policy.schedule_ids || []).length === 0;

      bodyHtml += `
        <div style="display:flex; flex-direction:column; gap:16px;">
          <p style="font-size:13px; color:var(--text-secondary);">Select time schedules to attach to this policy:</p>
          
          ${noSchedsSelected ? `
            <div class="hig-callout-warning" style="margin-top:0; margin-bottom:8px; padding:8px 12px; font-size:12px;">
              ⚠️ <strong>Warning:</strong> No schedules selected. Saving this policy will default it to <strong>ALLOW ALL</strong> for the target.
            </div>
          ` : ''}

          <div style="max-height:180px; overflow-y:auto; display:flex; flex-direction:column; gap:8px;">
            ${this.schedules.map(s => {
              const checked = (policy.schedule_ids || []).includes(s.id);
              return `
                <label style="display:flex; align-items:center; gap:10px; padding:8px 12px; background:var(--bg-tertiary); border-radius:8px; cursor:pointer;">
                  <input type="checkbox" class="wiz-sched-checkbox" value="${s.id}" ${checked ? 'checked' : ''}>
                  <div>
                    <div style="font-size:14px; font-weight:700;">${s.name}</div>
                    <div style="font-size:11px; color:var(--text-secondary);">${s.mode || 'downtime'} mode | ${s.timezone}</div>
                  </div>
                </label>
              `;
            }).join('')}
          </div>
          <div id="wiz-timeline-container">
            ${this.renderWeeklyTimeline(selectedScheds)}
          </div>
        </div>
      `;
    }

    const footerHtml = `
      ${step > 1 ? '<button class="btn btn-secondary" id="wiz-btn-back">Back</button>' : ''}
      <button class="btn btn-secondary" id="wiz-btn-cancel">Cancel</button>
      ${step < 3 ? '<button class="btn btn-primary" id="wiz-btn-next">Next</button>' : '<button class="btn btn-primary" id="wiz-btn-save">Save Policy</button>'}
    `;

    this.openModal(title, bodyHtml, footerHtml);
    this.bindPolicyWizardEvents();
    if (step === 1) this.checkShadowPolicy();
    
    if (step === 3) {
      this.updateWizardConflictState();
    }
  }

  updateWizardConflictState() {
    const { policy } = this.wizardState;
    const selectedScheds = (policy.schedule_ids || []).map(id => this.schedules.find(s => s.id === id)).filter(Boolean);
    const conflicts = detectConflicts(selectedScheds);
    
    const saveBtn = document.getElementById('wiz-btn-save');
    if (saveBtn) {
        saveBtn.disabled = conflicts.length > 0;
        saveBtn.style.opacity = conflicts.length > 0 ? '0.5' : '1';
        saveBtn.style.cursor = conflicts.length > 0 ? 'not-allowed' : 'pointer';
    }
  }

  checkShadowPolicy() {
    const { policy } = this.wizardState;
    const container = document.getElementById('wiz-shadow-warning');
    if (!container || policy.type === 'global') {
      if (container) container.innerHTML = '';
      return;
    }

    const target = policy.target_id;
    const existing = this.policies.find(p => p.id !== policy.id && p.type === policy.type && p.target_id === target);

    if (existing) {
      container.innerHTML = `
        <div class="shadow-policy-banner">
          ⚠️ <strong>Shadow Policy Warning:</strong> '${existing.name}' already targets this ${policy.type}. Creating a second policy will not replace it — the higher-priority rule wins.
          <button class="btn btn-secondary" id="btn-edit-existing-shadow" style="padding:2px 8px; font-size:11px; margin-top:6px; display:block;">Edit Existing Policy Instead</button>
        </div>
      `;
      const editBtn = document.getElementById('btn-edit-existing-shadow');
      if (editBtn) {
        editBtn.addEventListener('click', () => {
          this.openPolicyWizard(existing);
        });
      }
    } else {
      container.innerHTML = '';
    }
  }

  renderWizardTargetDropdown(type, selectedTarget) {
    if (type === 'global') return '<p style="font-size:12px; color:var(--text-secondary);">Applies to all devices without specific policy</p>';

    if (type === 'tag') {
      const filteredTags = this.tags.filter(t => t.id !== 'infrastructure');
      return `
        <label style="font-size:12px; font-weight:700;">Target Tag Group</label>
        <select id="wiz-target" style="width:100%; margin-top:4px;">
          ${filteredTags.map(t => `<option value="${t.id}" ${t.id === selectedTarget ? 'selected' : ''}>${t.name}</option>`).join('')}
        </select>
        <p style="font-size:11px; color:var(--text-secondary); margin-top:4px;">🔒 Infrastructure devices have unrestricted access and cannot be scheduled.</p>
      `;
    }

    return `
      <label style="font-size:12px; font-weight:700;">Target Device</label>
      <select id="wiz-target" style="width:100%; margin-top:4px;">
        ${this.devices.map(d => `<option value="${d.pdid}" ${d.pdid === selectedTarget ? 'selected' : ''}>${d.hostname || d.pdid}</option>`).join('')}
      </select>
    `;
  }

  bindPolicyWizardEvents() {
    const { step, policy } = this.wizardState;

    const cancelBtn = document.getElementById('wiz-btn-cancel');
    if (cancelBtn) cancelBtn.addEventListener('click', () => this.closeModal());

    const backBtn = document.getElementById('wiz-btn-back');
    if (backBtn) {
      backBtn.addEventListener('click', () => {
        this.wizardState.step--;
        this.renderPolicyWizardStep();
      });
    }

    if (step === 1) {
      const typeSel = document.getElementById('wiz-type');
      if (typeSel) {
        typeSel.addEventListener('change', (e) => {
          policy.type = e.target.value;
          document.getElementById('wiz-target-container').innerHTML = this.renderWizardTargetDropdown(policy.type, policy.target_id);
          this.checkShadowPolicy();
        });
      }

      const targetSel = document.getElementById('wiz-target');
      if (targetSel) {
        targetSel.addEventListener('change', (e) => {
          policy.target_id = e.target.value;
          this.checkShadowPolicy();
        });
      }

      const nextBtn = document.getElementById('wiz-btn-next');
      if (nextBtn) {
        nextBtn.addEventListener('click', () => {
          const nameInput = document.getElementById('wiz-name');
          if (!nameInput.value.trim()) {
            this.showToast('Please enter a policy name', 'danger');
            return;
          }
          policy.name = nameInput.value.trim();
          const targetEl = document.getElementById('wiz-target');
          policy.target_id = targetEl ? targetEl.value : '';

          this.wizardState.step = 2;
          this.renderPolicyWizardStep();
        });
      }
    } else if (step === 2) {
      const nextBtn = document.getElementById('wiz-btn-next');
      if (nextBtn) {
        nextBtn.addEventListener('click', () => {
          const actionSel = document.getElementById('wiz-action');
          const prioInput = document.getElementById('wiz-priority');
          policy.action = actionSel.value;
          policy.priority = parseInt(prioInput.value, 10) || 50;

          if (policy.action !== 'schedule') {
            policy.schedule_ids = [];
            this.savePolicyFromWizard();
          } else {
            this.wizardState.step = 3;
            this.renderPolicyWizardStep();
          }
        });
      }
    } else if (step === 3) {
      document.querySelectorAll('.wiz-sched-checkbox').forEach(chk => {
        chk.addEventListener('change', () => {
          const selected = Array.from(document.querySelectorAll('.wiz-sched-checkbox:checked')).map(c => c.value);
          policy.schedule_ids = selected;

          const selectedScheds = selected.map(id => this.schedules.find(s => s.id === id)).filter(Boolean);
          document.getElementById('wiz-timeline-container').innerHTML = this.renderWeeklyTimeline(selectedScheds);
          
          this.renderPolicyWizardStep();
        });
      });

      const saveBtn = document.getElementById('wiz-btn-save');
      if (saveBtn) {
        saveBtn.addEventListener('click', () => this.savePolicyFromWizard());
      }
    }
  }

  async savePolicyFromWizard() {
    try {
      await API.savePolicy(this.wizardState.policy);
      this.showToast('Policy saved successfully');
      this.closeModal();
      this.loadData();
    } catch (err) {
      this.showToast(`Failed to save policy: ${err.message}`, 'danger');
    }
  }

  openScheduleModal(existingSchedule = null) {
    const s = existingSchedule ? JSON.parse(JSON.stringify(existingSchedule)) : {
      name: '',
      mode: 'downtime',
      timezone: 'UTC',
      rules: [{ days: ['mon', 'tue', 'wed', 'thu', 'fri'], start_time: '22:00', end_time: '06:00', action: 'block' }]
    };

    const bodyHtml = `
      <div style="display:flex; flex-direction:column; gap:16px;">
        <div>
          <label style="font-size:12px; font-weight:700;">Schedule Name</label>
          <input type="text" id="sched-name" value="${s.name}" placeholder="e.g. Bedtime Schedule" style="width:100%; margin-top:4px;">
        </div>
        <div>
          <label style="font-size:12px; font-weight:700;">Schedule Mode</label>
          <select id="sched-mode" style="width:100%; margin-top:4px;">
            <option value="downtime" ${s.mode === 'downtime' ? 'selected' : ''}>Downtime Mode (Rules BLOCK, Default ALLOW)</option>
            <option value="whitelist" ${s.mode === 'whitelist' ? 'selected' : ''}>Whitelist Mode (Rules ALLOW, Default BLOCK)</option>
          </select>
        </div>
        
        <div>
          <label style="font-size:12px; font-weight:700;">Timezone</label>
          <select id="sched-tz" style="width:100%; margin-top:4px;">
            ${this.timezones.map(tz => `<option value="${tz.value}" ${s.timezone === tz.value ? 'selected' : ''}>${tz.label}</option>`).join('')}
          </select>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px;">
          <label style="font-size:14px; font-weight:700;">Time Window Rules</label>
          <button class="btn btn-secondary" id="btn-add-rule">+ Add Rule</button>
        </div>

        <div id="sched-rules-container" style="display:flex; flex-direction:column; gap:12px; max-height:300px; overflow-y:auto;">
          ${s.rules.map((r, idx) => this.renderScheduleRuleRow(r, idx)).join('')}
        </div>
      </div>
    `;

    this.openModal(s.id ? 'Edit Schedule' : 'New Schedule', bodyHtml, `
      <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
      <button class="btn btn-primary" id="modal-save-sched">Save Schedule</button>
    `);

    this.bindScheduleModalEvents(s);
  }

  // LIAS-SCH-09 Fix: Added Calendar Date inputs to rule row
  renderScheduleRuleRow(rule, idx) {
    const isOvernight = rule.start_time && rule.end_time && rule.end_time <= rule.start_time;
    const daysArr = (rule.days || []).map(d => d.toLowerCase().substring(0, 3));
    const isAllDay = rule.start_time === '00:00' && rule.end_time === '23:59';

    return `
      <div class="card rule-row" data-idx="${idx}" style="padding:12px; margin-bottom:0; background:var(--bg-tertiary);">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <strong style="font-size:12px;">Rule #${idx + 1}</strong>
          <div style="display:flex; gap:6px; align-items:center;">
            <select class="day-mode-select" style="font-size:11px; padding:4px 8px;">
              <option value="range">Continuous Day Range</option>
              <option value="specific">Specific Days</option>
              <option value="calendar">Calendar Dates</option>
            </select>
            <button class="btn btn-danger btn-remove-rule" data-idx="${idx}" style="padding:4px 8px; font-size:11px;">Remove</button>
          </div>
        </div>
        
        <div class="rule-mode-container" style="display:flex; flex-direction:column; gap:8px;">
          <div class="day-range-picker" style="display:flex; gap:8px; align-items:center;">
            <label style="font-size:11px; font-weight:700;">From:</label>
            <select class="range-from" style="flex:1; font-size:12px; padding:6px;">${['mon','tue','wed','thu','fri','sat','sun'].map(d => `<option value="${d}" ${daysArr[0] === d ? 'selected' : ''}>${d.toUpperCase()}</option>`).join('')}</select>
            <label style="font-size:11px; font-weight:700;">To:</label>
            <select class="range-to" style="flex:1; font-size:12px; padding:6px;">${['mon','tue','wed','thu','fri','sat','sun'].map(d => `<option value="${d}" ${daysArr[daysArr.length - 1] === d ? 'selected' : ''}>${d.toUpperCase()}</option>`).join('')}</select>
          </div>

          <div class="day-chip-group specific-days-picker" style="display:none; flex-wrap:wrap; gap:4px;">
            ${['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'].map(day => `<div class="day-chip ${daysArr.includes(day) ? 'selected' : ''}" data-day="${day}">${day.toUpperCase()}</div>`).join('')}
          </div>

          <div class="calendar-picker" style="display:none; gap:8px; align-items:center;">
            <label style="font-size:11px; font-weight:700;">Start Date:</label>
            <input type="date" class="rule-start-date" value="${rule.start_date || ''}" style="flex:1; font-size:12px; padding:6px;">
            <label style="font-size:11px; font-weight:700;">End Date:</label>
            <input type="date" class="rule-end-date" value="${rule.end_date || ''}" style="flex:1; font-size:12px; padding:6px;">
          </div>
        </div>

        <div style="display:flex; gap:8px; align-items:center; margin-top:8px;">
          <input type="time" class="rule-start" value="${rule.start_time}" style="flex:1;" ${isAllDay ? 'disabled' : ''}>
          <span>to</span>
          <input type="time" class="rule-end" value="${rule.end_time}" style="flex:1;" ${isAllDay ? 'disabled' : ''}>
          <select class="rule-action" style="flex:1;">
            <option value="block" ${rule.action === 'block' ? 'selected' : ''}>Block</option>
            <option value="allow" ${rule.action === 'allow' ? 'selected' : ''}>Allow</option>
          </select>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px;">
          <div class="overnight-container">
            ${isOvernight && !isAllDay ? `<div class="overnight-chip moon">🌙 Continues past midnight — ends ${this.formatTimeTo12hr(rule.end_time)} the FOLLOWING day</div>` : ''}
          </div>
          <label style="display:flex; align-items:center; gap:4px; font-size:11px; font-weight:600; color:var(--text-secondary);">
            <input type="checkbox" class="rule-all-day" ${isAllDay ? 'checked' : ''}> All Day
          </label>
        </div>
      </div>
    `;
  }

  bindScheduleModalEvents(s) {
    document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());

    // LIAS-SCH-09 Fix: Handle mode switching (Range/Specific/Calendar)
    document.querySelectorAll('.day-mode-select').forEach(sel => {
      sel.addEventListener('change', (e) => {
        const row = e.target.closest('.rule-row');
        const mode = e.target.value;
        row.querySelector('.day-range-picker').style.display = mode === 'range' ? 'flex' : 'none';
        row.querySelector('.specific-days-picker').style.display = mode === 'specific' ? 'flex' : 'none';
        row.querySelector('.calendar-picker').style.display = mode === 'calendar' ? 'flex' : 'none';
      });
      // Trigger initial state if dates exist
      const row = sel.closest('.rule-row');
      if (row.querySelector('.rule-start-date').value) {
        sel.value = 'calendar';
        sel.dispatchEvent(new Event('change'));
      }
    });

    document.querySelectorAll('.day-chip').forEach(chip => chip.addEventListener('click', (e) => e.currentTarget.classList.toggle('selected')));
    
    document.querySelectorAll('.rule-start, .rule-end').forEach(input => {
      input.addEventListener('change', () => {
        const row = input.closest('.rule-row');
        const start = row.querySelector('.rule-start').value;
        const end = row.querySelector('.rule-end').value;
        const container = row.querySelector('.overnight-container');
        const allDayChk = row.querySelector('.rule-all-day');
        if (allDayChk && allDayChk.checked) return;
        if (start && end && end <= start) {
          container.innerHTML = `<div class="overnight-chip moon">🌙 Continues past midnight — ends ${this.formatTimeTo12hr(end)} the FOLLOWING day</div>`;
        } else {
          container.innerHTML = '';
        }
      });
    });

    document.querySelectorAll('.rule-all-day').forEach(chk => {
      chk.addEventListener('change', (e) => {
        const row = e.target.closest('.rule-row');
        const startInput = row.querySelector('.rule-start');
        const endInput = row.querySelector('.rule-end');
        const overnightContainer = row.querySelector('.overnight-container');
        if (e.target.checked) {
          startInput.value = '00:00'; endInput.value = '23:59';
          startInput.disabled = true; endInput.disabled = true; overnightContainer.innerHTML = '';
        } else { startInput.disabled = false; endInput.disabled = false; }
      });
    });

    const addRuleBtn = document.getElementById('btn-add-rule');
    if (addRuleBtn) {
      addRuleBtn.addEventListener('click', () => {
        const container = document.getElementById('sched-rules-container');
        const newIdx = container.children.length;
        const newRuleHtml = this.renderScheduleRuleRow({
          days: ['mon', 'tue', 'wed', 'thu', 'fri'],
          start_time: '22:00',
          end_time: '06:00',
          action: 'block'
        }, newIdx);
        container.insertAdjacentHTML('beforeend', newRuleHtml);
        this.bindScheduleModalEvents(s);
      });
    }

    document.querySelectorAll('.btn-remove-rule').forEach(btn => btn.addEventListener('click', (e) => e.currentTarget.closest('.rule-row').remove()));
    
    document.getElementById('modal-save-sched').addEventListener('click', async () => {
      const name = document.getElementById('sched-name').value.trim();
      if (!name) { this.showToast('Schedule name is required', 'danger'); return; }
      const mode = document.getElementById('sched-mode').value;
      const timezone = document.getElementById('sched-tz').value;
      const rules = [];
      document.querySelectorAll('.rule-row').forEach(row => {
        const start = row.querySelector('.rule-start').value;
        const end = row.querySelector('.rule-end').value;
        const action = row.querySelector('.rule-action').value;
        const modeSelect = row.querySelector('.day-mode-select').value;
        
        let days = [];
        let startDate = '';
        let endDate = '';

        if (modeSelect === 'calendar') {
            startDate = row.querySelector('.rule-start-date').value;
            endDate = row.querySelector('.rule-end-date').value;
            days = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']; // Dummy days to pass validation
        } else if (modeSelect === 'range') {
            days = expandDayRange(row.querySelector('.range-from').value, row.querySelector('.range-to').value);
        } else {
            days = Array.from(row.querySelectorAll('.day-chip.selected')).map(c => c.dataset.day);
        }

        if (start && end && (days.length > 0 || (startDate && endDate))) {
            rules.push({ days, start_time: start, end_time: end, action, start_date: startDate, end_date: endDate });
        }
      });
      s.name = name; s.mode = mode; s.timezone = timezone; s.rules = rules;
      try { await API.saveSchedule(s); this.showToast('Schedule saved successfully'); this.closeModal(); this.loadData(); }
      catch (err) { this.showToast(`Failed to save schedule: ${err.message}`, 'danger'); }
    });
  }

  // UI-FN-08 Fix: Analytics Dashboard View
  async renderAnalyticsView(container) {
    container.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;
    try {
      const stats = await API.getNetworkStats();
      const topDevName = this.devices.find(d => d.pdid === stats.TopBlockedDevicePDID)?.hostname || stats.TopBlockedDevicePDID || 'N/A';

      container.innerHTML = `
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap:16px; margin-bottom:24px;">
          <div class="card">
            <div style="font-size:13px; color:var(--danger); font-weight:600;">BLOCKED EVENTS (24H)</div>
            <div style="font-size:32px; font-weight:800; margin-top:4px; color:var(--danger);">${stats.BlockedEvents24h || 0}</div>
          </div>
          <div class="card">
            <div style="font-size:13px; color:var(--text-secondary); font-weight:600;">MOST BLOCKED DEVICE</div>
            <div style="font-size:20px; font-weight:700; margin-top:8px;">${topDevName}</div>
          </div>
        </div>
        <div class="card">
          <h3>Network Activity Insights</h3>
          <p style="color:var(--text-secondary); margin-top:4px;">Detailed flow logs and per-device bandwidth charts will appear here in future updates.</p>
        </div>
      `;
    } catch (err) {
      container.innerHTML = `<div class="card"><p>Failed to load analytics.</p></div>`;
    }
  }

  renderSettingsView(container) {
    // Fix 3: Rewrote Vacation Mode Toggle HTML/CSS to be strictly HIG compliant and clickable
    container.innerHTML = `
      <div class="card">
        <h3>System Maintenance</h3>
        <p style="font-size:13px; color:var(--text-secondary); margin-top:4px;">Manage underlying netfilter tables and global overrides.</p>
        <div style="margin-top:16px; display:flex; flex-direction:column; gap:12px;">
          <button class="btn btn-danger" id="btn-flush-nft">Flush Nftables Lancontrol Table</button>
          
          <div class="hig-toggle-row">
            <div class="hig-toggle-text">
              <strong>Vacation Mode</strong>
              <p>Immediately blocks all internet access for all devices (except Infrastructure).</p>
            </div>
            <label class="hig-toggle-switch">
              <input type="checkbox" id="chk-vacation">
              <span class="hig-slider"></span>
            </label>
          </div>
        </div>
      </div>
      <style>
        .hig-toggle-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 16px;
          background: var(--bg-tertiary);
          border-radius: 12px;
        }
        .hig-toggle-text strong {
          font-size: 15px;
          font-weight: 600;
          color: var(--text-primary);
          display: block;
        }
        .hig-toggle-text p {
          font-size: 13px;
          color: var(--text-secondary);
          margin-top: 4px;
        }
        .hig-toggle-switch {
          position: relative;
          display: inline-block;
          width: 51px;
          height: 31px;
          flex-shrink: 0;
          cursor: pointer;
        }
        .hig-toggle-switch input {
          opacity: 0;
          width: 0;
          height: 0;
        }
        .hig-slider {
          position: absolute;
          cursor: pointer;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background-color: #e9e9ea; /* Default Apple Gray for OFF */
          transition: .4s;
          border-radius: 31px;
        }
        .hig-slider:before {
          position: absolute;
          content: "";
          height: 27px;
          width: 27px;
          left: 2px;
          bottom: 2px;
          background-color: white;
          transition: .4s;
          border-radius: 50%;
          box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        input:checked + .hig-slider {
          background-color: #34c759; /* Apple Green for ON */
        }
        input:checked + .hig-slider:before {
          transform: translateX(20px);
        }
      </style>
    `;

    document.getElementById('btn-flush-nft').addEventListener('click', () => {
      this.openConfirmModal('Flush Nftables', 'Are you sure you want to flush all nftables netdev rules? LIAS will rebuild them on the next sync cycle.', 'Flush Rules', async () => {
        try { await API.flushNftables(); this.showToast('Nftables table flushed successfully'); }
        catch (err) { this.showToast(`Flush failed: ${err.message}`, 'danger'); }
      });
    });

    const vacChk = document.getElementById('chk-vacation');
    const globalPol = this.policies.find(p => p.id === 'global_default');
    
    // Fix 3: Explicitly set initial state
    if (globalPol && globalPol.action === 'block') {
      vacChk.checked = true;
    } else {
      vacChk.checked = false;
    }
    
    vacChk.addEventListener('change', async (e) => {
      try { 
        await API.toggleVacationMode(e.target.checked); 
        this.showToast(`Vacation Mode ${e.target.checked ? 'Enabled' : 'Disabled'}`); 
        
        // Fix 3: Update local state immediately to prevent UI flicker, then delay reload
        if (globalPol) {
          globalPol.action = e.target.checked ? 'block' : 'schedule';
        } else {
          this.policies.push({ id: 'global_default', action: e.target.checked ? 'block' : 'schedule' });
        }
        
        // Delay loadData to allow the toggle animation to complete smoothly
        setTimeout(() => this.loadData(), 300);
      } 
      catch (err) { 
        this.showToast(`Failed: ${err.message}`, 'danger'); 
        e.target.checked = !e.target.checked; 
      }
    });
  }

  openTagModal(existingTag = null) {
    const t = existingTag || { name: '', color: '#0071e3' };
    this.openModal(existingTag ? 'Edit Tag Group' : 'New Tag Group', `
      <div style="display:flex; flex-direction:column; gap:16px;">
        <div>
          <label style="font-size:12px; font-weight:700;">Tag Name</label>
          <input type="text" id="tag-name" value="${t.name}" placeholder="e.g. Smart TVs" style="width:100%; margin-top:4px;">
        </div>
        <div>
          <label style="font-size:12px; font-weight:700;">Badge Color</label>
          <input type="color" id="tag-color" value="${t.color}" style="width:100%; height:40px; border:none; cursor:pointer; margin-top:4px;">
        </div>
      </div>
    `, `
      <button class="btn btn-secondary" id="modal-cancel">Cancel</button>
      <button class="btn btn-primary" id="modal-save-tag">Save Tag</button>
    `);

    document.getElementById('modal-cancel').addEventListener('click', () => this.closeModal());
    document.getElementById('modal-save-tag').addEventListener('click', async () => {
      const name = document.getElementById('tag-name').value.trim();
      const color = document.getElementById('tag-color').value;
      if (!name) {
        this.showToast('Tag name required', 'danger');
        return;
      }

      try {
        if (existingTag) {
          await API.updateTag(existingTag.id, name, color);
        } else {
          await API.createTag(name, color);
        }
        this.showToast('Tag saved');
        this.closeModal();
        this.loadData();
      } catch (err) {
        this.showToast(`Failed: ${err.message}`, 'danger');
      }
    });
  }

  // HIG Modal Helpers (No primitive popups allowed)
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
