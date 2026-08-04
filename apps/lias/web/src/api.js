/**
 * LIAS REST API Client & Real-time EventSource Subscriber
 * File:    apps/lias/web/src/api.js
 * Version: 2.2 (Added Reporting, Device Logs, Import/Export, Vacation Mode)
 */

export const API = {
    async request(endpoint, options = {}) {
        const config = {
            headers: { 'Content-Type': 'application/json', ...options.headers },
            ...options
        };

        const response = await fetch(endpoint, config);

        if (response.status === 204) return null;

        if (!response.ok) {
            let errorMsg = `HTTP Error ${response.status}`;
            let errData = null;
            try {
                errData = await response.json();
                if (errData) {
                    if (errData.message) errorMsg = errData.message;
                    else if (errData.error) errorMsg = errData.error;
                }
            } catch (e) {}

            const errorObj = new Error(errorMsg);
            errorObj.status = response.status;
            if (errData) {
                errorObj.error = errData.error;
                errorObj.message = errData.message;
                errorObj.conflicts = errData.conflicts;
            }
            throw errorObj;
        }

        // Handle raw blob for export
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return await response.json();
        }
        return await response.text();
    },

    // --- DEVICE ENDPOINTS ---
    async getDevices() { return await this.request('/api/v1/devices'); },
    async getDevice(pdid) { return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}`); },
    async getDeviceLogs(pdid) { return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/logs`); }, // UI-FN-01
    async assignDeviceTag(pdid, tagId) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/tags`, {
            method: 'POST', body: JSON.stringify({ tag_id: tagId })
        });
    },
    async pauseDeviceInternet(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/pause`, { method: 'POST' });
    },
    async renameDevice(pdid, name) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/rename`, {
            method: 'POST', body: JSON.stringify({ name })
        });
    },
    async assignDeviceUser(pdid, userId) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/user`, {
            method: 'POST', body: JSON.stringify({ user_id: userId })
        });
    },

    // --- TAG ENDPOINTS ---
    async getTags() { return await this.request('/api/v1/tags'); },
    async createTag(tagData, colorHex) {
        const payload = typeof tagData === 'string' ? { name: tagData, color: colorHex || '#0071e3' } : tagData;
        return await this.request('/api/v1/tags', { method: 'POST', body: JSON.stringify(payload) });
    },
    async updateTag(id, tagData, colorHex) {
        const payload = typeof tagData === 'string' ? { name: tagData, color: colorHex || '#0071e3' } : tagData;
        return await this.request(`/api/v1/tags/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(payload) });
    },
    async deleteTag(id) {
        return await this.request(`/api/v1/tags/${encodeURIComponent(id)}`, { method: 'DELETE' });
    },

    // --- POLICY ENDPOINTS ---
    async getPolicies() { return await this.request('/api/v1/policies'); },
    async createPolicy(policyData) {
        return await this.request('/api/v1/policies', { method: 'POST', body: JSON.stringify(policyData) });
    },
    async updatePolicy(id, policyData) {
        return await this.request(`/api/v1/policies/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(policyData) });
    },
    async savePolicy(policyData) {
        if (policyData.id) {
            try { return await this.updatePolicy(policyData.id, policyData); }
            catch (err) { if (err.status === 409) throw err; return await this.createPolicy(policyData); }
        }
        return await this.createPolicy(policyData);
    },
    async validatePolicy(scheduleIds) {
        return await this.request('/api/v1/policies/validate', { method: 'POST', body: JSON.stringify({ schedule_ids: scheduleIds }) });
    },
    async deletePolicy(id) {
        return await this.request(`/api/v1/policies/${encodeURIComponent(id)}`, { method: 'DELETE' });
    },
    // LIAS-POL-08 Fix: Import/Export
    async exportPolicies() {
        // Use raw fetch for blob download
        const response = await fetch('/api/v1/policies/export');
        if (!response.ok) throw new Error('Failed to export');
        return response.blob();
    },
    async importPolicies(jsonFile) {
        const text = await jsonFile.text();
        return await this.request('/api/v1/policies/import', { method: 'POST', body: text });
    },

    // --- SCHEDULE ENDPOINTS ---
    async getSchedules() { return await this.request('/api/v1/schedules'); },
    async createSchedule(scheduleData) {
        return await this.request('/api/v1/schedules', { method: 'POST', body: JSON.stringify(scheduleData) });
    },
    async updateSchedule(id, scheduleData) {
        return await this.request(`/api/v1/schedules/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(scheduleData) });
    },
    async saveSchedule(scheduleData) {
        if (scheduleData.id) {
            try { return await this.updateSchedule(scheduleData.id, scheduleData); }
            catch (err) { if (err.status === 409) throw err; return await this.createSchedule(scheduleData); }
        }
        return await this.createSchedule(scheduleData);
    },
    async deleteSchedule(id) {
        return await this.request(`/api/v1/schedules/${encodeURIComponent(id)}`, { method: 'DELETE' });
    },

    // --- SYSTEM & REPORTING ENDPOINTS ---
    async getNetworkStats() { return await this.request('/api/v1/stats'); }, // UI-FN-08
    async toggleVacationMode(enabled) { // LIAS-POL-12
        return await this.request('/api/v1/vacation', { method: 'POST', body: JSON.stringify({ enabled }) });
    },
    async flushNftables() {
        return await this.request('/api/v1/nftables/flush', { method: 'POST' });
    },

    // --- REAL-TIME SSE EVENT STREAM ---
    subscribeEvents(onEventCallback) {
        const eventSource = new EventSource('/api/v1/events');

        eventSource.onmessage = (e) => {
            try {
                const eventData = JSON.parse(e.data);
                onEventCallback(eventData);
            } catch (err) {}
        };

        const eventTypes = [
            'device.added', 'device.removed', 'device.online', 'device.offline',
            'device.hostname_changed', 'device.fingerprint_updated', 'device.ip_changed',
            'device.mac_changed', 'device.reidentified', 'security.alert'
        ];

        eventTypes.forEach(evtType => {
            eventSource.addEventListener(evtType, (e) => {
                try {
                    let payload = null;
                    if (e.data) payload = JSON.parse(e.data);
                    onEventCallback({ type: evtType, payload: payload });
                } catch (err) {
                    onEventCallback({ type: evtType, payload: null });
                }
            });
        });

        eventSource.onerror = (err) => {};
        return eventSource;
    }
};
