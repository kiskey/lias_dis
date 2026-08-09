/**
 * LIAS REST API Client & Real-time EventSource Subscriber
 * File:    apps/lias/web/src/api.js
 * Version: 2.5 (Added Extend Access & Effective Status endpoints)
 */

export const API = {
    csrfToken() {
        const prefix = 'lias_csrf=';
        const entry = document.cookie.split(';').map(value => value.trim()).find(value => value.startsWith(prefix));
        return entry ? decodeURIComponent(entry.slice(prefix.length)) : '';
    },

    async request(endpoint, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
            const csrf = this.csrfToken();
            if (csrf) headers['X-CSRF-Token'] = csrf;
        }
        const config = {
            ...options,
            credentials: 'same-origin',
            headers
        };

        const response = await fetch(endpoint, config);

        if (response.status === 204) {
            return null;
        }

        if (!response.ok) {
            let errorMsg = `HTTP Error ${response.status}`;
            let errData = null;
            try {
                errData = await response.json();
                if (errData) {
                    if (errData.message) {
                        errorMsg = errData.message;
                    } else if (errData.error) {
                        errorMsg = errData.error;
                    }
                }
            } catch (e) {
                // Ignore JSON parse errors on non-OK responses
            }

            const errorObj = new Error(errorMsg);
            errorObj.status = response.status;
            if (errData) {
                errorObj.error = errData.error;
                // Fix: Only overwrite message if errData.message is actually present
                if (errData.message) {
                    errorObj.message = errData.message;
                }
                errorObj.conflicts = errData.conflicts;
            }
            throw errorObj;
        }

        // Handle raw blob/text for export/import
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            return await response.json();
        }
        return await response.text();
    },

    async createSession(token) {
        return await this.request('/api/v1/session', {
            method: 'POST',
            body: JSON.stringify({ token })
        });
    },

    async deleteSession() {
        return await this.request('/api/v1/session', { method: 'DELETE' });
    },

    async getCapabilities() {
        return await this.request('/api/v1/capabilities');
    },

    async getSnapshot(etag = '') {
        const headers = {};
        if (etag) headers['If-None-Match'] = etag;
        const response = await fetch('/api/v1/snapshot', { credentials: 'same-origin', headers });
        if (response.status === 304) {
            return { notModified: true, etag: response.headers.get('etag') || etag };
        }
        if (!response.ok) {
            const error = new Error(`HTTP Error ${response.status}`);
            error.status = response.status;
            try {
                const body = await response.json();
                error.message = body.message || body.error || error.message;
                error.error = body.error;
            } catch (_) { /* keep status message */ }
            throw error;
        }
        return {
            notModified: false,
            etag: response.headers.get('etag') || '',
            snapshot: await response.json()
        };
    },

    // --- DEVICE ENDPOINTS ---
    async getDevices() {
        return await this.request('/api/v1/devices');
    },

    async getDevice(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}`);
    },

    async getDeviceLogs(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/logs`);
    },

    async assignDeviceTag(pdid, tagIds) {
        const payload = Array.isArray(tagIds) ? { tag_ids: tagIds } : { tag_id: tagIds };
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/tags`, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

    async pauseDeviceInternet(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/pause`, {
            method: 'POST'
        });
    },

    async unpauseDeviceInternet(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/pause`, {
            method: 'DELETE'
        });
    },

    async renameDevice(pdid, name) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/rename`, {
            method: 'POST',
            body: JSON.stringify({ name })
        });
    },

    async assignDeviceUser(pdid, userId) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/user`, {
            method: 'POST',
            body: JSON.stringify({ user_id: userId })
        });
    },

    // --- EXTEND ACCESS (DEVICE) ---
    async extendDeviceAccess(pdid, minutes) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/extend`, {
            method: 'POST',
            body: JSON.stringify({ minutes })
        });
    },

    async cancelDeviceExtension(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/extend`, {
            method: 'DELETE'
        });
    },

    async getDeviceEffectiveStatus(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/effective-status`);
    },

    // --- TAG ENDPOINTS ---
    async getTags() {
        return await this.request('/api/v1/tags');
    },

    async createTag(tagData, colorHex) {
        const payload = typeof tagData === 'string' ? { name: tagData, color: colorHex || '#0071e3' } : tagData;
        return await this.request('/api/v1/tags', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

    async updateTag(id, tagData, colorHex) {
        const payload = typeof tagData === 'string' ? { name: tagData, color: colorHex || '#0071e3' } : tagData;
        return await this.request(`/api/v1/tags/${encodeURIComponent(id)}`, {
            method: 'PUT',
            body: JSON.stringify(payload)
        });
    },

    async deleteTag(id) {
        return await this.request(`/api/v1/tags/${encodeURIComponent(id)}`, {
            method: 'DELETE'
        });
    },

    // --- EXTEND ACCESS (TAG) ---
    async extendTagAccess(tagId, minutes) {
        return await this.request(`/api/v1/tags/${encodeURIComponent(tagId)}/extend`, {
            method: 'POST',
            body: JSON.stringify({ minutes })
        });
    },

    async cancelTagExtension(tagId) {
        return await this.request(`/api/v1/tags/${encodeURIComponent(tagId)}/extend`, {
            method: 'DELETE'
        });
    },

    async getTagEffectiveStatus(tagId) {
        return await this.request(`/api/v1/tags/${encodeURIComponent(tagId)}/effective-status`);
    },

    // --- POLICY ENDPOINTS ---
    async getPolicies() {
        return await this.request('/api/v1/policies');
    },

    async createPolicy(policyData) {
        return await this.request('/api/v1/policies', {
            method: 'POST',
            body: JSON.stringify(policyData)
        });
    },

    async updatePolicy(id, policyData) {
        return await this.request(`/api/v1/policies/${encodeURIComponent(id)}`, {
            method: 'PUT',
            body: JSON.stringify(policyData)
        });
    },

    async savePolicy(policyData) {
        if (policyData.id) {
            try {
                return await this.updatePolicy(policyData.id, policyData);
            } catch (err) {
                if (err.status === 409) throw err;
                return await this.createPolicy(policyData);
            }
        }
        return await this.createPolicy(policyData);
    },

    async validatePolicy(scheduleIds) {
        return await this.request('/api/v1/policies/validate', {
            method: 'POST',
            body: JSON.stringify({ schedule_ids: scheduleIds })
        });
    },

    async deletePolicy(id) {
        return await this.request(`/api/v1/policies/${encodeURIComponent(id)}`, {
            method: 'DELETE'
        });
    },

    async exportPolicies() {
        const response = await fetch('/api/v1/policies/export', { credentials: 'same-origin' });
        if (!response.ok) throw new Error('Failed to export policies');
        return response.blob();
    },

    async importPolicies(jsonFile) {
        const text = await jsonFile.text();
        return await this.request('/api/v1/policies/import', {
            method: 'POST',
            body: text
        });
    },

    // --- SCHEDULE ENDPOINTS ---
    async getSchedules() {
        return await this.request('/api/v1/schedules');
    },

    async createSchedule(scheduleData) {
        return await this.request('/api/v1/schedules', {
            method: 'POST',
            body: JSON.stringify(scheduleData)
        });
    },

    async updateSchedule(id, scheduleData) {
        return await this.request(`/api/v1/schedules/${encodeURIComponent(id)}`, {
            method: 'PUT',
            body: JSON.stringify(scheduleData)
        });
    },

    async saveSchedule(scheduleData) {
        if (scheduleData.id) {
            try {
                return await this.updateSchedule(scheduleData.id, scheduleData);
            } catch (err) {
                if (err.status === 409) throw err;
                return await this.createSchedule(scheduleData);
            }
        }
        return await this.createSchedule(scheduleData);
    },

    async deleteSchedule(id) {
        return await this.request(`/api/v1/schedules/${encodeURIComponent(id)}`, {
            method: 'DELETE'
        });
    },

    // --- USER ENDPOINTS ---
    async createUser(userData) {
        return await this.request('/api/v1/users', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    },

    // --- IDENTITY REVIEW ENDPOINTS ---
    async getIdentityCandidates(status = 'pending', limit = 50, cursor = '') {
        const query = new URLSearchParams({ status, limit: String(limit) });
        if (cursor) query.set('cursor', cursor);
        return await this.request(`/api/v1/identity/candidates?${query.toString()}`);
    },

    async getIdentityCandidate(id) {
        return await this.request(`/api/v1/identity/candidates/${encodeURIComponent(id)}`);
    },

    async getIdentityProfile(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/identity`);
    },

    async decideIdentityCandidate(id, action, decision = {}) {
        return await this.request(`/api/v1/identity/candidates/${encodeURIComponent(id)}/${action}`, {
            method: 'POST',
            body: JSON.stringify(decision)
        });
    },

    async bindIdentity(pdid, binding) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/identity/bindings`, {
            method: 'POST',
            body: JSON.stringify(binding)
        });
    },

    async revokeIdentity(pdid, aliasId) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/identity/bindings/${encodeURIComponent(aliasId)}`, {
            method: 'DELETE'
        });
    },

    async splitIdentity(pdid, split) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/identity/split`, {
            method: 'POST',
            body: JSON.stringify(split)
        });
    },

    // --- SYSTEM & REPORTING ENDPOINTS ---
    async getNetworkStats() {
        return await this.request('/api/v1/stats');
    },

    async toggleVacationMode(enabled) {
        return await this.request('/api/v1/vacation', {
            method: 'POST',
            body: JSON.stringify({ enabled })
        });
    },

    async flushNftables() {
        return await this.request('/api/v1/nftables/flush', {
            method: 'POST'
        });
    },

    // --- REAL-TIME SSE EVENT STREAM ---
    subscribeEvents(onEventCallback) {
        const eventSource = new EventSource('/api/v1/events', { withCredentials: true });

        eventSource.onmessage = (e) => {
            try {
                const eventData = JSON.parse(e.data);
                onEventCallback(eventData);
            } catch (err) {
                // Ignore empty ping parse errors
            }
        };

        const eventTypes = [
            'device.added',
            'device.removed',
            'device.online',
            'device.offline',
            'device.hostname_changed',
            'device.fingerprint_updated',
            'device.ip_changed',
            'device.mac_changed',
            'device.reidentified',
            'security.alert',
            'effective.status_changed',
            'identity.candidate.changed',
            'identity.candidate.decided',
            'identity.binding.changed'
        ];

        eventTypes.forEach(evtType => {
            eventSource.addEventListener(evtType, (e) => {
                try {
                    let payload = null;
                    if (e.data) {
                        payload = JSON.parse(e.data);
                    }
                    onEventCallback({ type: evtType, payload: payload });
                } catch (err) {
                    onEventCallback({ type: evtType, payload: null });
                }
            });
        });

        eventSource.onerror = (err) => {
            // EventSource auto-reconnects natively on disconnect
        };

        return eventSource;
    }
};
