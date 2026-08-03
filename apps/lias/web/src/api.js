/**
 * LIAS REST API Client & Real-time EventSource Subscriber
 * File:    apps/lias/web/src/api.js
 * Version: 2.0 (Audited & Merged per Enhancement 3.0)
 */

export const API = {
    /**
     * Internal generic fetch helper handling JSON responses, status validation,
     * and attaching 409 Conflict metadata to thrown errors.
     */
    async request(endpoint, options = {}) {
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
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
                errorObj.message = errData.message;
                errorObj.conflicts = errData.conflicts;
            }
            throw errorObj;
        }

        return await response.json();
    },

    // --- DEVICE ENDPOINTS ---
    async getDevices() {
        return await this.request('/api/v1/devices');
    },

    async getDevice(pdid) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}`);
    },

    async assignDeviceTag(pdid, tagId) {
        return await this.request(`/api/v1/devices/${encodeURIComponent(pdid)}/tags`, {
            method: 'POST',
            body: JSON.stringify({ tag_id: tagId })
        });
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
                // If update failed due to 409 Conflict, rethrow immediately
                if (err.status === 409) throw err;
                // Fall back to create if policy record doesn't exist yet
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

    // --- NFTABLES ENDPOINTS ---
    async flushNftables() {
        return await this.request('/api/v1/nftables/flush', {
            method: 'POST'
        });
    },

    // --- REAL-TIME SSE EVENT STREAM ---
    subscribeEvents(onEventCallback) {
        const eventSource = new EventSource('/api/v1/events');

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
            'device.mac_changed'
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
