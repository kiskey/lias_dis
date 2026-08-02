/*
 * LIAS Control Center - API Client
 * File:    apps/lias/web/src/api.js
 * Version: 1.0
 */

const BASE_URL = '/api/v1';

export const API = {
  // Devices
  async getDevices() {
    const res = await fetch(`${BASE_URL}/devices`);
    if (!res.ok) throw new Error('Failed to fetch devices');
    return await res.json();
  },

  async getDevice(pdid) {
    const res = await fetch(`${BASE_URL}/devices/${pdid}`);
    if (!res.ok) throw new Error('Failed to fetch device details');
    return await res.json();
  },

  async assignDeviceTag(pdid, tagId) {
    const res = await fetch(`${BASE_URL}/devices/${pdid}/tags`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tag_id: tagId }),
    });
    if (!res.ok) throw new Error('Failed to assign tag');
  },

  // Tags
  async getTags() {
    const res = await fetch(`${BASE_URL}/tags`);
    if (!res.ok) throw new Error('Failed to fetch tags');
    return await res.json();
  },

  async createTag(name, color) {
    const res = await fetch(`${BASE_URL}/tags`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, color }),
    });
    if (!res.ok) throw new Error('Failed to create tag');
    return await res.json();
  },

  async deleteTag(id) {
    const res = await fetch(`${BASE_URL}/tags/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete tag');
  },

  // Policies
  async getPolicies() {
    const res = await fetch(`${BASE_URL}/policies`);
    if (!res.ok) throw new Error('Failed to fetch policies');
    return await res.json();
  },

  async createPolicy(policy) {
    const res = await fetch(`${BASE_URL}/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    });
    if (!res.ok) throw new Error('Failed to create policy');
    return await res.json();
  },

  async deletePolicy(id) {
    const res = await fetch(`${BASE_URL}/policies/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete policy');
  },

  // Schedules
  async getSchedules() {
    const res = await fetch(`${BASE_URL}/schedules`);
    if (!res.ok) throw new Error('Failed to fetch schedules');
    return await res.json();
  },

  async createSchedule(schedule) {
    const res = await fetch(`${BASE_URL}/schedules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(schedule),
    });
    if (!res.ok) throw new Error('Failed to create schedule');
    return await res.json();
  },

  async deleteSchedule(id) {
    const res = await fetch(`${BASE_URL}/schedules/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete schedule');
  },

  // SSE Real-Time Stream Subscription
  subscribeEvents(onEvent) {
    const es = new EventSource(`${BASE_URL}/events`);
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        onEvent({ type: e.type, ...data });
      } catch (err) {
        console.error('Failed to parse SSE frame', err);
      }
    };
    es.onerror = () => {
      console.warn('SSE connection lost, reconnecting...');
    };
    return es;
  },
};
