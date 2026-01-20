/**
 * RAKSHAK Dashboard JavaScript
 * India's First Agentic AI Cyber Guardian for Home IoT
 */

// =============================================================================
// Configuration
// =============================================================================
const API_BASE = '';
const REFRESH_INTERVAL = 5000;

// =============================================================================
// Internationalization
// =============================================================================
const translations = {
    en: {
        devices: 'Devices',
        threats: 'Threats',
        honeypots: 'Honeypots',
        actions: 'Actions',
        network_devices: 'Network Devices',
        scan: 'Scan',
        device: 'Device',
        ip: 'IP',
        risk: 'Risk',
        status: 'Status',
        action: 'Action',
        loading: 'Loading...',
        threat_activity: 'Threat Activity',
        live_events: 'Live Events',
        waiting: 'Waiting for events...',
        active_honeypots: 'Active Honeypots',
        deploy: 'Deploy',
        no_honeypots: 'No active honeypots',
        quick_actions: 'Quick Actions',
        export_cctns: 'Export CCTNS',
        export_json: 'Export JSON',
        view_intel: 'View Intel',
        simulation: 'Simulation',
        mode_simulation: 'Mode: Simulation',
        isolate: 'Isolate',
        connected: 'Connected',
        disconnected: 'Disconnected',
        threat_detected: 'Threat detected on {device}!',
        attack_blocked: 'Attack from {ip} blocked'
    },
    hi: {
        devices: 'उपकरण',
        threats: 'खतरे',
        honeypots: 'हनीपॉट',
        actions: 'कार्रवाई',
        network_devices: 'नेटवर्क उपकरण',
        scan: 'स्कैन',
        device: 'उपकरण',
        ip: 'आईपी',
        risk: 'जोखिम',
        status: 'स्थिति',
        action: 'कार्रवाई',
        loading: 'लोड हो रहा है...',
        threat_activity: 'खतरा गतिविधि',
        live_events: 'लाइव इवेंट्स',
        waiting: 'इवेंट्स का इंतजार...',
        active_honeypots: 'सक्रिय हनीपॉट',
        deploy: 'तैनात करें',
        no_honeypots: 'कोई सक्रिय हनीपॉट नहीं',
        quick_actions: 'त्वरित कार्रवाई',
        export_cctns: 'CCTNS निर्यात',
        export_json: 'JSON निर्यात',
        view_intel: 'इंटेल देखें',
        simulation: 'सिमुलेशन',
        mode_simulation: 'मोड: सिमुलेशन',
        isolate: 'अलग करें',
        connected: 'जुड़ा हुआ',
        disconnected: 'डिस्कनेक्ट',
        threat_detected: '{device} पर खतरा पाया गया!',
        attack_blocked: '{ip} से हमला रोका गया'
    }
};

let currentLanguage = 'en';

// =============================================================================
// State
// =============================================================================
let socket = null;
let threatChart = null;
let threatData = [];
let eventsCount = 0;

// =============================================================================
// Initialization
// =============================================================================
document.addEventListener('DOMContentLoaded', () => {
    initializeSocket();
    initializeChart();
    loadInitialData();
    setupEventListeners();
    startAutoRefresh();
});

// =============================================================================
// WebSocket
// =============================================================================
function initializeSocket() {
    socket = io();

    socket.on('connect', () => {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
        addEvent('info', 'Connected to RAKSHAK server');
    });

    socket.on('disconnect', () => {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
        addEvent('warning', 'Disconnected from server');
    });

    socket.on('connected', (data) => {
        console.log('Server message:', data.message);
    });

    socket.on('threat_detected', (data) => {
        handleThreatDetected(data);
    });

    socket.on('action_taken', (data) => {
        handleActionTaken(data);
    });

    socket.on('alert', (data) => {
        showAlert(data.message, data.severity);
    });

    socket.on('device_isolated', (data) => {
        addEvent('action', `Device ${data.ip} isolated`);
        loadDevices();
    });

    socket.on('honeypot_deployed', (data) => {
        addEvent('action', `Honeypot ${data.id} deployed on port ${data.port}`);
        loadHoneypots();
    });

    socket.on('status_update', (data) => {
        updateStats(data);
    });

    socket.on('devices_update', (data) => {
        renderDevices(data.devices);
        document.getElementById('devices-count').textContent = data.count;
    });

    socket.on('device_status_changed', (data) => {
        console.log(`Device ${data.ip} status changed to ${data.status}`);
        updateDeviceStatus(data.ip, data.status);
    });
}

function updateConnectionStatus(connected) {
    const indicator = document.getElementById('status-indicator');
    const dot = indicator.querySelector('.status-dot');
    const text = document.getElementById('status-text');

    if (connected) {
        dot.classList.add('active');
        text.textContent = t('connected');
    } else {
        dot.classList.remove('active');
        text.textContent = t('disconnected');
    }
}

// =============================================================================
// Data Loading
// =============================================================================
function loadInitialData() {
    loadStatus();
    loadDevices();
    loadThreats();
    loadHoneypots();
}

async function loadStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/status`);
        const data = await response.json();
        if (data.success) {
            updateStats(data.data);
        }
    } catch (error) {
        console.error('Failed to load status:', error);
    }
}

async function loadDevices() {
    try {
        const response = await fetch(`${API_BASE}/api/devices`);
        const data = await response.json();
        if (data.success) {
            renderDevices(data.data);
            document.getElementById('devices-count').textContent = data.count;
        }
    } catch (error) {
        console.error('Failed to load devices:', error);
    }
}

async function loadThreats() {
    try {
        const response = await fetch(`${API_BASE}/api/threats?limit=20`);
        const data = await response.json();
        if (data.success) {
            updateThreatChart(data.data);
            document.getElementById('threats-count').textContent = data.count;
        }
    } catch (error) {
        console.error('Failed to load threats:', error);
    }
}

async function loadHoneypots() {
    try {
        const response = await fetch(`${API_BASE}/api/honeypots`);
        const data = await response.json();
        if (data.success) {
            renderHoneypots(data.data);
            document.getElementById('honeypots-count').textContent = data.count;
        }
    } catch (error) {
        console.error('Failed to load honeypots:', error);
    }
}

// =============================================================================
// Rendering
// =============================================================================
function renderDevices(devices) {
    const tbody = document.getElementById('devices-table-body');

    if (!devices || devices.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="loading">${t('loading')}</td></tr>`;
        return;
    }

    tbody.innerHTML = devices.map(device => {
        // Get zone badge
        const zoneBadge = getZoneBadge(device.zone || 'unknown');

        // Get enrollment status
        const enrollmentStatus = device.enrollment_status || 'unknown';

        // Determine action buttons based on enrollment status
        let actionButtons = '';

        if (enrollmentStatus === 'unknown') {
            // Unknown device - show "Enroll" button
            actionButtons = `
                <button class="btn btn-sm btn-primary" onclick="initiateEnrollment('${device.ip}')">
                    Enroll
                </button>
            `;
        } else if (enrollmentStatus === 'pending') {
            // Pending - show zone dropdown and "Approve" button
            actionButtons = `
                <select id="zone-${device.ip}" class="zone-select">
                    <option value="main">MAIN (Trusted)</option>
                    <option value="iot" selected>IOT (Limited)</option>
                    <option value="guest">GUEST (Untrusted)</option>
                </select>
                <button class="btn btn-sm btn-success" onclick="approveEnrollment('${device.ip}')">
                    Approve
                </button>
            `;
        } else if (enrollmentStatus === 'enrolled') {
            // Enrolled - show zone change and isolate
            actionButtons = `
                <select id="zone-${device.ip}" class="zone-select" onchange="changeZone('${device.ip}')">
                    <option value="main" ${device.zone === 'main' ? 'selected' : ''}>MAIN</option>
                    <option value="iot" ${device.zone === 'iot' ? 'selected' : ''}>IOT</option>
                    <option value="guest" ${device.zone === 'guest' ? 'selected' : ''}>GUEST</option>
                </select>
                <button class="btn btn-sm btn-danger" onclick="isolateDevice('${device.ip}')"
                        ${device.status === 'isolated' ? 'disabled' : ''}>
                    Isolate
                </button>
            `;
        } else {
            // Fallback - just isolate button
            actionButtons = `
                <button class="btn btn-sm btn-danger" onclick="isolateDevice('${device.ip}')"
                        ${device.status === 'isolated' ? 'disabled' : ''}>
                    ${t('isolate')}
                </button>
            `;
        }

        return `
            <tr>
                <td>
                    <div style="font-weight: 500;">${getDeviceDisplayName(device)}</div>
                    <div class="text-muted" style="font-size: 0.75rem;">${device.device_type || 'unknown'}</div>
                </td>
                <td><code>${device.ip}</code></td>
                <td>${zoneBadge}</td>
                <td>
                    <span class="risk-badge risk-${getRiskLevel(device.risk_score || 0)}">
                        ${device.risk_score || 0}%
                    </span>
                </td>
                <td>
                    <span class="status-badge status-${device.status || 'active'}">
                        ${device.status || 'active'}
                    </span>
                </td>
                <td class="action-cell">
                    ${actionButtons}
                </td>
            </tr>
        `;
    }).join('');
}

function updateDeviceStatus(ip, newStatus) {
    const rows = document.querySelectorAll('#devices-table-body tr');
    rows.forEach(row => {
        const ipCell = row.querySelector('code');
        if (ipCell && ipCell.textContent === ip) {
            const statusBadge = row.querySelector('.status-badge');
            if (statusBadge) {
                // Remove old status class
                statusBadge.className = 'status-badge';
                // Add new status class
                statusBadge.classList.add(`status-${newStatus}`);
                statusBadge.textContent = newStatus;
            }
        }
    });
}

function getZoneBadge(zone) {
    const zoneColors = {
        'mgmt': 'primary',
        'main': 'success',
        'iot': 'warning',
        'guest': 'secondary',
        'quarantine': 'danger',
        'unknown': 'dark'
    };

    const color = zoneColors[zone] || 'dark';
    const displayName = zone.toUpperCase();

    return `<span class="badge badge-${color}">${displayName}</span>`;
}

function getRiskLevel(score) {
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
}

function getDeviceDisplayName(device) {
    // If device has a hostname and it's not "unknown", use it
    if (device.hostname && device.hostname !== 'unknown' && device.hostname !== '') {
        return device.hostname;
    }

    // Generate friendly name from manufacturer and device_type
    const manufacturer = device.manufacturer || 'unknown';
    const deviceType = device.device_type || 'unknown';

    // If both are unknown, return "Unknown Device"
    if (manufacturer === 'unknown' && deviceType === 'unknown') {
        return 'Unknown Device';
    }

    // Format device type nicely
    const formatDeviceType = (type) => {
        const typeMap = {
            'esp32_cam': 'ESP32 Camera',
            'network_adapter': 'Network Adapter',
            'smart_bulb': 'Smart Bulb',
            'smart_plug': 'Smart Plug',
            'smart_tv': 'Smart TV',
            'smart_speaker': 'Smart Speaker',
            'thermostat': 'Thermostat',
            'streaming': 'Streaming Device',
            'camera': 'Camera',
            'router': 'Router',
            'mobile': 'Mobile Device',
            'alexa': 'Alexa',
            'unknown': 'Device'
        };
        return typeMap[type] || type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    };

    // If only device type is known
    if (manufacturer === 'unknown') {
        return formatDeviceType(deviceType);
    }

    // If only manufacturer is known
    if (deviceType === 'unknown') {
        return `${manufacturer} Device`;
    }

    // Both known - combine them
    return `${manufacturer} ${formatDeviceType(deviceType)}`;
}

function renderHoneypots(honeypots) {
    const container = document.getElementById('honeypots-list');

    if (!honeypots || honeypots.length === 0) {
        container.innerHTML = `<div class="honeypot-item empty">${t('no_honeypots')}</div>`;
        return;
    }

    container.innerHTML = honeypots.map(hp => `
        <div class="honeypot-item">
            <div class="honeypot-info">
                <span class="honeypot-id">${hp.id}</span>
                <span class="honeypot-details">${hp.protocol}:${hp.port} | ${hp.persona}</span>
            </div>
            <div class="honeypot-stats">
                <span class="honeypot-connections">${hp.connections}</span>
                <div class="text-muted" style="font-size: 0.75rem;">connections</div>
            </div>
        </div>
    `).join('');
}

function updateStats(data) {
    if (data.devices_count !== undefined) {
        document.getElementById('devices-count').textContent = data.devices_count;
    }
    if (data.threats_count !== undefined) {
        document.getElementById('threats-count').textContent = data.threats_count;
    }
    if (data.honeypots_active !== undefined) {
        document.getElementById('honeypots-count').textContent = data.honeypots_active;
    }
}

// =============================================================================
// Events
// =============================================================================
function addEvent(type, message) {
    const eventsList = document.getElementById('events-list');
    const time = new Date().toLocaleTimeString();

    const eventHtml = `
        <div class="event-item ${type}">
            <span class="event-time">${time}</span>
            <span class="event-message">${message}</span>
        </div>
    `;

    // Add to top
    eventsList.insertAdjacentHTML('afterbegin', eventHtml);

    // Keep only last 50 events
    const events = eventsList.querySelectorAll('.event-item');
    if (events.length > 50) {
        events[events.length - 1].remove();
    }

    eventsCount++;
    document.getElementById('actions-count').textContent = eventsCount;
}

function handleThreatDetected(data) {
    const threat = data.threat;
    const message = t('threat_detected').replace('{device}', threat.target_device);

    addEvent('threat', message);
    showAlert(message, 'danger');

    // Update chart
    threatData.push({
        time: new Date(),
        severity: threat.severity
    });
    updateThreatChart();

    // Update count
    const currentCount = parseInt(document.getElementById('threats-count').textContent) || 0;
    document.getElementById('threats-count').textContent = currentCount + 1;
}

function handleActionTaken(data) {
    const action = data.action;
    addEvent('action', `${action.action}: ${action.target}`);
}

// =============================================================================
// Chart
// =============================================================================
function initializeChart() {
    const ctx = document.getElementById('threat-chart').getContext('2d');

    threatChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Threats',
                data: [],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    display: true,
                    grid: {
                        color: '#1e293b'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                },
                y: {
                    display: true,
                    beginAtZero: true,
                    grid: {
                        color: '#1e293b'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                }
            }
        }
    });
}

function updateThreatChart(threats = []) {
    if (!threatChart) return;

    // Group threats by time (last 10 intervals)
    const now = new Date();
    const labels = [];
    const data = [];

    for (let i = 9; i >= 0; i--) {
        const time = new Date(now - i * 60000); // 1 minute intervals
        labels.push(time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
        data.push(Math.floor(Math.random() * 5)); // Placeholder
    }

    threatChart.data.labels = labels;
    threatChart.data.datasets[0].data = data;
    threatChart.update('none');
}

// =============================================================================
// Actions
// =============================================================================
async function scanNetwork() {
    addEvent('info', 'Starting network scan...');
    await loadDevices();
    addEvent('info', 'Network scan complete');
}

async function isolateDevice(ip) {
    try {
        const response = await fetch(`${API_BASE}/api/devices/${ip}/isolate`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.success) {
            addEvent('action', `Device ${ip} isolated`);
            loadDevices();
        }
    } catch (error) {
        console.error('Failed to isolate device:', error);
    }
}

async function initiateEnrollment(ip) {
    const token = localStorage.getItem('auth_token');

    try {
        const response = await fetch(`${API_BASE}/api/devices/${ip}/enroll`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        const data = await response.json();
        if (data.success) {
            addEvent('info', `Enrollment initiated for ${ip}`);
            showAlert(`Device ${ip} marked for enrollment`, 'success');
            loadDevices();
        } else {
            showAlert(data.error || 'Failed to initiate enrollment', 'danger');
        }
    } catch (error) {
        console.error('Failed to initiate enrollment:', error);
        showAlert('Error initiating enrollment', 'danger');
    }
}

async function approveEnrollment(ip) {
    const token = localStorage.getItem('auth_token');
    const zoneSelect = document.getElementById(`zone-${ip}`);
    const zone = zoneSelect ? zoneSelect.value : 'iot';

    try {
        const response = await fetch(`${API_BASE}/api/devices/${ip}/approve`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ zone: zone })
        });
        const data = await response.json();
        if (data.success) {
            addEvent('action', `Device ${ip} enrolled to ${zone.toUpperCase()} zone`);
            showAlert(`Device enrolled to ${zone.toUpperCase()} zone`, 'success');
            loadDevices();
        } else {
            showAlert(data.error || 'Failed to approve enrollment', 'danger');
        }
    } catch (error) {
        console.error('Failed to approve enrollment:', error);
        showAlert('Error approving enrollment', 'danger');
    }
}

async function changeZone(ip) {
    const token = localStorage.getItem('auth_token');
    const zoneSelect = document.getElementById(`zone-${ip}`);
    const newZone = zoneSelect.value;

    // Confirm zone change
    if (!confirm(`Change device ${ip} to ${newZone.toUpperCase()} zone?`)) {
        // Revert selection
        loadDevices();
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/devices/${ip}/approve`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ zone: newZone })
        });
        const data = await response.json();
        if (data.success) {
            addEvent('action', `Device ${ip} moved to ${newZone.toUpperCase()} zone`);
            showAlert(`Zone changed to ${newZone.toUpperCase()}`, 'success');
            loadDevices();
        } else {
            showAlert(data.error || 'Failed to change zone', 'danger');
            loadDevices(); // Revert UI
        }
    } catch (error) {
        console.error('Failed to change zone:', error);
        showAlert('Error changing zone', 'danger');
        loadDevices(); // Revert UI
    }
}

async function deployHoneypot() {
    try {
        const response = await fetch(`${API_BASE}/api/honeypots/deploy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ protocol: 'telnet', persona: 'tp_link' })
        });
        const data = await response.json();
        if (data.success) {
            addEvent('action', `Honeypot ${data.data.id} deployed`);
            loadHoneypots();
        }
    } catch (error) {
        console.error('Failed to deploy honeypot:', error);
    }
}

async function exportCCTNS() {
    try {
        const response = await fetch(`${API_BASE}/api/threats/export/cctns`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.success) {
            showModal('Export Complete', `CCTNS report saved to: ${data.filepath}`);
        }
    } catch (error) {
        console.error('Failed to export CCTNS:', error);
    }
}

async function exportJSON() {
    try {
        const response = await fetch(`${API_BASE}/api/threats/export/json`, {
            method: 'POST'
        });
        const data = await response.json();
        if (data.success) {
            showModal('Export Complete', `JSON export saved to: ${data.filepath}`);
        }
    } catch (error) {
        console.error('Failed to export JSON:', error);
    }
}

async function viewIntelligence() {
    try {
        const response = await fetch(`${API_BASE}/api/honeypots/intelligence`);
        const data = await response.json();
        if (data.success) {
            const intel = data.data;
            const content = `
                <p><strong>Total Commands Captured:</strong> ${intel.total_commands}</p>
                <p><strong>Unique Commands:</strong> ${intel.unique_commands}</p>
                <p><strong>Credentials Captured:</strong> ${intel.credentials_captured}</p>
                <p><strong>Sessions:</strong> ${intel.sessions.length}</p>
                <h4 style="margin-top: 1rem;">Top Commands:</h4>
                <ul>${intel.top_commands.map(c => `<li>${c[0]} (${c[1]})</li>`).join('')}</ul>
            `;
            showModal('Threat Intelligence', content);
        }
    } catch (error) {
        console.error('Failed to load intelligence:', error);
    }
}

function toggleSimulation() {
    addEvent('info', 'Simulation mode active');
}

// =============================================================================
// UI Helpers
// =============================================================================
function showAlert(message, severity = 'warning') {
    const banner = document.getElementById('alert-banner');
    const messageEl = document.getElementById('alert-message');

    messageEl.textContent = message;
    banner.style.display = 'flex';

    // Auto-hide after 5 seconds
    setTimeout(() => {
        banner.style.display = 'none';
    }, 5000);
}

function closeAlert() {
    document.getElementById('alert-banner').style.display = 'none';
}

function showModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-body').innerHTML = content;
    document.getElementById('modal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('modal').style.display = 'none';
}

// =============================================================================
// Internationalization
// =============================================================================
function t(key) {
    return translations[currentLanguage][key] || key;
}

function setLanguage(lang) {
    currentLanguage = lang;
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = t(key);
    });

    // Update server
    fetch(`${API_BASE}/api/config/language`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language: lang })
    });
}

// =============================================================================
// Event Listeners
// =============================================================================
function setupEventListeners() {
    // Language selector
    document.getElementById('language-select').addEventListener('change', (e) => {
        setLanguage(e.target.value);
    });

    // Close modal on outside click
    document.getElementById('modal').addEventListener('click', (e) => {
        if (e.target.id === 'modal') {
            closeModal();
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
            closeAlert();
        }
    });
}

// =============================================================================
// Auto Refresh
// =============================================================================
function startAutoRefresh() {
    setInterval(() => {
        loadStatus();
        loadDevices();
        loadHoneypots();
    }, REFRESH_INTERVAL);
}
