// ═══════════════════════════════════════════════════════════════════════════════
//  SENTINEL CLIENT — v3.0
// ═══════════════════════════════════════════════════════════════════════════════

let scanInterval = null;
let currentDevices = [];
let monitorInterval = null;

// ── INIT ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    log('System initialized. Ready.');
    updateStats();
    scanNetwork(); // Auto-scan on load

    // Auto-refresh stats every 5s
    setInterval(updateStats, 5000);
});

// ── NAVIGATION ────────────────────────────────────────────────────────────────
function switchTab(tabId) {
    // Hide all sections
    document.querySelectorAll('.view-section').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));

    // Show selected section
    const target = document.getElementById(`view-${tabId}`);
    if (target) {
        target.style.display = 'block';
        setTimeout(() => target.classList.add('active'), 10);
    }

    // Update Sidebar Active State
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

    const navItem = document.getElementById(`nav-${tabId}`);
    if (navItem) navItem.classList.add('active');

    // If switching to targets, refresh the target list
    if (tabId === 'targets') {
        renderTargets();
    }
}

// ── API CALLS ─────────────────────────────────────────────────────────────────

async function scanNetwork() {
    const statusEl = document.getElementById('scanStatus');
    const gridEl = document.getElementById('deviceGrid');

    if (statusEl) statusEl.innerText = 'SCANNING...';
    if (statusEl) statusEl.className = 'badge warning';

    log('Initiating active network scan...');

    try {
        const response = await fetch('/api/scan');
        const data = await response.json();

        if (data.status === 'success') {
            currentDevices = data.devices;
            renderDevices(data.devices);
            renderTargets(); // Also update targets list
            renderRadar(data.devices); // Update Radar

            document.getElementById('deviceCount').innerText = data.count;
            document.getElementById('subnetInfo').innerText = data.subnet;

            if (statusEl) statusEl.innerText = 'IDLE';
            if (statusEl) statusEl.className = 'badge';
            log(`Scan complete. ${data.count} devices found.`);
        } else {
            throw new Error(data.message || 'Unknown error');
        }
    } catch (error) {
        console.error('Scan Error:', error);
        log(`Scan failed: ${error.message}`);
        if (statusEl) statusEl.innerText = 'ERROR';
        if (statusEl) statusEl.className = 'badge danger';
    }
}

async function updateStats() {
    try {
        const response = await fetch('/api/traffic');
        const stats = await response.json();

        if (stats.error) return;

        document.getElementById('uploadStats').innerText = stats.upload_mb + ' MB';
        document.getElementById('downloadStats').innerText = stats.download_mb + ' MB';
        document.getElementById('connectionCount').innerText = stats.connections;
    } catch (e) {
        console.error('Stats error:', e);
    }
}

// ── RENDERING ─────────────────────────────────────────────────────────────────

function renderDevices(devices) {
    const grid = document.getElementById('deviceGrid');
    grid.innerHTML = '';

    if (devices.length === 0) {
        grid.innerHTML = '<div class="empty-state">No devices found. Try rescanning.</div>';
        return;
    }

    devices.forEach(device => {
        const card = createDeviceCard(device);
        grid.appendChild(card);
    });
}

// ── RADAR VISUALIZATION ──────────────────────────────────────────────────────
function renderRadar(devices) {
    const canvas = document.getElementById('radarCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.parentElement.offsetWidth;
    const height = canvas.parentElement.offsetHeight;

    // Set canvas resolution
    canvas.width = width;
    canvas.height = height;

    const cx = width / 2;
    const cy = height / 2;
    const maxRadius = Math.min(width, height) / 2 - 20;

    // Clear
    ctx.clearRect(0, 0, width, height);

    // Draw Grid Concentric Circles
    ctx.strokeStyle = 'rgba(0, 212, 255, 0.2)';
    ctx.lineWidth = 1;
    [0.3, 0.6, 0.9].forEach(scale => {
        ctx.beginPath();
        ctx.arc(cx, cy, maxRadius * scale, 0, Math.PI * 2);
        ctx.stroke();
    });

    // Draw Crosshairs
    ctx.beginPath();
    ctx.moveTo(cx, cy - maxRadius);
    ctx.lineTo(cx, cy + maxRadius);
    ctx.moveTo(cx - maxRadius, cy);
    ctx.lineTo(cx + maxRadius, cy);
    ctx.stroke();

    // Draw Sweep (Animated by separate loop, or static for now)
    // For now, let's just plot devices

    devices.forEach((device, index) => {
        // Signal Quality 0-100. Stronger = Closer to center.
        // Default to 50 if missing (middle ring)
        const signal = device.signal_quality || 50;

        // Invert: 100% signal -> 0 distance (center)
        // 0% signal -> maxRadius distance
        const distance = maxRadius * (1 - (signal / 110));

        // Random angle (seeded by IP for stability would be better, but random is okay for scan refresh)
        // Let's rely on index to spread them out somewhat evenly if stable
        const angle = (index / devices.length) * Math.PI * 2 + (Date.now() / 10000); // Verify rotation? No, keep stable.

        // Use hash of IP for stable angle
        const ipSum = device.ip.split('.').reduce((a, b) => a + parseInt(b), 0);
        const stableAngle = (ipSum % 360) * (Math.PI / 180);

        const x = cx + Math.cos(stableAngle) * distance;
        const y = cy + Math.sin(stableAngle) * distance;

        // Draw Blip
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, Math.PI * 2);
        ctx.fillStyle = signal > 70 ? '#00d4ff' : (signal > 40 ? '#ffd700' : '#ff4444');
        ctx.fill();

        // Glow
        ctx.shadowBlur = 10;
        ctx.shadowColor = ctx.fillStyle;

        // Label (IP)
        ctx.shadowBlur = 0;
        ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
        ctx.font = '10px monospace';
        ctx.fillText(device.ip.split('.').pop(), x + 8, y + 3);
    });
}

function renderTargets() {
    const grid = document.getElementById('targetGrid');
    grid.innerHTML = '';

    // Filter devices that have a custom name
    const targets = currentDevices.filter(d => d.name);

    if (targets.length === 0) {
        grid.innerHTML = '<div class="empty-state">No named targets yet. Rename a device to pin it here.</div>';
        return;
    }

    targets.forEach(device => {
        const card = createDeviceCard(device);
        grid.appendChild(card);
    });
}

function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';
    card.onclick = () => openDeviceModal(device);

    const isRandom = device.type === 'Privacy-Randomized MAC';
    const icon = getIconForType(device.type);

    // Display Name: Custom Name (if set) > Hostname > Vendor > "Unknown"
    const displayName = device.name || device.hostname || device.vendor || 'Unknown Device';
    const subText = device.name ? (device.hostname || device.vendor) : (device.vendor || device.type);

    card.innerHTML = `
        <div class="ip-badge">${device.ip}</div>
        <div class="header">
            <div class="device-icon">${icon}</div>
            <div class="device-details">
                <h3>${displayName}</h3>
                <p>${subText}</p>
                <p style="font-family: monospace; opacity: 0.7;">${device.mac}</p>
            </div>
        </div>
        <div class="meta-tags">
            <span class="tag online">ONLINE</span>
            ${isRandom ? '<span class="tag random">RANDOM MAC</span>' : ''}
            <span class="tag apple">${device.vendor || 'Unknown'}</span>
        </div>
    `;
    return card;
}

function getIconForType(type) {
    if (type.includes('Apple')) return '';
    if (type.includes('Android') || type.includes('Mobile')) return '📱';
    if (type.includes('PC') || type.includes('Laptop')) return '💻';
    if (type.includes('IoT') || type.includes('Amazon')) return '🏠';
    if (type.includes('Router') || type.includes('Network')) return '🌐';
    if (type.includes('Game') || type.includes('Console')) return '🎮';
    if (type.includes('Camera')) return '📷';
    if (type.includes('Printer')) return '🖨️';
    return '🔌';
}

// ── MODAL & ACTIONS ───────────────────────────────────────────────────────────

let selectedDevice = null;

function openDeviceModal(device) {
    selectedDevice = device;
    document.getElementById('modalTitle').innerText = device.name || device.hostname || device.vendor || 'Unknown Device';
    document.getElementById('modalIp').innerText = device.ip;
    document.getElementById('modalMac').innerText = device.mac;
    document.getElementById('modalVendor').innerText = device.vendor;

    // Set verify rename input value
    document.getElementById('renameInput').value = device.name || '';

    document.getElementById('modalConsole').innerText = `Target selected: ${device.ip}\nWaiting for command...`;

    const modal = document.getElementById('deviceModal');
    modal.style.display = 'flex';
}

function closeModal() {
    document.getElementById('deviceModal').style.display = 'none';
    selectedDevice = null;
}

// Close modal when clicking outside
window.onclick = function (event) {
    const modal = document.getElementById('deviceModal');
    if (event.target === modal) {
        closeModal();
    }
}

// ── ACTION LOGIC ──────────────────────────────────────────────────────────────

async function saveDeviceName() {
    if (!selectedDevice) return;

    const name = document.getElementById('renameInput').value.trim();
    if (!name) return alert('Please enter a name');

    log(`Renaming ${selectedDevice.mac} to "${name}"...`);

    try {
        const res = await fetch('/api/device/rename', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac: selectedDevice.mac, name })
        });
        const data = await res.json();

        if (data.status === 'success') {
            log(`Success: Device renamed to ${name}`);
            closeModal();
            scanNetwork(); // Refresh to update list
        } else {
            alert('Failed: ' + data.error);
        }
    } catch (e) {
        console.error(e);
        log('Error renaming device.');
    }
}

let inspectorInterval = null;

async function startMitm() {
    if (!selectedDevice) return;
    const ip = selectedDevice.ip;
    log(`Starting MITM on ${ip}...`);
    appendToConsole(`> INITIATING ARP SPOOFING ON ${ip}...`);

    try {
        const res = await fetch('/api/mitm/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, duration: 60 })
        });
        const data = await res.json();
        if (data.error) {
            appendToConsole(`ERROR: ${data.error}`);
        } else {
            appendToConsole(`SUCCESS: Traffic interception active.\nGateway: ${data.gateway}`);
            log(`MITM active. Switching to Inspector...`);

            // Auto-switch to Targets tab and show Inspector
            switchTab('targets');
            showInspector(selectedDevice);
            closeModal();
        }
    } catch (e) {
        appendToConsole(`Connection Error: ${e.message}`);
    }
}

function showInspector(device) {
    const panel = document.getElementById('inspectorPanel');
    panel.style.display = 'block';
    document.getElementById('inspectorName').innerText = device.name || device.hostname || device.vendor;
    document.getElementById('inspectorIp').innerText = device.ip;

    // Start Polling
    if (inspectorInterval) clearInterval(inspectorInterval);
    inspectorInterval = setInterval(updateInspector, 2000);
}

async function updateInspector() {
    try {
        const res = await fetch('/api/mitm/details');
        const data = await res.json();

        if (data.error) return; // No active monitor

        // Update Bandwidth
        // Simple diff logic or raw values? 
        // The python script saves CUMULATIVE bytes. We need rate?
        // For now just show total transferred or raw bytes.
        // Let's show TOTAL for now.
        document.getElementById('inspUp').innerText = formatBytes(data.upload_bytes);
        document.getElementById('inspDown').innerText = formatBytes(data.download_bytes);

        // Update Domains
        const domainList = document.getElementById('inspDomains');
        if (data.recent_sites && data.recent_sites.length > 0) {
            domainList.innerHTML = data.recent_sites.map(site => `
                <div class="domain-item">
                    <span class="time">${new Date(site.timestamp * 1000).toLocaleTimeString()}</span>
                    <span class="url" title="${site.url || site.domain}">${site.url || site.domain}</span>
                </div>
            `).join('');
        }

        // Update Images
        const imageList = document.getElementById('inspImages');
        if (data.captured_images && data.captured_images.length > 0) {
            imageList.innerHTML = data.captured_images.map(img => `
                <div class="media-item" onclick="window.open('/captured_images/${img.filename}', '_blank')">
                    <img src="/captured_images/${img.filename}" loading="lazy">
                </div>
            `).join('');
        } else {
            imageList.innerHTML = '<div class="empty-media">No images captured yet. Browse non-secure sites.</div>';
        }

        // Update Footprint
        updateFootprint();

    } catch (e) { console.error(e); }
}

function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '< 1s';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

async function updateFootprint() {
    if (!selectedDevice) return;
    try {
        const res = await fetch(`/api/footprint?ip=${selectedDevice.ip}`);
        const fp = await res.json();

        const footprintEl = document.getElementById('inspHistory');
        if (!footprintEl) return;

        const domains = fp.domains || {};
        const domainKeys = Object.keys(domains);

        if (domainKeys.length === 0) {
            footprintEl.innerHTML = '<div class="empty-media">No footprint data yet. Waiting for activity...</div>';
            return;
        }

        // Sort by last_seen (most recent first)
        domainKeys.sort((a, b) => (domains[b].last_seen || 0) - (domains[a].last_seen || 0));

        // Summary stats
        const totalBytes = fp.total_bytes || 0;
        const totalDomains = domainKeys.length;
        const sessions = (fp.sessions || []).length;

        let html = `
            <div class="fp-summary">
                <span>📊 <b>${totalDomains}</b> domains</span>
                <span>💾 <b>${formatBytes(totalBytes)}</b> total</span>
                <span>📋 <b>${sessions}</b> sessions</span>
            </div>
        `;

        html += domainKeys.map(domain => {
            const d = domains[domain];
            const duration = d.last_seen && d.first_seen
                ? formatDuration(d.last_seen - d.first_seen)
                : '-';
            const lastSeen = d.last_seen
                ? new Date(d.last_seen * 1000).toLocaleTimeString()
                : '-';
            const bytes = formatBytes(d.bytes_total || 0);
            const visits = d.visit_count || 0;

            // Show URLs if available
            let urlsHtml = '';
            if (d.urls && d.urls.length > 0) {
                const urlItems = d.urls.slice(0, 3).map(u =>
                    `<div class="fp-url">${u.url}</div>`
                ).join('');
                urlsHtml = `<div class="fp-urls">${urlItems}</div>`;
            }

            return `
                <div class="fp-domain-card">
                    <div class="fp-domain-header">
                        <span class="fp-domain-name">🌐 ${domain}</span>
                        <span class="fp-domain-visits">${visits}×</span>
                    </div>
                    <div class="fp-domain-stats">
                        <span>⏱ ${duration}</span>
                        <span>💾 ${bytes}</span>
                        <span>🕐 ${lastSeen}</span>
                    </div>
                    ${urlsHtml}
                </div>
            `;
        }).join('');

        footprintEl.innerHTML = html;
    } catch (e) { console.error(e); }
}

async function stopMitm() {
    try {
        await fetch('/api/mitm/stop', { method: 'POST' });
        clearInterval(inspectorInterval);
        document.getElementById('inspectorPanel').style.display = 'none';
        log('Monitoring stopped.');
    } catch (e) { log('Error stopping MITM'); }
}

function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

async function blockInternet() {
    if (!selectedDevice) return;
    const ip = selectedDevice.ip;
    log(`Blocking internet for ${ip}...`);
    appendToConsole(`> CUTTING CONNECTION TO ${ip}...`);

    try {
        const res = await fetch('/api/block/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (data.error) {
            appendToConsole(`ERROR: ${data.error}`);
        } else {
            appendToConsole(`SUCCESS: Target isolated from gateway.`);
            log(`Block active on ${ip}`);
        }
    } catch (e) {
        appendToConsole(`Connection Error: ${e.message}`);
    }
}

async function deepScan() {
    if (!selectedDevice) return;
    const ip = selectedDevice.ip;
    log(`Deep scanning ${ip}...`);
    appendToConsole(`> RUNNING NMAP-STYLE SCAN ON ${ip}...`);
    appendToConsole(`> Please wait (approx 10-20s)...`);

    try {
        const res = await fetch(`/api/inspect?ip=${ip}`);
        const data = await res.json();

        if (data.error) {
            appendToConsole(`ERROR: ${data.error}`);
        } else {
            const ports = data.ports ? data.ports.join(', ') : 'None';
            appendToConsole(`SCAN COMPLETE.\nOpen Ports: ${ports}\nOS Hint: ${data.os || 'Unknown'}`);
            log(`Scan complete for ${ip}`);
        }
    } catch (e) {
        appendToConsole(`Scan Error: ${e.message}`);
    }
}

function appendToConsole(text) {
    const consoleBox = document.getElementById('modalConsole');
    consoleBox.innerText += '\n' + text;
    consoleBox.scrollTop = consoleBox.scrollHeight;
}

// ── LOGGING ───────────────────────────────────────────────────────────────────

function log(msg) {
    const logBox = document.querySelector('.terminal-window');
    const entry = document.createElement('div');
    entry.className = 'log-line';
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `<span class="timestamp">[${time}]</span> ${msg}`;

    // Append to actual log container inside window in index.html
    const container = document.getElementById('activityLog');
    if (container) {
        container.appendChild(entry);
        if (container.parentElement) container.parentElement.scrollTop = container.parentElement.scrollHeight;
    }
}


function clearLogs() {
    const container = document.getElementById('activityLog');
    if (container) container.innerHTML = '';
}

// ── GLOBAL FOOTPRINT VIEW ─────────────────────────────────────────────────────
async function renderGlobalFootprint() {
    const container = document.getElementById('footprintContainer');
    if (!container) return;

    container.innerHTML = '<div class="empty-state">Loading network history...</div>';

    try {
        const res = await fetch('/api/footprint');
        const db = await res.json();
        const devices = Object.keys(db);

        if (devices.length === 0) {
            container.innerHTML = '<div class="empty-state">No network history recorded yet.</div>';
            return;
        }

        // Sort by total bytes (most active top)
        devices.sort((a, b) => (db[b].total_bytes || 0) - (db[a].total_bytes || 0));

        let html = '';

        devices.forEach(ip => {
            const data = db[ip];
            const domains = data.domains || {};
            const domainKeys = Object.keys(domains);

            // Sort domains by visits
            domainKeys.sort((a, b) => (domains[b].visit_count || 0) - (domains[a].visit_count || 0));
            const topDomains = domainKeys.slice(0, 5);

            html += `
                <div class="device-card" style="cursor: default;">
                    <div class="header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'" style="cursor: pointer;">
                        <div class="ip-badge">${ip}</div>
                        <div class="device-details">
                            <h3>${data.hostname || 'Unknown Device'}</h3>
                            <p>${domainKeys.length} domains • ${formatBytes(data.total_bytes)} • Last seen ${new Date((data.last_seen || 0) * 1000).toLocaleTimeString()}</p>
                        </div>
                        <div class="device-icon">▼</div>
                    </div>
                    
                    <div class="fp-details" style="display:none; padding-top:15px; border-top:1px solid rgba(255,255,255,0.1); margin-top:10px;">
                        ${domainKeys.length > 0 ? domainKeys.map(d => {
                const domain = domains[d];
                return `
                                <div class="fp-domain-card">
                                    <div class="fp-domain-header">
                                        <span class="fp-domain-name">🌐 ${d}</span>
                                        <span class="fp-domain-visits">${domain.visit_count}×</span>
                                    </div>
                                    <div class="fp-domain-stats">
                                        <span>⏱ ${formatDuration((domain.last_seen || 0) - (domain.first_seen || 0))}</span>
                                        <span>💾 ${formatBytes(domain.bytes_total)}</span>
                                    </div>
                                </div>
                            `;
            }).join('') : '<div class="empty-media">No domains recorded.</div>'}
                        
                        <div style="margin-top:10px; text-align:right;">
                            <span class="btn btn-secondary" onclick="window.open('/api/footprint?ip=${ip}', '_blank')" style="font-size:10px;">VIEW RAW JSON</span>
                        </div>
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;

    } catch (e) {
        console.error(e);
        container.innerHTML = `<div class="empty-state">Error loading footprint: ${e.message}</div>`;
    }
}
