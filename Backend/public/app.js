// ═══════════════════════════════════════════════════════════════════════════════
//  SENTINEL — Network Command Center — Frontend Logic
// ═══════════════════════════════════════════════════════════════════════════════

// ── State ──────────────────────────────────────
let devices = [];
let selectedDevice = null;
let selectedIdx = -1;
let isMonitoring = false;
let isBlocking = false;
let statsInterval = null;
let trafficInterval = null;

// ── Toast ──────────────────────────────────────
function toast(msg, type) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast show ' + (type || '');
    setTimeout(() => t.className = 'toast', 3500);
}

// ── Terminal Log ───────────────────────────────
function log(msg, level) {
    const term = document.getElementById('terminal');
    if (!term) return;
    const cls = level === 'err' ? 'line-err' : level === 'warn' ? 'line-warn' : 'line-info';
    const time = new Date().toLocaleTimeString();
    term.innerHTML += `<div class="${cls}">[${time}] ${msg}</div>`;
    term.scrollTop = term.scrollHeight;
}

function clearTerminal() {
    const term = document.getElementById('terminal');
    if (term) term.innerHTML = '<div class="line-info">[SENTINEL] Log cleared.</div>';
}

function toggleTerminal() {
    const s = document.getElementById('terminalSection');
    s.style.display = s.style.display === 'none' ? 'block' : 'none';
}

// ── Server Status ──────────────────────────────
async function checkStatus() {
    try {
        const res = await fetch('/api/status');
        if (res.ok) {
            const pill = document.getElementById('statusPill');
            const dot = document.getElementById('statusDot');
            const txt = document.getElementById('statusText');
            pill.className = 'status-pill online';
            dot.className = 'status-dot on';
            txt.textContent = 'Online — Root Active';
            log('Server connected. Root privileges confirmed.', 'info');
            // Auto-scan on first successful connection
            if (devices.length === 0) {
                log('Auto-scanning network...', 'info');
                scanNetwork();
            }
        } else throw new Error('Not OK');
    } catch {
        const pill = document.getElementById('statusPill');
        const dot = document.getElementById('statusDot');
        const txt = document.getElementById('statusText');
        pill.className = 'status-pill offline';
        dot.className = 'status-dot off';
        txt.textContent = 'Offline';
    }
}

// ── Traffic Stats ──────────────────────────────
async function updateTraffic() {
    try {
        const res = await fetch('/api/traffic');
        const d = await res.json();
        document.getElementById('downloadStat').textContent = (d.download_mb || '0') + ' MB';
        document.getElementById('uploadStat').textContent = (d.upload_mb || '0') + ' MB';
        document.getElementById('connStat').textContent = d.connections || '0';
    } catch { }
}

// ── Scan Network ───────────────────────────────
async function scanNetwork() {
    const btn = document.getElementById('scanBtn');
    btn.disabled = true;
    btn.textContent = '⏳ SCANNING...';
    document.getElementById('deviceGrid').innerHTML = `
        <div class="loading">
            <div class="spinner"></div>
            <div>Performing active sweep + ARP discovery...</div>
            <div style="font-size:11px;color:var(--text-dim);margin-top:6px">This may take up to 30 seconds</div>
        </div>`;

    log('Initiating network scan (ping sweep + ARP)...', 'info');

    try {
        const res = await fetch('/api/scan');
        const data = await res.json();

        if (data.status === 'error') {
            throw new Error(data.message || 'Scan failed');
        }

        devices = data.devices || [];
        document.getElementById('deviceCount').textContent = devices.length;
        document.getElementById('subnetStat').textContent = data.subnet || '—';
        document.getElementById('scanMode').textContent = `Mode: ${data.scan_mode || 'passive'} | ${devices.length} devices`;

        renderDevices();
        toast(`Found ${devices.length} devices on network`, 'success');
        log(`Scan complete: ${devices.length} device(s) discovered.`, 'info');

        if (data.database) {
            log(`Database: ${data.database.saved} saved, ${data.database.total_logged} total logged.`, 'info');
        }
    } catch (e) {
        toast('Scan failed: ' + e.message, 'error');
        log('ERROR: Scan failed — ' + e.message, 'err');
        document.getElementById('deviceGrid').innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">❌</div>
                <h3>Scan failed</h3>
                <p>${e.message}. Make sure the server is running with sudo.</p>
            </div>`;
    } finally {
        btn.disabled = false;
        btn.textContent = '⚡ Scan Network';
    }
}

// ── Device Icons ───────────────────────────────
function getDeviceIcon(d) {
    const name = ((d.hostname || '') + ' ' + (d.vendor || '') + ' ' + (d.type || '')).toLowerCase();
    if (/apple|iphone|ipad|macbook|imac/.test(name)) return '🍎';
    if (/android|samsung|galaxy|xiaomi|oppo|vivo|huawei|mobile/.test(name)) return '📱';
    if (/google|pixel|nest|chromecast/.test(name)) return '🔵';
    if (/router|gateway|netgear|tp-link|linksys|cisco|networking/.test(name)) return '📡';
    if (/amazon|alexa|echo|ring/.test(name)) return '🔶';
    if (/printer|canon|epson|brother/.test(name)) return '🖨️';
    if (/camera|hikvision|dahua|wyze|arlo/.test(name)) return '📹';
    if (/tv|roku|fire|media|sonos|nvidia/.test(name)) return '📺';
    if (/pc|laptop|dell|lenovo|hp|intel|windows/.test(name)) return '💻';
    if (/gaming|playstation|xbox|nintendo/.test(name)) return '🎮';
    if (/raspberry|pi|arduino|dev board/.test(name)) return '🔧';
    if (/tesla/.test(name)) return '🚗';
    if (/iot|espressif|tuya|shelly|smart/.test(name)) return '💡';
    if (/privacy|random/.test(name)) return '🔒';
    return '🖥️';
}

// ── Render Devices ─────────────────────────────
function renderDevices() {
    const grid = document.getElementById('deviceGrid');
    if (!devices.length) {
        grid.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📡</div>
                <h3>No devices found</h3>
                <p>Try scanning again. Make sure the server is running with <strong>sudo</strong>.</p>
            </div>`;
        return;
    }

    grid.innerHTML = devices.map((d, i) => {
        const isRandom = (d.type || '').toLowerCase().includes('random');
        return `
        <div class="device-card ${d._blocked ? 'blocked' : ''} ${d._monitoring ? 'monitoring' : ''}" onclick="openDevice(${i})">
            <div class="device-header">
                <div class="device-info">
                    <div class="device-icon">${getDeviceIcon(d)}</div>
                    <div>
                        <div class="device-name">${d.hostname && d.hostname !== 'Unknown' ? d.hostname : (d.vendor && d.vendor !== 'Unknown' ? d.vendor : 'Unknown Device')}</div>
                        <div class="device-type">${d.type || 'Unknown'}</div>
                    </div>
                </div>
                <span class="device-ip">${d.ip}</span>
            </div>
            <div class="device-meta">
                <span class="device-mac">${d.mac}</span>
                <span class="badge badge-online">ONLINE</span>
                ${d._blocked ? '<span class="badge badge-blocked">⛔ BLOCKED</span>' : ''}
                ${d._monitoring ? '<span class="badge badge-monitoring">📡 MONITORING</span>' : ''}
                ${isRandom ? '<span class="badge badge-random">🔒 RANDOM MAC</span>' : ''}
            </div>
        </div>`;
    }).join('');
}

// ── Open Device Panel ──────────────────────────
function openDevice(idx) {
    selectedDevice = devices[idx];
    selectedIdx = idx;

    document.getElementById('panelName').textContent = selectedDevice.hostname && selectedDevice.hostname !== 'Unknown' ? selectedDevice.hostname : (selectedDevice.vendor || 'Unknown Device');
    document.getElementById('panelType').textContent = selectedDevice.type || 'Unknown Device';
    document.getElementById('panelIP').textContent = selectedDevice.ip;
    document.getElementById('panelMAC').textContent = selectedDevice.mac;
    document.getElementById('panelVendor').textContent = selectedDevice.vendor || 'Unknown';
    document.getElementById('panelHost').textContent = selectedDevice.hostname || 'Unknown';
    document.getElementById('panelClass').textContent = selectedDevice.type || 'Unknown Device';

    isMonitoring = !!selectedDevice._monitoring;
    isBlocking = !!selectedDevice._blocked;
    updateMonitorUI();
    updateBlockUI();

    // Reset port scan
    document.getElementById('portList').className = 'port-list';
    document.getElementById('portList').innerHTML = '';

    document.getElementById('overlay').classList.add('active');
    document.getElementById('detailPanel').classList.add('active');

    log(`Opened device panel: ${selectedDevice.ip} (${selectedDevice.vendor || 'Unknown'})`, 'info');
}

function closePanel() {
    document.getElementById('overlay').classList.remove('active');
    document.getElementById('detailPanel').classList.remove('active');
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
}

// ── Monitor ────────────────────────────────────
async function toggleMonitor() {
    if (!selectedDevice) return;
    if (isBlocking) { toast('Stop blocking first', 'error'); return; }

    const btn = document.getElementById('monitorBtn');
    btn.disabled = true;

    try {
        if (isMonitoring) {
            await fetch('/api/mitm/stop', { method: 'POST' });
            isMonitoring = false;
            selectedDevice._monitoring = false;
            if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
            toast('Monitoring stopped', 'success');
            log(`Stopped monitoring ${selectedDevice.ip}`, 'warn');
        } else {
            const res = await fetch('/api/mitm/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: selectedDevice.ip })
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            isMonitoring = true;
            selectedDevice._monitoring = true;
            toast('ARP Spoofing + Traffic Monitor active', 'success');
            log(`Started ARP monitoring on ${selectedDevice.ip}`, 'info');
            statsInterval = setInterval(pollMitmStats, 2000);
        }
    } catch (e) {
        toast('Monitor error: ' + e.message, 'error');
        log('Monitor ERROR: ' + e.message, 'err');
    }

    updateMonitorUI();
    renderDevices();
    btn.disabled = false;
}

async function pollMitmStats() {
    try {
        const res = await fetch('/api/mitm/stats');
        const d = await res.json();
        if (!d.error) {
            document.getElementById('mitmDown').textContent = ((d.download_bytes || 0) / 1024 / 1024).toFixed(2) + ' MB';
            document.getElementById('mitmUp').textContent = ((d.upload_bytes || 0) / 1024 / 1024).toFixed(2) + ' MB';

            const list = document.getElementById('sitesList');
            if (d.recent_sites && d.recent_sites.length) {
                list.innerHTML = d.recent_sites.map(s => `
                    <div class="site-row">
                        <span class="site-time">${new Date(s.timestamp * 1000).toLocaleTimeString()}</span>
                        <span class="site-domain">${s.domain}</span>
                    </div>
                `).join('');
            }
        }
    } catch { }
}

function updateMonitorUI() {
    const btn = document.getElementById('monitorBtn');
    const stats = document.getElementById('monitorStats');
    if (isMonitoring) {
        btn.innerHTML = '⏹ Stop Monitoring';
        btn.classList.add('active');
        stats.classList.add('active');
    } else {
        btn.innerHTML = '▶ Start Monitoring';
        btn.classList.remove('active');
        stats.classList.remove('active');
    }
}

// ── Block ──────────────────────────────────────
async function toggleBlock() {
    if (!selectedDevice) return;
    if (isMonitoring) { toast('Stop monitoring first', 'error'); return; }

    const btn = document.getElementById('blockBtn');
    btn.disabled = true;

    try {
        if (isBlocking) {
            await fetch('/api/block/stop', { method: 'POST' });
            isBlocking = false;
            selectedDevice._blocked = false;
            toast('Device unblocked', 'success');
            log(`Unblocked ${selectedDevice.ip}`, 'warn');
        } else {
            const res = await fetch('/api/block/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: selectedDevice.ip })
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            isBlocking = true;
            selectedDevice._blocked = true;
            toast('⛔ Device internet BLOCKED', 'success');
            log(`BLOCKED internet for ${selectedDevice.ip}`, 'err');
        }
    } catch (e) {
        toast('Block error: ' + e.message, 'error');
        log('Block ERROR: ' + e.message, 'err');
    }

    updateBlockUI();
    renderDevices();
    btn.disabled = false;
}

function updateBlockUI() {
    const btn = document.getElementById('blockBtn');
    if (isBlocking) {
        btn.innerHTML = '🔓 Unblock Device';
        btn.classList.add('active');
    } else {
        btn.innerHTML = '🚫 Block Internet Access';
        btn.classList.remove('active');
    }
}

// ── Deep Port Scan ─────────────────────────────
async function deepScan() {
    if (!selectedDevice) return;

    const btn = document.getElementById('inspectBtn');
    const list = document.getElementById('portList');
    btn.disabled = true;
    btn.textContent = '⏳ Scanning Ports...';
    list.className = 'port-list active';
    list.innerHTML = '<div style="padding:12px;color:var(--text-dim);font-size:12px;text-align:center">Scanning 20 critical ports...</div>';

    log(`Deep scanning ${selectedDevice.ip}...`, 'info');

    try {
        const res = await fetch(`/api/inspect?ip=${selectedDevice.ip}`);
        const data = await res.json();

        if (data.error) throw new Error(data.error);

        if (data.open_ports && data.open_ports.length > 0) {
            list.innerHTML = `
                <div style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
                    <span style="font-family:var(--font-mono);font-size:11px;color:var(--text-dim)">${data.open_ports.length} open port(s)</span>
                    <span class="risk-badge risk-${data.risk_level}">${data.risk_level}</span>
                </div>
                ${data.open_ports.map(p => `
                    <div class="port-entry">
                        <span class="port-num">:${p.port}</span>
                        <span class="port-banner">${p.banner || 'No banner'}</span>
                    </div>
                `).join('')}
            `;
            log(`Port scan: ${data.open_ports.length} port(s) open, risk: ${data.risk_level}`, data.risk_level === 'CRITICAL' ? 'err' : 'warn');
        } else {
            list.innerHTML = '<div style="padding:12px;color:var(--success);font-size:12px;text-align:center">✅ No open ports found (stealth mode)</div>';
            log(`Port scan: No open ports on ${selectedDevice.ip}`, 'info');
        }

        toast(`Scan complete: ${(data.open_ports || []).length} ports found`, 'success');
    } catch (e) {
        list.innerHTML = `<div style="padding:12px;color:var(--danger);font-size:12px;text-align:center">❌ ${e.message}</div>`;
        toast('Port scan failed: ' + e.message, 'error');
        log('Port scan ERROR: ' + e.message, 'err');
    }

    btn.disabled = false;
    btn.textContent = '🔍 Deep Port Scan';
}

// ── Init ───────────────────────────────────────
checkStatus();
updateTraffic();
trafficInterval = setInterval(updateTraffic, 15000);
setInterval(checkStatus, 30000);
