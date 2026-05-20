let API_BASE = 'http://localhost:8001';
let API_KEY = '';

// Load settings from storage
if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['apiBaseUrl', 'apiKey'], (result) => {
        if (result.apiBaseUrl) {
            API_BASE = result.apiBaseUrl;
            if (document.getElementById('api-url-input')) {
                document.getElementById('api-url-input').value = API_BASE;
            }
        }
        if (result.apiKey) {
            API_KEY = result.apiKey;
            if (document.getElementById('api-key-input')) {
                document.getElementById('api-key-input').value = API_KEY;
            }
        }
        checkStatus();
    });
}

// Settings logic
const settingsBtn = document.getElementById('settings-btn');
const closeSettingsBtn = document.getElementById('close-settings-btn');
const settingsModal = document.getElementById('settings-modal');
const apiUrlInput = document.getElementById('api-url-input');
const apiKeyInput = document.getElementById('api-key-input');

if (settingsBtn) settingsBtn.addEventListener('click', () => settingsModal.style.display = 'block');
if (closeSettingsBtn) closeSettingsBtn.addEventListener('click', () => settingsModal.style.display = 'none');

if (apiUrlInput) {
    apiUrlInput.addEventListener('change', (e) => {
        let val = e.target.value.trim();
        if(val.endsWith('/')) val = val.slice(0, -1);
        API_BASE = val || 'http://localhost:8001';
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({apiBaseUrl: API_BASE});
        }
        checkStatus();
    });
}

if (apiKeyInput) {
    apiKeyInput.addEventListener('change', (e) => {
        API_KEY = e.target.value.trim();
        if (typeof chrome !== 'undefined' && chrome.storage) {
            chrome.storage.local.set({apiKey: API_KEY});
        }
    });
}

function getApiUrl() { return API_BASE + '/api/scan'; }
function getHealthUrl() { return API_BASE + '/health'; }

// History logic
const historyBtn = document.getElementById('history-btn');
const closeHistoryBtn = document.getElementById('close-history-btn');
const historyModal = document.getElementById('history-modal');
const historyList = document.getElementById('history-list');

if (historyBtn) historyBtn.addEventListener('click', () => {
    if(settingsModal) settingsModal.style.display = 'none';
    if(historyModal) historyModal.style.display = 'block';
    loadHistory();
});
if (closeHistoryBtn) closeHistoryBtn.addEventListener('click', () => historyModal.style.display = 'none');

function loadHistory() {
    if (typeof chrome === 'undefined' || !chrome.storage) return;
    chrome.storage.local.get(['scanHistory'], (result) => {
        const history = result.scanHistory || [];
        if (history.length === 0) {
            historyList.innerHTML = '<div style="color: var(--text-dim); text-align: center;">No history yet.</div>';
            return;
        }
        historyList.innerHTML = '';
        history.forEach(item => {
            const div = document.createElement('div');
            div.style.cssText = 'background: rgba(255,255,255,0.05); padding: 8px; border-radius: 4px; cursor: pointer; border: 1px solid transparent;';
            div.innerHTML = `<strong>${item.target}</strong> <span style="color: var(--text-dim); float: right;">${new Date(item.timestamp).toLocaleString()}</span>`;
            div.addEventListener('mouseover', () => div.style.borderColor = 'var(--primary)');
            div.addEventListener('mouseout', () => div.style.borderColor = 'transparent');
            div.addEventListener('click', () => {
                outputEl.innerHTML = parseOutputText(item.output);
                historyModal.style.display = 'none';
            });
            historyList.appendChild(div);
        });
    });
}

// ── CVE Parsing ──
function parseOutputText(text) {
    const div = document.createElement('div');
    div.textContent = text;
    let escaped = div.innerHTML;
    // Matches CVE-2023-1234, CVE 2023 1234, cve-2023-1234
    escaped = escaped.replace(/CVE[-\s]?(\d{4})[-\s]?(\d{4,7})/gi, (match, year, id) => {
        const cveId = `CVE-${year}-${id}`;
        return `<a href="https://nvd.nist.gov/vuln/detail/${cveId}" target="_blank" style="color: #60a5fa; text-decoration: underline;">${match}</a>`;
    });
    return escaped;
}

// ── All named text inputs (maps HTML name → API field) ──
const TEXT_INPUTS = [
    'idle_zombie','scan_flags','dns_servers','iR','exclude',
    'port_range','top_ports','script','mtu','decoy','source_port',
    'data_length','spoof_mac','interface','custom_flags',
    'ttl','min_parallelism','max_parallelism','min_hostgroup','max_hostgroup',
    'max_rtt_timeout','initial_rtt_timeout','max_retries','host_timeout',
    'scan_delay','max_scan_delay','min_rate','max_rate',
    // New fields
    'version_intensity','out_normal','out_xml','out_grep','out_all','stats_every'
];

// ── Checkbox name → API field ──
const CHECKBOXES = [
    'syn_scan','tcp_connect','udp_scan','null_scan','fin_scan','xmas_scan',
    'ack_scan','window_scan','ip_protocol_scan','rpc_scan','ipv6','aggressive_scan',
    'ping_sweep','no_ping','syn_ping','ack_ping','udp_ping','sctp_ping',
    'icmp_echo','icmp_timestamp','icmp_mask','ip_proto_ping','arp_ping',
    'traceroute','force_rdns','disable_rdns','system_dns','list_scan',
    'service_detection','version_trace','os_detection','os_scan_guess','script_scan','script_trace',
    'fast_scan','all_ports','sequential',
    'fragment','badsum','randomize_hosts','send_eth','send_ip','defeat_rst',
    'verbose','debug','reason','open_only','packet_trace','iflist'
];

// Map HTML input name to flag string for live CMD preview
const FLAG_MAP = {};
document.querySelectorAll('input[data-flag]').forEach(el => {
    FLAG_MAP[el.name] = el.getAttribute('data-flag');
});

const outputEl  = document.getElementById('output');
const cmdText   = document.getElementById('cmd-text');
const apiStatus = document.getElementById('api-status');
const statusTxt = document.getElementById('status-text');
const scanBtn   = document.getElementById('scan-btn');
const clearBtn  = document.getElementById('clear-btn');
const copyBtn   = document.getElementById('copy-btn');
const targetEl  = document.getElementById('target');

// ── Accordions ──
document.querySelectorAll('.accordion-header').forEach(btn => {
    btn.addEventListener('click', () => {
        btn.closest('.accordion').classList.toggle('open');
    });
});

// ── Quick-fill: Port presets ──
document.querySelectorAll('.qbtn[data-port]').forEach(btn => {
    btn.addEventListener('click', () => {
        const portInput = document.querySelector('input[name="port_range"]');
        if (portInput) {
            portInput.value = btn.getAttribute('data-port');
            // Uncheck "All Ports" checkbox since we're specifying a range
            const allPortsCb = document.querySelector('input[name="all_ports"]');
            if (allPortsCb) allPortsCb.checked = false;
            document.querySelectorAll('.qbtn[data-port]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            buildPreview();
        }
    });
});

// ── Quick-fill: Top ports presets ──
document.querySelectorAll('.qbtn[data-topport]').forEach(btn => {
    btn.addEventListener('click', () => {
        const topInput = document.querySelector('input[name="top_ports"]');
        if (topInput) {
            topInput.value = btn.getAttribute('data-topport');
            document.querySelectorAll('.qbtn[data-topport]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            buildPreview();
        }
    });
});

// ── Quick-fill: Script categories / names ──
document.querySelectorAll('.qbtn[data-script]').forEach(btn => {
    btn.addEventListener('click', () => {
        const scriptInput = document.getElementById('script_input') || document.querySelector('input[name="script"]');
        if (!scriptInput) return;
        const val = btn.getAttribute('data-script');
        const cur = scriptInput.value.trim();
        // Toggle: if already in the list, remove it; otherwise append
        const parts = cur ? cur.split(',').map(s => s.trim()) : [];
        const idx = parts.indexOf(val);
        if (idx > -1) {
            parts.splice(idx, 1);
            btn.classList.remove('active');
        } else {
            parts.push(val);
            btn.classList.add('active');
        }
        scriptInput.value = parts.filter(Boolean).join(',');
        buildPreview();
    });
});

// ── Profiles ──
const PROFILES = {
    intense: { timing: '4', aggressive_scan: true, verbose: true },
    quick:   { timing: '4', fast_scan: true },
    ping:    { ping_sweep: true },
    vuln:    { timing: '4', script: 'vuln', service_detection: true }
};

document.querySelectorAll('.profile-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const profile = PROFILES[btn.getAttribute('data-profile')];
        if (!profile) return;
        
        // Reset first
        document.querySelectorAll('input[type="checkbox"]').forEach(c => c.checked = false);
        document.querySelectorAll('input[type="text"]').forEach(t => t.value = '');
        document.querySelector('input[name="timing"][value="3"]').checked = true;

        // Apply profile
        for (const [key, val] of Object.entries(profile)) {
            if (typeof val === 'boolean') {
                const el = document.querySelector(`input[name="${key}"]`);
                if (el) el.checked = val;
            } else if (key === 'timing') {
                const el = document.querySelector(`input[name="timing"][value="${val}"]`);
                if (el) el.checked = true;
            } else {
                const el = document.querySelector(`input[name="${key}"]`);
                if (el) el.value = val;
            }
        }
        buildPreview();
        updateConflictWarning();
    });
});

// ── Bulk Toggle ──
const bulkToggle = document.getElementById('bulk-toggle');
const bulkTargets = document.getElementById('bulk-targets');
bulkToggle.addEventListener('click', () => {
    const isVisible = bulkTargets.style.display !== 'none';
    bulkTargets.style.display = isVisible ? 'none' : 'block';
    targetEl.style.display = isVisible ? 'block' : 'none';
    bulkToggle.classList.toggle('active');
});

// ── Status polling ──
async function checkStatus() {
    try {
        const r = await fetch(getHealthUrl());
        if (r.ok) {
            const d = await r.json();
            apiStatus.classList.add('online');
            statusTxt.textContent = d.nmap_found ? 'Online' : 'Online (Mock)';
        } else { throw new Error(); }
    } catch {
        apiStatus.classList.remove('online');
        statusTxt.textContent = 'Offline';
    }
}
// Initial check is handled by storage callback (or we just call it once for non-extension context)
if (typeof chrome === 'undefined' || !chrome.storage) checkStatus();
setInterval(checkStatus, 12000);

// ── Build command preview live ──
function buildPreview() {
    let parts = ['nmap'];

    // Timing
    const timing = document.querySelector('input[name="timing"]:checked')?.value || '3';
    if (timing !== '3') parts.push(`-T${timing}`);

    // Checkboxes
    CHECKBOXES.forEach(name => {
        const el = document.querySelector(`input[name="${name}"]`);
        if (el?.checked) {
            const flag = el.getAttribute('data-flag') || `--${name.replace(/_/g,'-')}`;
            parts.push(flag);
        }
    });

    // Text inputs
    TEXT_INPUTS.forEach(name => {
        const el = document.querySelector(`input[name="${name}"]`);
        if (el?.value.trim()) {
            const flagMap = {
                idle_zombie: '-sI',  scan_flags: '--scanflags', dns_servers: '--dns-servers',
                iR: '-iR', exclude: '--exclude', port_range: '-p', top_ports: '--top-ports',
                script: '--script', mtu: '--mtu', decoy: '-D', source_port: '--source-port',
                data_length: '--data-length', spoof_mac: '--spoof-mac', interface: '-e',
                ttl: '--ttl', min_parallelism: '--min-parallelism', max_parallelism: '--max-parallelism',
                min_hostgroup: '--min-hostgroup', max_hostgroup: '--max-hostgroup',
                max_rtt_timeout: '--max-rtt-timeout', initial_rtt_timeout: '--initial-rtt-timeout',
                max_retries: '--max-retries', host_timeout: '--host-timeout',
                scan_delay: '--scan-delay', max_scan_delay: '--max-scan-delay',
                min_rate: '--min-rate', max_rate: '--max-rate', custom_flags: null
            };
            if (flagMap[name] === null) {
                parts.push(el.value.trim()); // custom_flags appended raw
            } else if (flagMap[name]) {
                parts.push(flagMap[name], el.value.trim());
            }
        }
    });

    const target = targetEl.value.trim();
    if (target) parts.push(target);

    cmdText.textContent = parts.join(' ');
}

// ── Conflict warning ──
function updateConflictWarning() {
    const listScan   = document.querySelector('input[name="list_scan"]')?.checked;
    const pingSweep  = document.querySelector('input[name="ping_sweep"]')?.checked;

    let existing = document.getElementById('conflict-warning');
    if (!existing) {
        existing = document.createElement('div');
        existing.id = 'conflict-warning';
        existing.style.cssText = `
            background: rgba(234,179,8,0.12); border: 1px solid rgba(234,179,8,0.4);
            border-radius:6px; padding:8px 12px; margin-bottom:10px;
            font-size:0.72rem; color:#fbbf24; display:none; line-height:1.5;
        `;
        document.querySelector('.options-panel').insertAdjacentElement('beforebegin', existing);
    }

    if (listScan) {
        existing.style.display = 'block';
        existing.textContent = '⚠ List Scan (-sL) ignores all ping, port, and service options — only hostnames are listed.';
    } else if (pingSweep) {
        existing.style.display = 'block';
        existing.textContent = '⚠ Ping Sweep (-sn) skips port scanning — service detection, OS, and port options are ignored.';
    } else {
        existing.style.display = 'none';
    }
}

document.querySelectorAll('input').forEach(el => {
    el.addEventListener('input', buildPreview);
    el.addEventListener('change', buildPreview);
    el.addEventListener('change', updateConflictWarning);
});

// ── Build API payload ──
function buildPayload() {
    const payload = { target: targetEl.value.trim() };

    // Timing
    payload.timing = document.querySelector('input[name="timing"]:checked')?.value || '3';

    // Checkboxes
    CHECKBOXES.forEach(name => {
        const el = document.querySelector(`input[name="${name}"]`);
        payload[name] = el?.checked || false;
    });

    // Text inputs
    TEXT_INPUTS.forEach(name => {
        const el = document.querySelector(`input[name="${name}"]`);
        payload[name] = el?.value.trim() || '';
    });

    return payload;
}

// ── Scan ──
scanBtn.addEventListener('click', () => {
    const isBulk = bulkTargets.style.display !== 'none';
    const targets = isBulk 
        ? bulkTargets.value.split('\n').map(t => t.trim()).filter(Boolean)
        : [targetEl.value.trim()];

    if (targets.length === 0 && !document.querySelector('input[name="iR"]').value) {
        outputEl.innerHTML = '⚠ Enter a target IP, hostname, or CIDR.';
        return;
    }

    if (targets.length > 1) {
        outputEl.innerHTML = '⚠ Bulk scanning is temporarily limited to 1 target to support background execution.';
        return;
    }

    const target = targets[0] || '';

    outputEl.innerHTML = '';
    outputEl.classList.add('scanning');
    scanBtn.disabled = true;
    scanBtn.textContent = '⏳ Scanning…';

    const payload = buildPayload();
    payload.target = target;

    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
            type: 'START_SCAN',
            payload: payload,
            apiUrl: getApiUrl(),
            apiKey: API_KEY
        }).catch(err => {
            outputEl.innerHTML = `❌ Failed to communicate with background script.<br><br><b>💡 FIX:</b> Please go to <code>chrome://extensions/</code> and click the <b>Reload ↻</b> button on the extension card to register the new background worker.`;
            outputEl.classList.remove('scanning');
            scanBtn.disabled = false;
            scanBtn.textContent = '▶ Scan';
        });
    } else {
        outputEl.innerHTML = '⚠ Background scanning requires running as a Chrome Extension.';
        scanBtn.disabled = false;
        scanBtn.textContent = '▶ Scan';
    }
});

// Listen for completion
if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.type === 'SCAN_COMPLETE') {
            outputEl.classList.remove('scanning');
            scanBtn.disabled = false;
            scanBtn.textContent = '▶ Scan';
            outputEl.innerHTML = parseOutputText(request.output);
        }
    });

    // Check active scan on load
    chrome.storage.local.get(['activeScan'], (result) => {
        if (result.activeScan) {
            outputEl.innerHTML = 'Scan in progress... Feel free to close this popup, a notification will appear when done.';
            outputEl.classList.add('scanning');
            scanBtn.disabled = true;
            scanBtn.textContent = '⏳ Scanning…';
            targetEl.value = result.activeScan;
        }
    });
}

// ── Clear ──
clearBtn.addEventListener('click', () => {
    targetEl.value = '';
    document.querySelectorAll('input[type="checkbox"]').forEach(c => c.checked = false);
    document.querySelectorAll('input[type="text"]').forEach(t => t.value = '');
    document.querySelector('input[name="timing"][value="3"]').checked = true;
    
    // Force reset UI in case it was stuck
    outputEl.classList.remove('scanning');
    scanBtn.disabled = false;
    scanBtn.textContent = '▶ Scan';
    outputEl.innerHTML = 'Cleared. Ready for next scan.';
    
    // Force remove activeScan and activeJobId from storage
    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.remove(['activeScan', 'activeJobId']);
    }

    buildPreview();
});

// ── Copy ──
copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(outputEl.textContent).then(() => {
        const oldText = copyBtn.textContent;
        copyBtn.textContent = '✓';
        setTimeout(() => copyBtn.textContent = oldText, 2000);
    });
});

// ── Download ──
const downloadBtn = document.getElementById('download-btn');
downloadBtn.addEventListener('click', () => {
    const text = outputEl.textContent;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nmap_scan_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    
    const oldText = downloadBtn.textContent;
    downloadBtn.textContent = '✓';
    setTimeout(() => downloadBtn.textContent = oldText, 2000);
});

// ── Auto-fill target with active tab's domain ──
if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].url) {
            try {
                const url = new URL(tabs[0].url);
                if (url.protocol === 'http:' || url.protocol === 'https:') {
                    targetEl.value = url.hostname;
                    buildPreview();
                }
            } catch (e) {
                console.error("Error parsing tab URL:", e);
            }
        }
    });
}

buildPreview();
