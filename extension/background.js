chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'START_SCAN') {
        const { payload, apiUrl, apiKey } = request;
        const target = payload.target;
        
        // Derive base URL to use for polling
        const baseUrl = apiUrl.replace('/api/scan', '');

        // Set active scan state
        chrome.storage.local.set({ activeScan: target, apiBaseUrl: baseUrl, apiKey: apiKey || '' });

        console.log(`Starting background scan for: ${target} at ${apiUrl}`);

        const headers = { 'Content-Type': 'application/json' };
        if (apiKey) {
            headers['X-API-Key'] = apiKey;
        }

        fetch(apiUrl, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(payload)
        })
        .then(res => res.json())
        .then(data => {
            if (data.job_id) {
                chrome.storage.local.set({ activeJobId: data.job_id });
                // If it's a mock scan, it might be completed immediately
                if (data.status === 'mock') {
                    finishJob(target, data);
                } else {
                    // Start polling alarm (Chrome allows 1 minute min for packed extensions, but <1 min for unpacked)
                    chrome.alarms.create('pollScan', { periodInMinutes: 0.25 });
                }
            } else {
                throw new Error(data.detail || JSON.stringify(data));
            }
        })
        .catch(err => {
            console.error(err);
            const out = `❌ Cannot reach backend for ${target}: ${err.message}\n${'='.repeat(40)}\n`;
            saveHistory(target, out);
            chrome.storage.local.remove(['activeScan', 'activeJobId', 'apiBaseUrl']);
            
            chrome.notifications.create('', {
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icon.png'),
                title: 'Nmap Scan Failed',
                message: `Could not reach backend for ${target}`,
                requireInteraction: true
            }, (notifId) => {
                if (chrome.runtime.lastError) console.error("Notification Error:", chrome.runtime.lastError);
            });

            chrome.runtime.sendMessage({ type: 'SCAN_COMPLETE', target: target, output: out }).catch(() => {});
        });

        sendResponse({ status: 'started' });
    }
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'pollScan') {
        chrome.storage.local.get(['activeJobId', 'activeScan', 'apiBaseUrl', 'apiKey'], (result) => {
            if (!result.activeJobId || !result.apiBaseUrl) {
                chrome.alarms.clear('pollScan');
                return;
            }

            const headers = {};
            if (result.apiKey) {
                headers['X-API-Key'] = result.apiKey;
            }

            fetch(`${result.apiBaseUrl}/api/scan/${result.activeJobId}`, {
                headers: headers
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === 'completed' || data.status === 'failed') {
                    chrome.alarms.clear('pollScan');
                    finishJob(result.activeScan, data);
                }
            })
            .catch(err => {
                console.error("Polling error:", err);
                // We do NOT clear the alarm on network error, in case the backend just temporarily restarted
            });
        });
    }
});

function finishJob(target, data) {
    chrome.storage.local.remove(['activeScan', 'activeJobId']);
    
    let out = `\n▶ Command: ${data.command || 'Error'}\n${'─'.repeat(40)}\n`;
    if (data.status === 'mock') out += `[MOCK MODE]\n`;
    
    if (data.status === 'completed' || data.status === 'mock') {
        out += data.output || '(no output)';
        if (data.error) out += `\n⚠ Stderr: ${data.error}`;
    } else {
        out += `❌ Error: ${data.error || JSON.stringify(data)}\n`;
    }

    // Smart hints
    if (out.includes('Host seems down')) out += '\n💡 TIP: Use -Pn to bypass ping filtering.';
    if (out.includes('requires administrator')) out += '\n🔑 TIP: Run as Admin.';
    if (out.includes('not to any IPv6 address')) out += '\n🌐 TIP: Target does not support IPv6.';

    out += `\n${'='.repeat(40)}\n`;

    saveHistory(target, out);

    // Send notification
    chrome.notifications.create('', {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icon.png'),
        title: (data.status === 'completed' || data.status === 'mock') ? 'Nmap Scan Complete' : 'Nmap Scan Failed',
        message: `Scan finished for ${target}`,
        priority: 2,
        requireInteraction: true
    }, (notifId) => {
        if (chrome.runtime.lastError) console.error("Notification Error:", chrome.runtime.lastError);
    });

    // Tell popup if it's open
    chrome.runtime.sendMessage({ type: 'SCAN_COMPLETE', target: target, output: out }).catch(() => {});
}

function saveHistory(target, output) {
    chrome.storage.local.get(['scanHistory'], (result) => {
        let history = result.scanHistory || [];
        const entry = {
            target: target,
            timestamp: new Date().toISOString(),
            output: output
        };
        history.unshift(entry);
        
        // Limit to 20 history items
        if (history.length > 20) {
            history = history.slice(0, 20);
        }

        chrome.storage.local.set({ scanHistory: history });
    });
}
