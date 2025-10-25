document.addEventListener('DOMContentLoaded', () => {
    // Elements
    const outputEl = document.getElementById('live-output');
    const statusEl = document.getElementById('scan-status');
    const runBtn = document.getElementById('run-scan-btn');
    const runTextEl = document.getElementById('run-scan-text');
    const spinnerEl = document.getElementById('run-scan-spinner');
    const domainInput = document.getElementById('target-domain');
    const highlightsEl = document.getElementById('highlights-content');
    const noHighlightsEl = document.getElementById('no-highlights');
    const saveReportBtn = document.getElementById('save-report-btn');
    const downloadReportBtn = document.getElementById('download-report-btn');
    const runningStatusEl = document.getElementById('running-status');
    const criticalMetricEl = document.getElementById('critical-findings-metric');
    const targetIpMetricEl = document.getElementById('target-ip-metric');
    const consoleStatusLabelEl = document.getElementById('console-status-label');
    const mainToggleEl = document.getElementById('main-scan-toggle');
    const exportModal = document.getElementById('export-modal');
    const modalDownloadBtn = document.getElementById('modal-download-btn');

    let isScanning = false;
    let totalOutput = [];
    let targetIP = 'N/A';
    let findings = { medium: 0, critical: 0 };

    const scanModules = {
        'basic': { id: 'scan-basic', name: 'Basic Check (Live)', type: 'backend' },
        'whois': { id: 'scan-whois', name: 'Whois Lookup (Live)', type: 'backend' },
        'subdomain': { id: 'scan-subdomain', name: 'Subdomain Scan (Live)', type: 'backend' },
        'wordpress': { id: 'scan-wordpress', name: 'WordPress Scan (Live)', type: 'backend' },
        'sqli': { id: 'scan-sqli', name: 'Error Based SQli (Simulated)', type: 'simulated' },
        'geoip': { id: 'scan-geoip', name: 'Geo-IP Lookup (Client API)', type: 'client-api' }
    };

    function getCleanHostname(url) {
        try {
            let input = url.trim();
            if (!input) return '';
            if (!input.startsWith('http://') && !input.startsWith('https://')) {
                input = 'https://' + input;
            }
            const urlObj = new URL(input);
            let host = urlObj.hostname;
            if (host.startsWith('www.')) host = host.substring(4);
            return host;
        } catch (e) {
            // fallback: return trimmed input (no scheme)
            return url.trim();
        }
    }

    function formatLine(line) {
        if (!line) return '';
        if (line.includes('[CRITICAL ERROR]') || line.includes('[CRITICAL]')) {
            return `<span class="critical">${escapeHtml(line)}</span>`;
        } else if (line.includes('[ERROR]')) {
            return `<span class="error">${escapeHtml(line)}</span>`;
        } else if (line.includes('[SUCCESS]')) {
            return `<span class="success">${escapeHtml(line)}</span>`;
        } else if (line.includes('[FINDING]') || line.includes('[WARNING]')) {
            return `<span class="warning">${escapeHtml(line)}</span>`;
        } else if (line.includes('[LIVE API]')) {
             return `<span class="api">${escapeHtml(line)}</span>`;
        } else if (line.includes('[INFO]') || line.startsWith('--- Executing Module') || line.startsWith('$ abspider') || line.startsWith('[SCAN]')) {
            return `<span class="info">${escapeHtml(line)}</span>`;
        }
        return escapeHtml(line);
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }

    async function printOutput(lines) {
        for (const line of lines) {
            const isScrolledToBottom = outputEl.scrollHeight - outputEl.clientHeight <= outputEl.scrollTop + 1;
            totalOutput.push(line);
            outputEl.innerHTML = totalOutput.map(formatLine).join('\n');
            if (isScrolledToBottom) outputEl.scrollTop = outputEl.scrollHeight;
            // micro-yield to let UI update
            await new Promise(resolve => setTimeout(resolve, 5));
        }
    }

    function updateHighlights(domain) {
        highlightsEl.innerHTML = '';
        let hasHighlights = false;
        let currentHighlights = {};

        const highlightMap = {
            'IP': line => line.includes('Target IP resolved:') ? line.split(': ')[1].trim() : null,
            'Server': line => line.includes('Server:') ? line.split('Server: ')[1].trim() : null,
            'Country': line => line.includes('Country:') ? line.split('Country: ')[1].trim() : null,
            'City': line => line.includes('City:') ? line.split('City: ')[1].trim() : null,
            'Organization': line => line.includes('Organization:') ? line.split('Organization: ')[1].trim() : null,
            'WordPress Version': line => line.includes('WordPress Version:') ? line.split('WordPress Version: ')[1].trim() : null,
            'Registrar': line => line.includes('Registrar:') ? line.split('Registrar: ')[1].trim() : null,
        };

        findings = { medium: 0, critical: 0 };

        totalOutput.forEach(line => {
            if (line.includes('[FINDING]') || line.includes('[WARNING]')) findings.medium++;
            if (line.includes('[CRITICAL]') || line.includes('[CRITICAL ERROR]')) findings.critical++;
            for (const key in highlightMap) {
                if (!currentHighlights[key]) {
                    try {
                        const value = highlightMap[key](line);
                        if (value) currentHighlights[key] = value;
                    } catch (e) {}
                }
            }
        });

        const displayMapping = {
            'IP': 'Target IP',
            'Server': 'Web Server',
            'Country': 'Country/Region',
            'City': 'City/Location',
            'Organization': 'Organization',
            'WordPress Version': 'CMS/Version',
            'Registrar': 'Registrar',
        };

        const keysToDisplay = ['IP', 'Country', 'City', 'Server', 'Registrar', 'Organization', 'WordPress Version'];
        keysToDisplay.forEach(key => {
            if (currentHighlights[key]) {
                const label = displayMapping[key] || key;
                const value = currentHighlights[key];
                highlightsEl.innerHTML += `
                    <div class="flex flex-col p-2 bg-gray-900 rounded-md">
                        <span class="text-gray-400 text-xs">${label}</span>
                        <span class="text-white font-mono">${escapeHtml(value)}</span>
                    </div>`;
                hasHighlights = true;
                if (key === 'IP') targetIP = value;
            }
        });

        // Always show a small Ports card (simulated)
        highlightsEl.innerHTML += `<div class="flex flex-col p-2 bg-gray-900 rounded-md">
            <span class="text-gray-400 text-xs">Ports</span>
            <span class="text-white font-mono">80, 443 (Sim)</span>
        </div>`;
        hasHighlights = true;

        if (!hasHighlights) highlightsEl.appendChild(noHighlightsEl);
        else document.getElementById('findings-summary').classList.remove('hidden');

        document.getElementById('medium-findings').textContent = `${findings.medium} medium findings`;
        document.getElementById('critical-findings').textContent = `${findings.critical} critical findings`;
        criticalMetricEl.textContent = findings.critical;
        targetIpMetricEl.textContent = targetIP;
    }

    function clearOutput() {
        if (isScanning) return;
        totalOutput = [];
        targetIP = 'N/A';
        findings = { medium: 0, critical: 0 };
        outputEl.innerHTML = `<span class="info">[[ ABSpider v1.0 Console Cleared ]]</span>`;
        highlightsEl.innerHTML = `<p class="text-gray-500 col-span-2 md:col-span-3" id="no-highlights">Waiting for scan data...</p>`;
        document.getElementById('findings-summary').classList.add('hidden');
        saveReportBtn.disabled = true;
        downloadReportBtn.disabled = true;
        statusEl.textContent = 'Idle';
        criticalMetricEl.textContent = 0;
        targetIpMetricEl.textContent = 'N/A';
        runningStatusEl.textContent = '00:00';
        consoleStatusLabelEl.textContent = 'ABSpider Initialized';
        statusEl.className = 'font-bold text-lg text-gray-500';
    }

    async function runGeoIpLookup(ipToLookup) {
        const results = [];
        const apiUrl = `https://ipapi.co/${ipToLookup}/json/`;
        results.push(`[LIVE API] Geo-IP Lookup on ${ipToLookup} using ipapi.co...`);
        await new Promise(resolve => setTimeout(resolve, 500));
        try {
            const response = await fetch(apiUrl);
            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);
            const data = await response.json();
            if (data.error) results.push(`[ERROR] Geo-IP API error: ${data.reason || 'Unknown reason'}`);
            else {
                results.push("[SUCCESS] Geo-IP data retrieved.");
                results.push("Country: " + (data.country_name || 'N/A'));
                results.push("City: " + (data.city || 'N/A'));
                results.push("Organization: " + (data.org || 'N/A'));
                results.push("Postal: " + (data.postal || 'N/A'));
            }
        } catch (e) {
            results.push(`[ERROR] Geo-IP Lookup failed: API call failed. (Check console for network error)`);
        }
        return results;
    }

    async function runSqliScan(domain) {
        const results = [];
        results.push(`[SIMULATED] Initializing SQLi check on common parameters...`);
        await new Promise(resolve => setTimeout(resolve, 1000));
        if (domain.toLowerCase().includes("test") || domain.toLowerCase().includes("dev")) {
             results.push(`[CRITICAL] Parameter 'id=1' on /test.php potentially vulnerable to basic injection.`);
             results.push(`[DETAIL] Payload 'or 1=1-- ' resulted in a database error.`);
        } else {
             results.push(`[INFO] 25 common payloads tested against index and login endpoints. No obvious SQL error patterns detected.`);
        }
        return results;
    }

    async function startScan() {
        if (isScanning) {
            // stop
            isScanning = false;
            return;
        }

        const rawDomain = domainInput.value.trim();
        if (!rawDomain) {
            showModal('Validation Error', 'Please enter a target domain (e.g., google.com) to start the scan.');
            return;
        }
        const domain = getCleanHostname(rawDomain);

        clearOutput();
        isScanning = true;
        runTextEl.textContent = 'STOP SCAN';
        runBtn.classList.add('bg-gray-500', 'hover:bg-gray-600');
        runBtn.classList.remove('btn-primary');
        spinnerEl.classList.remove('hidden');
        statusEl.textContent = 'Running';
        statusEl.className = 'font-bold text-lg text-red-500';
        consoleStatusLabelEl.textContent = 'Scanning in Progress';

        const backendModules = ['basic', 'subdomain', 'wordpress', 'whois'];
        const simulatedModules = ['sqli'];

        const selectedBackendModules = backendModules.filter(key => {
            const m = scanModules[key];
            const el = document.getElementById(m.id);
            return m && el && el.checked;
        });
        const selectedSimulatedModules = simulatedModules.filter(key => {
            const el = document.getElementById(scanModules[key].id);
            return el && el.checked;
        });
        const isGeoIpSelected = document.getElementById('scan-geoip') && document.getElementById('scan-geoip').checked;

        const selectedModuleNames = selectedBackendModules.map(s => scanModules[s].name.split(' ')[0])
            .concat(selectedSimulatedModules.map(s => scanModules[s].name.split(' ')[0]))
            .concat(isGeoIpSelected ? ['Geo-IP'] : []);

        await printOutput([
            `ABSpider Scanner initiated for target: ${domain}`,
            `Selected modules: ${selectedModuleNames.join(', ')}`,
            '----------------------------------------------------'
        ]);

        let scanCounter = 0;
        const updateTimer = setInterval(() => {
            if (!isScanning) return clearInterval(updateTimer);
            scanCounter++;
            runningStatusEl.textContent = `Elapsed: ${Math.floor(scanCounter / 10)}s`;
        }, 100);

        try {
            if (selectedBackendModules.length > 0) {
                await printOutput([`[SCAN] Sending ${selectedBackendModules.length} real scan modules to Flask backend...`]);

                const proxyVal = (document.getElementById('scan-proxy') && document.getElementById('scan-proxy').value.trim()) || null;
                const webhookVal = (document.getElementById('scan-webhook') && document.getElementById('scan-webhook').value.trim()) || null;
                const saveProxyFlag = false;

                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        domain: domain,
                        modules: selectedBackendModules,
                        proxy: proxyVal,
                        save_proxy: saveProxyFlag,
                        webhook: webhookVal
                    })
                });

                if (!response.ok) {
                    let errText = `HTTP Error! Status: ${response.status}`;
                    try {
                        const errJson = await response.json();
                        errText = errJson.error || errText;
                    } catch (e) {}
                    throw new Error(errText);
                }

                const data = await response.json();
                const outputLines = (data.output || '').split('\n').filter(Boolean);

                if (isScanning) {
                    await printOutput(outputLines);
                    updateHighlights(domain);
                    // enable report buttons now that logs exist
                    saveReportBtn.disabled = false;
                    downloadReportBtn.disabled = false;
                }
            }

            if (isScanning && isGeoIpSelected) {
                await printOutput([`\n[SCAN] Running Module: Geo-IP Lookup...`]);

                if (targetIP === 'N/A' || targetIP.includes('Unknown') || targetIP.includes('CRITICAL ERROR')) {
                    await printOutput([`[ERROR] Geo-IP failed: Basic Scan did not resolve a valid Target IP for lookup.`]);
                } else {
                    const geoIpResults = await runGeoIpLookup(targetIP);
                    await printOutput(geoIpResults);
                    updateHighlights(domain);
                }
            }

            for (const key of selectedSimulatedModules) {
                if (!isScanning) break;
                await printOutput([`\n[SCAN] Running Module: ${scanModules[key].name}...`]);
                const results = await runSqliScan(domain);
                await printOutput(results);
                updateHighlights(domain);
            }

        } catch (error) {
            await printOutput([`\n[CRITICAL ERROR] Scan Execution Failed: Could not connect to the backend server. Is Flask running? (Error: ${error.message})`]);
        }

        clearInterval(updateTimer);
        if (isScanning) {
            updateHighlights(domain);
            await printOutput([
                '\n----------------------------------------------------',
                '[COMPLETED] All selected modules finished executing.',
                `[SUMMARY] ${findings.critical} Critical, ${findings.medium} Medium findings found.`,
            ]);

            statusEl.textContent = 'COMPLETE';
            statusEl.className = 'font-bold text-lg text-green-500';
            consoleStatusLabelEl.textContent = 'Scan Complete';
            saveReportBtn.disabled = false;
            downloadReportBtn.disabled = false;
            runningStatusEl.textContent = '00:00';
        } else {
            await printOutput(['\n[INTERRUPTED] Scan manually stopped by user.']);
            statusEl.textContent = 'STOPPED';
            statusEl.className = 'font-bold text-lg text-yellow-500';
            consoleStatusLabelEl.textContent = 'Scan Interrupted';
        }

        isScanning = false;
        runTextEl.textContent = 'RUN SCAN';
        runBtn.classList.remove('bg-gray-500', 'hover:bg-gray-600');
        runBtn.classList.add('btn-primary');
        spinnerEl.classList.add('hidden');
    }

    function showModal(title, message) {
        const modal = document.getElementById('custom-message-box');
        document.getElementById('message-title').textContent = title;
        document.getElementById('message-body').textContent = message;
        modal.classList.remove('hidden');
        // simple close handler
        const okBtn = modal.querySelector('button');
        okBtn.onclick = () => modal.classList.add('hidden');
    }

    function toggleAllScans() {
        const toggle = mainToggleEl;
        const wasChecked = toggle.classList.contains('checked');
        // Flip UI state
        toggle.classList.toggle('checked', !wasChecked);
        toggle.setAttribute('aria-pressed', String(!wasChecked));

        // When turning on: check everything.
        // When turning off: disable all non-basic scans (keep basic checked).
        const options = document.querySelectorAll('.scan-checkbox');
        options.forEach(checkbox => {
            if (!wasChecked) {
                checkbox.checked = true;
            } else {
                // turning off -> leave basic checked
                if (checkbox.id === 'scan-basic') checkbox.checked = true;
                else checkbox.checked = false;
            }
        });
    }

    function showExportModal() {
        const domain = domainInput.value.trim();
        const date = new Date().toISOString().split('T')[0];
        const selectedModuleKeys = Object.keys(scanModules).filter(key => document.getElementById(scanModules[key].id).checked);
        const selectedScans = selectedModuleKeys.map(key => scanModules[key].name.split(' ')[0]);

        document.getElementById('modal-domain').textContent = domain || 'n/a';
        document.getElementById('modal-findings').textContent = `${findings.critical} critical, ${findings.medium} medium findings`;
        document.getElementById('report-filename').textContent = `abspider-${getCleanHostname(domain)}-${date}`;

        const previewText = `
ABSpider Report — ${domain}
Date: ${date}
Includes: ${selectedScans.join(', ')}
IP: ${targetIP || 'N/A'}
Findings: ${findings.critical} Critical, ${findings.medium} Medium
${totalOutput.length} lines of raw log data.
`;
        document.getElementById('report-preview').textContent = previewText.trim();
        document.getElementById('report-format-label').textContent = 'PDF (Default)';

        // default selection: pdf
        document.querySelectorAll('.format-btn').forEach(btn => btn.classList.remove('selected'));
        const pdfBtn = document.querySelector('.format-btn[data-format="pdf"]');
        if (pdfBtn) pdfBtn.classList.add('selected');

        exportModal.classList.remove('hidden');
        exportModal.setAttribute('aria-hidden', 'false');
    }

    function hideExportModal() {
        exportModal.classList.add('hidden');
        exportModal.setAttribute('aria-hidden', 'true');
    }

    async function downloadReport() {
        modalDownloadBtn.disabled = true;
        modalDownloadBtn.classList.add('opacity-50', 'cursor-not-allowed');

        const domain = domainInput.value.trim();
        let chosenFormat = 'pdf';
        const sel = document.querySelector('.format-btn.selected');
        if (sel && sel.dataset && sel.dataset.format) chosenFormat = sel.dataset.format;

        if (!totalOutput || totalOutput.length === 0) {
            showModal('Nothing to Download', 'No logs available to export. Run a scan first.');
            modalDownloadBtn.disabled = false;
            modalDownloadBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            return;
        }

        const payload = {
            domain: domain,
            full_log_output: totalOutput,
            findings: findings,
            format: chosenFormat,
            webhook: (document.getElementById('scan-webhook') && document.getElementById('scan-webhook').value.trim()) || null
        };

        try {
            const resp = await fetch('/api/report', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });

            if (!resp.ok) {
                let err = `Report endpoint returned HTTP ${resp.status}`;
                try {
                    const j = await resp.json();
                    err = j.error || err;
                } catch (e) {}
                showModal('Report Error', err);
                modalDownloadBtn.disabled = false;
                modalDownloadBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                return;
            }

            // parse filename from header or fallback
            let filename = document.getElementById('report-filename').textContent || `abspider-${getCleanHostname(domain)}.${chosenFormat}`;
            const cd = resp.headers.get('Content-Disposition');
            if (cd) {
                const match = /filename\*?=(?:UTF-8'')?["']?([^"';\n]+)/i.exec(cd);
                if (match) filename = decodeURIComponent(match[1]);
            }

            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);

            showModal('Download Complete', `The comprehensive ${chosenFormat.toUpperCase()} report for ${domain} has been downloaded as ${filename}.`);
            hideExportModal();
        } catch (e) {
            showModal('Report Error', `Failed to generate/download report: ${e.message}`);
        } finally {
            modalDownloadBtn.disabled = false;
            modalDownloadBtn.classList.remove('opacity-50', 'cursor-not-allowed');
        }
    }

    // Save session locally
    function saveSession() {
        if (!totalOutput || totalOutput.length === 0) {
            showModal('Nothing to Save', 'There are no logs to save yet. Run a scan first.');
            return;
        }
        const domain = domainInput.value.trim() || 'session';
        const date = new Date().toISOString().split('T')[0];
        const filename = `abspider-${getCleanHostname(domain)}-${date}.txt`;
        const content = totalOutput.join('\n');
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showModal('Saved', `Session saved locally as ${filename}.`);
    }

    // Wire events
    runBtn.addEventListener('click', startScan);
    document.getElementById('clear-output-btn').addEventListener('click', () => {
        if (isScanning) {
            showModal('Busy', 'Cannot clear logs while a scan is running.');
            return;
        }
        clearOutput();
    });
    saveReportBtn.addEventListener('click', saveSession);
    downloadReportBtn.addEventListener('click', showExportModal);
    modalDownloadBtn.addEventListener('click', downloadReport);

    // Toggle click/keyboard
    mainToggleEl.addEventListener('click', toggleAllScans);
    mainToggleEl.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleAllScans(); } });

    // format buttons logic
    document.querySelectorAll('.format-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.format-btn').forEach(x => x.classList.remove('selected'));
            btn.classList.add('selected');
        });
    });

    // initialize UI
    clearOutput();
});

