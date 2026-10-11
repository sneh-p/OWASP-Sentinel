// Dashboard and Scan interaction logic

document.addEventListener('DOMContentLoaded', () => {
    // 1. Tab Switching
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-tab');

            // Reset tab button styles
            tabButtons.forEach(b => {
                b.classList.remove('text-brand-400', 'border-brand-500', 'font-semibold');
                b.classList.add('text-slate-400', 'border-transparent', 'font-medium');
            });

            // Activate current button
            btn.classList.remove('text-slate-400', 'border-transparent', 'font-medium');
            btn.classList.add('text-brand-400', 'border-brand-500', 'font-semibold');

            // Toggle contents
            tabContents.forEach(content => {
                if (content.id === targetId) {
                    content.classList.remove('hidden');
                    content.classList.add('block');
                } else {
                    content.classList.remove('block');
                    content.classList.add('hidden');
                }
            });
            if (window.lucide) lucide.createIcons();
        });
    });

    // 2. Dropzone file selection handling
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('archive_file');
    const fileSelectedText = document.getElementById('file_selected_text');

    if (dropzone && fileInput) {
        dropzone.addEventListener('click', () => fileInput.click());

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('border-brand-500', 'bg-slate-900/80');
        });

        dropzone.addEventListener('dragleave', () => {
            dropzone.classList.remove('border-brand-500', 'bg-slate-900/80');
        });

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('border-brand-500', 'bg-slate-900/80');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateFileText(fileInput.files[0]);
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                updateFileText(fileInput.files[0]);
            }
        });
    }

    function updateFileText(file) {
        if (fileSelectedText && file) {
            const sizeKb = (file.size / 1024).toFixed(1);
            fileSelectedText.innerHTML = `<span class="text-brand-400 font-semibold font-mono">Selected:</span> ${file.name} <span class="text-slate-500 font-mono text-xs">(${sizeKb} KB)</span>`;
            if (window.showGlobalToast) window.showGlobalToast(`Archive selected: ${file.name}`, 'info');
        }
    }

    // 3. Scan Form Submissions with Animated Terminal Console
    const scanForms = document.querySelectorAll('.scan-form');
    const progressOverlay = document.getElementById('scan-progress-overlay');
    const scanTimerEl = document.getElementById('scanTimer');
    const progressBar = document.getElementById('scanProgressBar');

    scanForms.forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const submitBtn = form.querySelector('.submit-scan-btn');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.classList.add('opacity-50');
            }

            // Show scanning terminal overlay
            if (progressOverlay) progressOverlay.classList.remove('hidden');

            // Start Live Stopwatch Timer & Progress Animation
            let startTime = performance.now();
            let timerInterval = setInterval(() => {
                const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
                if (scanTimerEl) scanTimerEl.textContent = `${elapsed}s`;
            }, 100);

            // Step animator
            let currentPct = 15;
            if (progressBar) progressBar.style.width = `${currentPct}%`;

            const steps = [
                { id: 'step-tree', text: 'Directory tree parsed & AST engines active', delay: 400 },
                { id: 'step-owasp', text: 'OWASP Top 10 & CWE Top 25 vulnerabilities evaluated', delay: 900 },
                { id: 'step-cis', text: 'CIS Container & Infrastructure-as-Code benchmarks checked', delay: 1400 },
                { id: 'step-slsa', text: 'SLSA CI/CD pipelines & FOSS license governance verified', delay: 1900 },
                { id: 'step-gate', text: 'Quality Gate computed & remediation patches formatted', delay: 2400 },
            ];

            let timeouts = [];
            steps.forEach((s, idx) => {
                let t = setTimeout(() => {
                    const stepEl = document.getElementById(s.id);
                    if (stepEl) {
                        stepEl.className = 'flex items-center gap-2 text-emerald-400';
                        stepEl.innerHTML = `<span>[${idx + 2}/6]</span> <span>✓ ${s.text}</span>`;
                    }
                    currentPct = Math.min(90, currentPct + 15);
                    if (progressBar) progressBar.style.width = `${currentPct}%`;
                }, s.delay);
                timeouts.push(t);
            });

            const formData = new FormData(form);

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                clearInterval(timerInterval);
                timeouts.forEach(t => clearTimeout(t));

                if (result.success && result.redirect_url) {
                    if (progressBar) progressBar.style.width = '100%';
                    const statusText = document.getElementById('progress-status');
                    if (statusText) statusText.textContent = 'Scan completed! Loading security assessment report...';

                    if (window.showGlobalToast) window.showGlobalToast('Scan completed successfully! Loading report...', 'success');
                    setTimeout(() => {
                        window.location.href = result.redirect_url;
                    }, 400);
                } else {
                    if (progressOverlay) progressOverlay.classList.add('hidden');
                    if (submitBtn) {
                        submitBtn.disabled = false;
                        submitBtn.classList.remove('opacity-50');
                    }
                    alert('Scan Failed: ' + (result.error || 'Unknown error occurred.'));
                }
            } catch (err) {
                clearInterval(timerInterval);
                timeouts.forEach(t => clearTimeout(t));
                if (progressOverlay) progressOverlay.classList.add('hidden');
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('opacity-50');
                }
                alert('Connection error while submitting scan: ' + err.message);
            }
        });
    });

    // 4. Initialize Interactive Charts on Dashboard if elements exist
    initDashboardCharts();
});

// Interactive Charts Initialization
function initDashboardCharts() {
    if (typeof Chart === 'undefined') return;

    // Severity Doughnut Chart
    const sevCanvas = document.getElementById('severityChart');
    if (sevCanvas && typeof dashboardStats !== 'undefined') {
        const sevData = dashboardStats.severity || {};
        const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
        const values = [
            sevData['CRITICAL'] || 0,
            sevData['HIGH'] || 0,
            sevData['MEDIUM'] || 0,
            sevData['LOW'] || 0,
            sevData['INFO'] || 0
        ];

        const hasValues = values.some(v => v > 0);

        new Chart(sevCanvas, {
            type: 'doughnut',
            data: {
                labels: hasValues ? labels : ['No Findings'],
                datasets: [{
                    data: hasValues ? values : [1],
                    backgroundColor: hasValues ? [
                        '#ef4444', // Critical
                        '#f97316', // High
                        '#eab308', // Medium
                        '#3b82f6', // Low
                        '#64748b'  // Info
                    ] : ['#334155'],
                    borderWidth: 2,
                    borderColor: '#0f172a'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return ` ${context.label}: ${context.raw}`;
                            }
                        }
                    }
                }
            }
        });
    }

    // Top Category Bar Chart
    const catCanvas = document.getElementById('categoryChart');
    if (catCanvas && typeof dashboardStats !== 'undefined') {
        const catData = dashboardStats.categories || {};
        const catKeys = Object.keys(catData).slice(0, 5);
        const catValues = catKeys.map(k => catData[k]);

        new Chart(catCanvas, {
            type: 'bar',
            data: {
                labels: catKeys.length ? catKeys : ['Clean'],
                datasets: [{
                    label: 'Findings',
                    data: catValues.length ? catValues : [0],
                    backgroundColor: 'rgba(6, 182, 212, 0.75)',
                    hoverBackgroundColor: '#06b6d4',
                    borderRadius: 6,
                    borderSkipped: false
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        grid: { color: 'rgba(51, 65, 85, 0.3)' },
                        ticks: { color: '#94a3b8', font: { size: 10 } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#cbd5e1', font: { size: 11, weight: 'bold' } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // Security Score Trend Area Chart
    const trendCanvas = document.getElementById('trendChart');
    if (trendCanvas) {
        fetch('/api/analytics/trends')
            .then(res => res.json())
            .then(data => {
                if (data.success && data.history) {
                    const points = data.history.slice(-8);
                    const labels = points.map(p => p.repo_name.slice(0, 10));
                    const scores = points.map(p => p.score);

                    new Chart(trendCanvas, {
                        type: 'line',
                        data: {
                            labels: labels.length ? labels : ['Current'],
                            datasets: [{
                                label: 'Security Score',
                                data: scores.length ? scores : [dashboardStats ? dashboardStats.avgScore : 100],
                                borderColor: '#10b981',
                                backgroundColor: 'rgba(16, 185, 129, 0.12)',
                                fill: true,
                                tension: 0.35,
                                pointBackgroundColor: '#10b981',
                                pointRadius: 3,
                                pointHoverRadius: 6
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    min: 0,
                                    max: 100,
                                    grid: { color: 'rgba(51, 65, 85, 0.3)' },
                                    ticks: { color: '#94a3b8', font: { size: 10 } }
                                },
                                x: {
                                    grid: { display: false },
                                    ticks: { color: '#94a3b8', font: { size: 10 } }
                                }
                            },
                            plugins: {
                                legend: { display: false }
                            }
                        }
                    });
                }
            })
            .catch(() => {});
    }
}
