/* ============================================================
   SENTINEL CTI Platform — script.js v4.0
   Clean multi-page architecture — no tab switching needed.
   Each page loads its own section directly.
   ============================================================ */

// ─── Chart.js Global Config ───────────────────────────────
if (typeof Chart !== 'undefined') {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(15, 23, 42, 0.06)';
    Chart.defaults.font.family = "'IBM Plex Mono', monospace";
}

let overallChartInstance = null;
let insightsCharts = {};

// ─── Card Expand / Collapse ───────────────────────────────
function toggleCard(id) {
    const card = document.getElementById(`card-${id}`);
    if (!card) return;
    const wasExpanded = card.classList.contains('expanded');

    // Collapse all
    document.querySelectorAll('.threat-result-card.expanded').forEach(c => c.classList.remove('expanded'));

    if (!wasExpanded) {
        card.classList.add('expanded');
        setTimeout(() => createChartsForCard(card), 60);
        const rect = card.getBoundingClientRect();
        if (rect.top < 100) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ─── Mini Doughnut Charts ─────────────────────────────────
function createChartsForCard(card) {
    const makeDonut = (canvas, value, color) => {
        if (!canvas || Chart.getChart(canvas)) return;
        new Chart(canvas, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [value, 100 - value],
                    backgroundColor: [color, 'rgba(15,23,42,0.05)'],
                    borderWidth: 0
                }]
            },
            options: {
                cutout: '74%',
                responsive: false,
                maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } },
                animation: { animateScale: true, duration: 700 }
            }
        });
    };

    const binCanvas = card.querySelector('canvas[id^="binChart_"]');
    const binLabel  = card.querySelector('.binary-conf');
    if (binCanvas && binLabel) {
        const conf = parseFloat((binLabel.textContent.match(/[\d.]+/) || ['50'])[0]) || 50;
        const isT  = card.querySelector('.status-threat') !== null;
        makeDonut(binCanvas, conf, isT ? '#dc2626' : '#16a34a');
    }

    const mcCanvas = card.querySelector('canvas[id^="mcChart_"]');
    const mcLabel  = card.querySelector('.mc-conf');
    if (mcCanvas && mcLabel) {
        const conf = parseFloat((mcLabel.textContent.match(/[\d.]+/) || ['50'])[0]) || 50;
        makeDonut(mcCanvas, conf, '#0284c7');
    }
}

// ─── Overall Distribution Doughnut (Analyze page) ─────────
function createOverallChart() {
    const ctx = document.getElementById('overallChart');
    if (!ctx) return;

    const allCategories = JSON.parse(
        document.getElementById('allCategoriesData')?.textContent || '[]'
    );

    const counts = {};
    allCategories.forEach(c => counts[c] = 0);

    document.querySelectorAll('.category-header h2').forEach(h => {
        const match    = h.textContent.match(/(.+?)\s*\(/);
        const cat      = match ? match[1].trim() : null;
        if (cat && counts[cat] !== undefined) {
            const numMatch = h.textContent.match(/\((\d+)\)/);
            if (numMatch) counts[cat] = parseInt(numMatch[1]);
        }
    });

    const labels = Object.keys(counts).filter(k => counts[k] > 0);
    const data   = labels.map(k => counts[k]);
    if (!labels.length) return;

    if (overallChartInstance) overallChartInstance.destroy();

    const COLORS = ['#dc2626','#0284c7','#16a34a','#7c3aed','#d97706','#f97316','#3b82f6','#64748b'];

    overallChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: COLORS,
                borderWidth: 0,
                hoverBorderColor: '#fff',
                hoverBorderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            cutout: '65%',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(255,255,255,0.97)',
                    titleColor: '#0f172a',
                    bodyColor: '#475569',
                    borderColor: 'rgba(2,132,199,0.2)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                    callbacks: {
                        label: ctx => ` ${ctx.label}: ${ctx.parsed} threat${ctx.parsed !== 1 ? 's' : ''}`
                    }
                }
            },
            animation: { animateScale: true, animateRotate: true, duration: 900 }
        }
    });
}

// ─── Category Jump Bar ────────────────────────────────────
function jumpToCategory(cat, btn) {
    document.querySelectorAll('.cat-jump-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const safeId = 'cat-section-' + cat.replace(/ /g, '-');
    const el     = document.getElementById(safeId);
    if (el) {
        const offset = 130;
        const top    = el.getBoundingClientRect().top + window.scrollY - offset;
        window.scrollTo({ top, behavior: 'smooth' });
    }
}

// ─── Progress Overlay ─────────────────────────────────────
const STEPS = [
    { label: 'Preprocessing text...', step: 1 },
    { label: 'Running binary classification...', step: 2 },
    { label: 'Analyzing threat category...', step: 3 },
    { label: 'Generating AI insights...', step: 4 }
];

function showProgress(stepIndex) {
    const loading = document.getElementById('loading');
    if (!loading) return;
    const step  = STEPS[Math.min(stepIndex, STEPS.length - 1)];
    const label = document.getElementById('progressLabel');
    if (label) label.textContent = step.label;

    for (let i = 1; i <= 4; i++) {
        const dot = document.getElementById(`step${i}`);
        if (!dot) continue;
        dot.className = 'progress-step';
        if (i < step.step)      dot.classList.add('done');
        else if (i === step.step) dot.classList.add('active');
    }
    loading.style.display = 'block';
}

function hideProgress() {
    const loading = document.getElementById('loading');
    if (loading) {
        loading.style.opacity = '0';
        loading.style.transition = 'opacity 0.3s ease';
        setTimeout(() => { loading.style.display = 'none'; loading.style.opacity = '1'; }, 300);
    }
}

// ─── Toast Notification ────────────────────────────────────
function showToast(message, type = 'success') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = `position:fixed;top:24px;right:24px;z-index:10000;display:flex;flex-direction:column;gap:12px;pointer-events:none;`;
        document.body.appendChild(container);
    }

    const toast   = document.createElement('div');
    const isOk    = type === 'success';
    const color   = isOk ? '#16a34a' : '#dc2626';
    const bgColor = isOk ? 'rgba(22,163,74,0.08)' : 'rgba(220,38,38,0.08)';
    const icon    = isOk ? 'fa-check-circle' : 'fa-exclamation-triangle';

    toast.style.cssText = `
        background:rgba(255,255,255,0.97);backdrop-filter:blur(12px);
        border:1px solid ${color};border-radius:10px;padding:14px 20px;
        color:#0f172a;font-family:'DM Sans',sans-serif;font-weight:500;
        display:flex;align-items:center;gap:12px;
        box-shadow:0 4px 20px rgba(15,23,42,0.12);
        transform:translateX(120%);transition:transform 0.4s cubic-bezier(0.175,0.885,0.32,1.275);
        min-width:280px;pointer-events:auto;
    `;
    toast.innerHTML = `
        <div style="background:${bgColor};color:${color};width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.9rem;flex-shrink:0;">
            <i class="fas ${icon}"></i>
        </div>
        <div style="flex:1;font-size:0.9rem;">${message}</div>
    `;
    container.appendChild(toast);
    requestAnimationFrame(() => { toast.style.transform = 'translateX(0)'; });
    setTimeout(() => {
        toast.style.transform = 'translateX(120%)';
        setTimeout(() => toast.remove(), 400);
    }, 4000);
}

// ─── Predict Form ─────────────────────────────────────────
document.getElementById('predictForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = document.getElementById('textInput')?.value?.trim();
    if (!text) return;

    const btn      = e.target.querySelector('button[type="submit"]');
    const origHtml = btn.innerHTML;
    btn.disabled   = true;
    btn.innerHTML  = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';

    const errEl = document.getElementById('error');
    if (errEl) errEl.textContent = '';

    try {
        showProgress(0); await delay(500);
        showProgress(1); await delay(800);
        showProgress(2); await delay(1000);
        showProgress(3);

        const res = await fetch('/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ text })
        });

        if (!res.ok) throw new Error(`Analysis failed (${res.status})`);
        const data = await res.json();

        if (data.message === 'No threat indicators detected' || !data.relevant) {
            hideProgress();
            btn.disabled  = false;
            btn.innerHTML = origHtml;
            showToast('No threat detected — text appears clean.', 'success');
            return;
        }

        showToast(`Threat Detected: ${data.category || 'Unknown'}`, 'danger');
        const label = document.getElementById('progressLabel');
        if (label) label.textContent = 'Analysis complete! Refreshing...';
        await delay(2000);
        location.reload();
    } catch (err) {
        if (errEl) errEl.textContent = err.message;
        hideProgress();
        btn.disabled  = false;
        btn.innerHTML = origHtml;
    }
});

// ─── Multi-Source Fetch ────────────────────────────────────
// Every source button (data-source / data-endpoint) and the
// "Fetch All" button funnel through the same handler so adding
// a new feed later is a one-line addition to the markup, not new JS.

function setSourceBtnState(btn, state) {
    btn.classList.remove('is-loading', 'is-done', 'is-error');
    const statusIcon = btn.querySelector('.source-btn-status i');
    if (state === 'loading') {
        btn.classList.add('is-loading');
        btn.disabled = true;
        if (statusIcon) statusIcon.className = 'fas fa-spinner fa-spin';
    } else if (state === 'done') {
        btn.classList.add('is-done');
        btn.disabled = false;
        if (statusIcon) statusIcon.className = 'fas fa-check';
    } else if (state === 'error') {
        btn.classList.add('is-error');
        btn.disabled = false;
        if (statusIcon) statusIcon.className = 'fas fa-triangle-exclamation';
    } else {
        btn.disabled = false;
        if (statusIcon) statusIcon.className = 'fas fa-arrow-rotate-right';
    }
}

async function fetchFromSource(endpoint, sourceLabel, btn) {
    const errEl = document.getElementById('error');
    if (errEl) errEl.textContent = '';
    if (btn) setSourceBtnState(btn, 'loading');

    const loading = document.getElementById('loading');
    const pl = document.getElementById('progressLabel');
    if (loading) {
        if (pl) pl.textContent = `Connecting to ${sourceLabel}...`;
        loading.style.display = 'block';
    }

    try {
        await delay(400);
        if (pl) pl.textContent = `Fetching latest from ${sourceLabel}...`;
        await delay(700);
        if (pl) pl.textContent = 'Processing threat intelligence...';

        const res = await fetch(endpoint, { method: 'POST' });
        if (!res.ok) throw new Error(`${sourceLabel} fetch failed (${res.status})`);
        const data = await res.json();

        if (btn) setSourceBtnState(btn, 'done');
        return data;
    } catch (err) {
        if (btn) setSourceBtnState(btn, 'error');
        if (errEl) errEl.textContent = err.message;
        throw err;
    }
}

// Individual source buttons (OTX / ThreatFox / URLhaus / MalwareBazaar)
document.querySelectorAll('.source-btn[data-endpoint]').forEach(btn => {
    btn.addEventListener('click', async () => {
        const endpoint = btn.dataset.endpoint;
        const source   = btn.dataset.source || 'source';

        try {
            const data = await fetchFromSource(endpoint, source, btn);
            const pl = document.getElementById('progressLabel');
            if (pl) pl.textContent = 'Done! Reloading...';
            showToast(data.message || `${source} fetch complete`, 'success');
            await delay(800);
            location.reload();
        } catch (err) {
            hideProgress();
            showToast(err.message, 'danger');
        }
    });
});

// "Fetch All Sources" button — hits /fetch-all directly, but also
// walks each source button through its loading/done state so the
// panel gives per-source feedback even though it's one request.
document.getElementById('fetchAllBtn')?.addEventListener('click', async () => {
    const btn      = document.getElementById('fetchAllBtn');
    const origHtml = btn.innerHTML;
    btn.disabled   = true;
    btn.innerHTML  = '<i class="fas fa-spinner fa-spin"></i> Fetching...';

    const errEl = document.getElementById('error');
    if (errEl) errEl.textContent = '';

    const sourceBtns = document.querySelectorAll('.source-btn[data-endpoint]');
    sourceBtns.forEach(b => setSourceBtnState(b, 'loading'));

    const loading = document.getElementById('loading');
    const pl = document.getElementById('progressLabel');
    if (loading) {
        if (pl) pl.textContent = 'Connecting to all sources...';
        loading.style.display = 'block';
    }

    try {
        await delay(500);
        if (pl) pl.textContent = 'Fetching OTX, ThreatFox, URLhaus, MalwareBazaar...';
        await delay(1000);
        if (pl) pl.textContent = 'Processing threat intelligence...';

        const res = await fetch('/fetch-all', { method: 'POST' });
        if (!res.ok) throw new Error(`Fetch-all failed (${res.status})`);
        const data = await res.json();

        sourceBtns.forEach(b => setSourceBtnState(b, 'done'));

        const breakdown = data.breakdown || {};
        const summary = Object.entries(breakdown)
            .map(([k, v]) => `${k}: ${v}`)
            .join(' · ');
        showToast(data.message + (summary ? ` (${summary})` : ''), 'success');

        if (pl) pl.textContent = 'Done! Reloading...';
        await delay(900);
        location.reload();
    } catch (err) {
        sourceBtns.forEach(b => setSourceBtnState(b, 'error'));
        if (errEl) errEl.textContent = err.message;
        hideProgress();
        btn.disabled  = false;
        btn.innerHTML = origHtml;
        showToast(err.message, 'danger');
    }
});

// ─── Insights Data ────────────────────────────────────────
async function loadInsightsData(timeFilter = 'all', threatFilter = 'all') {
    const insightsEl = document.getElementById('insights') || document.querySelector('.insights-section');
    if (!insightsEl) return;

    try {
        const params   = new URLSearchParams({ time: timeFilter, threat: threatFilter });
        const response = await fetch(`/api/insights?${params}`);
        if (!response.ok) return;
        const data = await response.json();

        updateMetrics(data.metrics);
        updateCharts(data);
        updateComparisonTable(data.comparison);
    } catch (err) {
        console.warn('Insights load error:', err);
    }
}

function updateMetrics(m) {
    animateCount('totalThreats', m.total);
    animateCount('activeThreats', m.active);
    animateCount('categoriesCount', m.categories);
    const confEl = document.getElementById('avgConfidence');
    if (confEl) confEl.textContent = `${m.avgConfidence}%`;
}

function animateCount(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const duration = 800;
    const startTime = performance.now();
    const step = (now) => {
        const progress = Math.min((now - startTime) / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(target * ease);
        if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
}

const CHART_COLORS = ['#dc2626','#0284c7','#16a34a','#7c3aed','#d97706','#f97316','#3b82f6','#64748b'];

function getChartOptions(type = 'default') {
    const gridColor = 'rgba(15,23,42,0.05)';
    const tickColor = '#94a3b8';
    const base = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { labels: { color: '#475569', font: { size: 11 }, padding: 16 } },
            tooltip: {
                backgroundColor: 'rgba(255,255,255,0.97)',
                titleColor: '#0f172a',
                bodyColor: '#475569',
                borderColor: 'rgba(2,132,199,0.2)',
                borderWidth: 1,
                padding: 12,
                cornerRadius: 8
            }
        },
        scales: {
            x: { grid: { color: gridColor }, ticks: { color: tickColor, font: { size: 10 } }, border: { color: gridColor } },
            y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: tickColor, font: { size: 10 } }, border: { color: gridColor } }
        }
    };
    if (type === 'doughnut') { delete base.scales; return base; }
    if (type === 'horizontal') { base.indexAxis = 'y'; return base; }
    return base;
}

function updateCharts(data) {
    const destroy = (key) => { if (insightsCharts[key]) { insightsCharts[key].destroy(); delete insightsCharts[key]; } };

    destroy('trends');
    const trendsCtx = document.getElementById('trendsChart');
    if (trendsCtx) {
        insightsCharts.trends = new Chart(trendsCtx, {
            type: 'line',
            data: {
                labels: data.trends.labels,
                datasets: [{ label: 'Threats', data: data.trends.data, borderColor: '#0284c7', backgroundColor: 'rgba(2,132,199,0.07)', tension: 0.45, fill: true, pointBackgroundColor: '#0284c7', pointRadius: 3, pointHoverRadius: 6, borderWidth: 2 }]
            },
            options: { ...getChartOptions(), plugins: { ...getChartOptions().plugins, legend: { display: false } } }
        });
    }

    destroy('confidence');
    const confCtx = document.getElementById('confidenceChart');
    if (confCtx) {
        insightsCharts.confidence = new Chart(confCtx, {
            type: 'bar',
            data: { labels: ['0–20%','21–40%','41–60%','61–80%','81–100%'], datasets: [{ data: data.confidenceDistribution, backgroundColor: ['#dc2626','#f97316','#d97706','#7c3aed','#16a34a'], borderRadius: 5, borderWidth: 0 }] },
            options: { ...getChartOptions(), plugins: { ...getChartOptions().plugins, legend: { display: false } } }
        });
    }

    destroy('source');
    const srcCtx = document.getElementById('sourceChart');
    if (srcCtx) {
        insightsCharts.source = new Chart(srcCtx, {
            type: 'doughnut',
            data: { labels: data.sourceDistribution.labels, datasets: [{ data: data.sourceDistribution.data, backgroundColor: ['#0284c7','#16a34a','#d97706','#dc2626'], borderWidth: 0, hoverBorderColor: '#fff', hoverBorderWidth: 2, hoverOffset: 6 }] },
            options: { ...getChartOptions('doughnut'), cutout: '60%', plugins: { ...getChartOptions('doughnut').plugins, legend: { position: 'bottom', labels: { color: '#475569', padding: 14, font: { size: 11 } } } } }
        });
    }

    destroy('topCat');
    const topCtx = document.getElementById('topCategoriesChart');
    if (topCtx) {
        insightsCharts.topCat = new Chart(topCtx, {
            type: 'bar',
            data: { labels: data.topCategories.labels, datasets: [{ data: data.topCategories.data, backgroundColor: CHART_COLORS, borderRadius: 5, borderWidth: 0 }] },
            options: { ...getChartOptions('horizontal'), plugins: { ...getChartOptions().plugins, legend: { display: false } } }
        });
    }

    destroy('timeline');
    const timeCtx = document.getElementById('timelineChart');
    if (timeCtx && data.timeline?.length) {
        insightsCharts.timeline = new Chart(timeCtx, {
            type: 'scatter',
            data: { datasets: [{ label: 'Events', data: data.timeline, backgroundColor: '#7c3aed', borderColor: '#7c3aed', pointRadius: 5, pointHoverRadius: 8 }] },
            options: { ...getChartOptions(), scales: { x: { type: 'time', time: { unit: 'day' }, grid: { color: 'rgba(15,23,42,0.05)' }, ticks: { color: '#94a3b8' } }, y: { beginAtZero: true, grid: { color: 'rgba(15,23,42,0.05)' }, ticks: { color: '#94a3b8' } } } }
        });
    }
}

function updateComparisonTable(comparison) {
    const tbody = document.getElementById('comparisonBody');
    if (!tbody) return;
    if (!comparison || comparison.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:24px;font-style:italic;">No data available</td></tr>`;
        return;
    }
    tbody.innerHTML = comparison.map(item => `
        <tr>
            <td style="font-family:var(--font-mono);font-size:0.82rem;">${item.category}</td>
            <td>${item.total}</td>
            <td>${item.avgConfidence}%</td>
            <td><span style="color:${item.trend >= 0 ? 'var(--green)' : 'var(--red)'};font-family:var(--font-mono);font-size:0.8rem;">
                <i class="fas fa-arrow-${item.trend >= 0 ? 'up' : 'down'}"></i> ${Math.abs(item.trend)}%
            </span></td>
            <td><span class="status-badge status-${item.status}">${item.status.toUpperCase()}</span></td>
        </tr>
    `).join('');
}

// ─── Filter Handlers ──────────────────────────────────────
document.getElementById('applyFilters')?.addEventListener('click', () => {
    const t = document.getElementById('timeFilter')?.value || 'all';
    const c = document.getElementById('threatFilter')?.value || 'all';
    loadInsightsData(t, c);
});

document.getElementById('refreshData')?.addEventListener('click', () => {
    const t = document.getElementById('timeFilter')?.value || 'all';
    const c = document.getElementById('threatFilter')?.value || 'all';
    loadInsightsData(t, c);
});

// ─── Card Scroll Animations ───────────────────────────────
function initCardAnimations() {
    if (!('IntersectionObserver' in window)) return;
    const obs = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.animationPlayState = 'running';
                obs.unobserve(entry.target);
            }
        });
    }, { threshold: 0.08 });

    document.querySelectorAll('.feature-card, .threat-card, .metric-card').forEach(el => {
        el.style.animationPlayState = 'paused';
        obs.observe(el);
    });
}

// ─── Mobile Nav ───────────────────────────────────────────
function toggleMobileNav() {
    document.getElementById('mobileNavDrawer')?.classList.toggle('open');
}

// ─── Utility ──────────────────────────────────────────────
function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// ─── Init on load ─────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initCardAnimations();
});