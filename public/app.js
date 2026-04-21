// ── Config ────────────────────────────────────
const REFRESH_MS = 5000;

// ── Chart Instances ───────────────────────────
let timelineChart, protoChart;

// ── Init Charts ───────────────────────────────
function initCharts() {
  Chart.defaults.color       = '#3a6080';
  Chart.defaults.borderColor = '#0f2a40';

  // Timeline Line Chart
  const tlCtx = document.getElementById('timelineChart').getContext('2d');
  timelineChart = new Chart(tlCtx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Packets',
        data: [],
        borderColor: '#00e5ff',
        backgroundColor: 'rgba(0,229,255,0.08)',
        borderWidth: 2,
        pointRadius: 2,
        pointBackgroundColor: '#00e5ff',
        tension: 0.4,
        fill: true,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: '#3a6080', maxTicksLimit: 6, font: { family: 'Share Tech Mono', size: 10 } },
          grid:  { color: '#0f2a40' }
        },
        y: {
          ticks: { color: '#3a6080', font: { family: 'Share Tech Mono', size: 10 } },
          grid:  { color: '#0f2a40' }
        }
      }
    }
  });

  // Protocol Doughnut Chart
  const prCtx = document.getElementById('protoChart').getContext('2d');
  protoChart = new Chart(prCtx, {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: ['#00e5ff','#00ff88','#ffd600','#ff6d2e','#b388ff','#ff80ab','#607d8b'],
        borderColor: '#0a1520',
        borderWidth: 3,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#c8e0f0',
            font: { family: 'Share Tech Mono', size: 11 },
            padding: 12,
            boxWidth: 12
          }
        }
      }
    }
  });
}

// ── Clock ─────────────────────────────────────
function updateClock() {
  document.getElementById('clock').textContent =
    new Date().toLocaleTimeString('en-IN', { hour12: false });
}

// ── Refresh Progress Bar ──────────────────────
function animateRefreshBar() {
  const bar = document.getElementById('refresh-bar');
  bar.style.transition = 'none';
  bar.style.width = '0%';
  setTimeout(() => {
    bar.style.transition = `width ${REFRESH_MS}ms linear`;
    bar.style.width = '100%';
  }, 50);
}

// ── Render Stats ──────────────────────────────
function renderStats(d) {
  document.getElementById('total-packets').textContent = d.total_packets.toLocaleString();
  document.getElementById('total-alerts').textContent  = d.total_alerts.toLocaleString();
  document.getElementById('http-count').textContent    = (d.protocols['HTTP'] || 0).toLocaleString();
  document.getElementById('ssh-count').textContent     = (d.protocols['SSH']  || 0).toLocaleString();
}

// ── Render Charts ─────────────────────────────
function renderCharts(d) {
  if (d.timeline.length) {
    timelineChart.data.labels              = d.timeline.map(t => t.time.slice(11));
    timelineChart.data.datasets[0].data   = d.timeline.map(t => t.count);
    timelineChart.update('none');
  }

  if (Object.keys(d.protocols).length) {
    protoChart.data.labels                = Object.keys(d.protocols);
    protoChart.data.datasets[0].data      = Object.values(d.protocols);
    protoChart.update('none');
  }
}

// ── Render Alerts ─────────────────────────────
function renderAlerts(alerts) {
  const el = document.getElementById('alert-list');
  if (!alerts.length) return;

  el.innerHTML = alerts.map(a => `
    <div class="alert-item">
      <span class="alert-badge badge-${a.severity}">${a.severity}</span>
      <div>
        <div class="alert-msg">${a.message}</div>
        <div class="alert-time">${a.timestamp}</div>
      </div>
    </div>
  `).join('');
}

// ── Render Top IPs ────────────────────────────
function renderTopIPs(ips) {
  const el = document.getElementById('top-ips');
  if (!ips.length) return;

  const max = ips[0].count || 1;
  el.innerHTML = ips.map(ip => `
    <div class="ip-row">
      <div class="ip-label">${ip.ip}</div>
      <div class="ip-bar-wrap">
        <div class="ip-bar" style="width:${(ip.count / max * 100).toFixed(1)}%"></div>
      </div>
      <div class="ip-count">${ip.count}</div>
    </div>
  `).join('');
}

// ── Render Packet Table ───────────────────────
function renderPackets(packets) {
  const tbody = document.getElementById('pkt-tbody');
  if (!packets.length) return;

  tbody.innerHTML = packets.map(p => `
    <tr>
      <td><span class="proto-badge proto-${p.protocol}">${p.protocol}</span></td>
      <td>${p.src_ip}</td>
      <td>${p.dst_port}</td>
      <td>${p.packet_size}B</td>
      <td style="color:var(--dim)">${p.flags || '—'}</td>
    </tr>
  `).join('');
}

// ── Fetch & Render All ────────────────────────
async function fetchAndRender() {
  try {
    const res = await fetch('/api/stats');
    const d   = await res.json();

    renderStats(d);
    renderCharts(d);
    renderAlerts(d.recent_alerts);
    renderTopIPs(d.top_ips);
    renderPackets(d.recent_packets);

  } catch (e) {
    console.warn('Fetch error:', e);
  }
  animateRefreshBar();
}

// ── Boot ──────────────────────────────────────
initCharts();
updateClock();
setInterval(updateClock, 1000);
fetchAndRender();
setInterval(fetchAndRender, REFRESH_MS);