// dashboard.js
document.addEventListener("DOMContentLoaded", () => {
  const refreshBtn = document.getElementById("refreshAll");
  refreshBtn.addEventListener("click", refreshAll);

  // time range control
  document.getElementById("timeRangeSelect").addEventListener("change", () => {
    document.getElementById("kpiWindow").textContent = document.getElementById("timeRangeSelect").value + "m";
    refreshAll();
  });

  // tab switching handlers
  const tabTriggerList = [].slice.call(document.querySelectorAll('#navigationTabs a[data-bs-toggle="tab"]'));
  tabTriggerList.forEach(function (tabTriggerEl) {
    tabTriggerEl.addEventListener('shown.bs.tab', function (event) {
      const activeTab = event.target.getAttribute('aria-controls');
      if (activeTab === 'statsTab') {
        refreshStats();
      }
    });
  });

  // initialize charts
  // Dark theme defaults for charts
  Chart.defaults.color = '#e5e7eb';
  Chart.defaults.borderColor = 'rgba(229, 231, 235, 0.2)';
  window.eventsChart = new Chart(document.getElementById("chartEvents"), {
    type: "line",
    data: { labels: [], datasets: [{ label: "Events", data: [], fill: true, tension: 0.3, borderColor: '#36A2EB', backgroundColor: 'rgba(54,162,235,0.15)' }] },
    options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { grid: { color: 'rgba(229,231,235,0.1)' } }, y: { grid: { color: 'rgba(229,231,235,0.1)' }, beginAtZero: true } } }
  });

  // initialize stats charts
  initializeStatsCharts();

  // initial refresh
  refreshAll();
  setInterval(refreshAll, 7000);
});

function initializeStatsCharts() {
  // Location distribution chart
  window.statsLocationChart = new Chart(document.getElementById("statsLocationChart"), {
    type: "doughnut",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: ['#ef4444', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#e5e7eb' } }
      }
    }
  });

  // Attack types chart
  window.statsAttackChart = new Chart(document.getElementById("statsAttackChart"), {
    type: "bar",
    data: {
      labels: [],
      datasets: [{
        label: 'Events',
        data: [],
        backgroundColor: 'rgba(239,68,68,0.6)'
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { grid: { color: 'rgba(229,231,235,0.1)' } },
        y: { beginAtZero: true, grid: { color: 'rgba(229,231,235,0.1)' } }
      }
    }
  });
}

async function refreshAll(){
  // Only refresh map if not locked
  if (!window.mapLocked) {
    await Promise.all([fetchMetrics(), fetchMapData(), fetchAlerts()]);
  } else {
    await Promise.all([fetchMetrics(), fetchAlerts()]);
  }
  document.getElementById("lastUpdated").textContent = "Updated: " + new Date().toLocaleString();
}

async function refreshStats(){
  const minutes = document.getElementById("timeRangeSelect").value;
  const [metricsRes, alertsRes] = await Promise.all([
    fetch(`/metrics?minutes=${minutes}`),
    fetch(`/alerts?minutes=${minutes}&limit=1000`)
  ]);
  
  const metrics = await metricsRes.json();
  const alerts = await alertsRes.json();

  // Update basic stats
  document.getElementById("stats-total-events").textContent = metrics.total_events;
  document.getElementById("stats-blocked-events").textContent = metrics.blocked_events;
  document.getElementById("stats-unique-ips").textContent = metrics.unique_source_ips;
  
  const blockRate = metrics.total_events > 0 ? 
    Math.round((metrics.blocked_events / metrics.total_events) * 100) : 0;
  document.getElementById("stats-blocked-ratio").textContent = blockRate + "%";

  // Update signature table
  const tbody = document.getElementById("statsSignatureTable");
  tbody.innerHTML = "";
  
  if (metrics.top_signatures && metrics.top_signatures.length > 0) {
    metrics.top_signatures.forEach(sig => {
      const row = tbody.insertRow();
      const percentage = metrics.total_events > 0 ? 
        Math.round((sig.count / metrics.total_events) * 100) : 0;
      row.innerHTML = `
        <td class="small">${sig.sig}</td>
        <td class="text-end">${sig.count}</td>
        <td class="text-end">${percentage}%</td>
      `;
    });
  } else {
    tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No data available</td></tr>';
  }

  // Update location chart
  if (alerts.alerts && alerts.alerts.length > 0) {
    const locationCounts = {};
    const attackTypes = {};
    
    alerts.alerts.forEach(alert => {
      // Group by city or region
      const location = alert.city || alert.region || 'Unknown';
      locationCounts[location] = (locationCounts[location] || 0) + 1;
      
      // Group by signature for attack types
      const signature = alert.signature || 'Unknown';
      attackTypes[signature] = (attackTypes[signature] || 0) + 1;
    });

    // Update location chart
    const locationLabels = Object.keys(locationCounts).slice(0, 5);
    const locationData = locationLabels.map(label => locationCounts[label]);
    
    window.statsLocationChart.data.labels = locationLabels;
    window.statsLocationChart.data.datasets[0].data = locationData;
    window.statsLocationChart.update();

    // Update attack types chart
    const attackLabels = Object.keys(attackTypes).slice(0, 5);
    const attackData = attackLabels.map(label => attackTypes[label]);
    
    window.statsAttackChart.data.labels = attackLabels.map(label => 
      label.length > 20 ? label.substring(0, 20) + '...' : label
    );
    window.statsAttackChart.data.datasets[0].data = attackData;
    window.statsAttackChart.update();
  }
}

async function fetchMetrics(){
  const minutes = document.getElementById("timeRangeSelect").value;
  const res = await fetch(`/metrics?minutes=${minutes}`);
  const json = await res.json();
  document.getElementById("kpi-total").textContent = json.total_events;
  document.getElementById("kpi-blocked").textContent = json.blocked_events;
  
  // Update threat level KPIs
  const threatLevels = json.threat_levels || { Low: 0, Medium: 0, High: 0 };
  const highEl = document.getElementById("kpi-high-threats");
  const mediumEl = document.getElementById("kpi-medium-threats");
  const lowEl = document.getElementById("kpi-low-threats");
  
  if (highEl) highEl.textContent = threatLevels.High || 0;
  if (mediumEl) mediumEl.textContent = threatLevels.Medium || 0;
  if (lowEl) lowEl.textContent = threatLevels.Low || 0;
  
  // top signatures
  const ul = document.getElementById("topSigs");
  ul.innerHTML = "";
  (json.top_signatures || []).forEach(s => {
    const li = document.createElement("li");
    li.textContent = `${s.sig} — ${s.count}`;
    ul.appendChild(li);
  });
  // update events chart (fake histogram from metrics using a simple synthetic approach)
  updateEventsChart(json.total_events);
}

function updateEventsChart(total){
  const ch = window.eventsChart;
  // simple rolling window: push total as latest point
  if (ch.data.labels.length > 12){
    ch.data.labels.shift(); ch.data.datasets[0].data.shift();
  }
  ch.data.labels.push(new Date().toLocaleTimeString());
  ch.data.datasets[0].data.push(total);
  ch.update();
}
