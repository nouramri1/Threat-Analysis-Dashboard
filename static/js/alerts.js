// alerts.js
function getThreatLevelClass(threatLevel, isRow = false) {
  const prefix = isRow ? 'table-' : 'bg-';
  switch(threatLevel?.toLowerCase()) {
    case 'high': return isRow ? 'table-danger' : 'bg-danger';
    case 'medium': return isRow ? 'table-warning' : 'bg-warning text-dark';
    case 'low': return isRow ? 'table-success' : 'bg-success';
    default: return isRow ? '' : 'bg-secondary';
  }
}

function showIPDetails(ip) {
  if (!ip) return;

  // Helper: safe accessor
  const safe = (v, fallback='') => (typeof v === 'undefined' || v === null) ? fallback : v;

  // Try to find a matching threat actor from global THREAT_CONTEXT
  let threatActor = null;
  try {
    if (window.THREAT_CONTEXT && Array.isArray(window.THREAT_CONTEXT.threat_actors)) {
      threatActor = window.THREAT_CONTEXT.threat_actors.find(a => {
        // match by ip field or by listed ips or by name
        if (!a) return false;
        if (a.ip && a.ip === ip) return true;
        if (Array.isArray(a.ips) && a.ips.includes(ip)) return true;
        if (a.name && a.name.toLowerCase().includes(ip.toLowerCase())) return true;
        return false;
      }) || null;
    }
  } catch (e) {
    console.warn('THREAT_CONTEXT lookup failed', e);
  }

  // Show modal immediately with a loading state for snappier UX
  try {
    document.getElementById('ipDetailsModalLabel').textContent = `IP Details: ${ip}`;
    document.getElementById('ipDetailsContent').innerHTML = `
      <div class="d-flex align-items-center justify-content-center py-4">
        <div class="spinner-border text-info me-3" role="status"><span class="visually-hidden">Loading...</span></div>
        <div class="small text-muted">Loading IP context…</div>
      </div>`;
    new bootstrap.Modal(document.getElementById('ipDetailsModal')).show();
  } catch(e) { /* ignore */ }

  // Fetch canonical IP info from server and then render the modal enriched with threatActor and global context
  fetch(`/ipinfo?ip=${encodeURIComponent(ip)}`)
    .then(res => res.json())
    .then(ipInfo => {
      const ctx = window.THREAT_CONTEXT || {};
      const key_findings = Array.isArray(ctx.key_findings) ? ctx.key_findings : [];
      const strategic_recommendations = Array.isArray(ctx.strategic_recommendations) ? ctx.strategic_recommendations : [];

      // Build tabbed modal HTML
      const actor = threatActor || {};
      const threatLevel = safe(actor.threat_level, safe(ipInfo.threat_level, 'Unknown'));
      const riskScore = safe(actor.risk_score, safe(ipInfo.risk_score, 0));
      const sophistication = safe(actor.sophistication, 'N/A');
      const threatCount = safe(actor.threat_count, safe(ipInfo.total_events, 0));
      const attackTypes = Array.isArray(actor.attack_types) ? actor.attack_types : (actor.attack_type ? [actor.attack_type] : []);

      // Filter key findings for relevance (simple contains ip or actor name), fallback to top few
      const relevantFindings = key_findings.filter(f => {
        try {
          const txt = JSON.stringify(f).toLowerCase();
          if (txt.includes(ip.toLowerCase())) return true;
          if (actor.name && txt.includes((actor.name||'').toLowerCase())) return true;
          return false;
        } catch(e) { return false; }
      });
      let findingsToShow = relevantFindings.length ? relevantFindings.slice(0,10) : key_findings.slice(0,5);

      // If there are no findings available, synthesize a few example findings based on ipInfo
      if (!findingsToShow || findingsToShow.length === 0) {
        findingsToShow = [];
        if (ipInfo && ipInfo.total_events && ipInfo.total_events > 0) {
          findingsToShow.push({ title: 'Repeated suspicious activity', summary: `Observed ${ipInfo.total_events} related events in the selected time window.` });
        }
        if (ipInfo && ipInfo.is_malicious) {
          findingsToShow.push({ title: 'Known malicious IP', summary: 'IP is present in the known malicious IP list.' });
        }
        if (attackTypes && attackTypes.length) {
          findingsToShow.push({ title: 'Observed attack patterns', summary: `Detected attack types: ${attackTypes.join(', ')}.` });
        }
        if (findingsToShow.length === 0) {
          findingsToShow.push({ title: 'No explicit findings', summary: 'No specific findings were generated for this IP in the current context.' });
        }
      }

      // Modal HTML
      const html = `
        <div>
          <ul class="nav nav-tabs" id="ipDetailsTab" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="tab-summary" data-bs-toggle="tab" data-bs-target="#ip-tab-summary" type="button" role="tab">Summary</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="tab-findings" data-bs-toggle="tab" data-bs-target="#ip-tab-findings" type="button" role="tab">Findings</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="tab-recs" data-bs-toggle="tab" data-bs-target="#ip-tab-recs" type="button" role="tab">Recommendations</button>
            </li>
            <li class="nav-item" role="presentation">
              <button class="nav-link" id="tab-raw" data-bs-toggle="tab" data-bs-target="#ip-tab-raw" type="button" role="tab">Raw Data</button>
            </li>
          </ul>
          <div class="tab-content p-3" id="ipDetailsTabContent">
            <div class="tab-pane fade show active" id="ip-tab-summary" role="tabpanel">
              <div class="row">
                <div class="col-md-6">
                  <h6>Network & Geo</h6>
                  <p><strong>IP:</strong> ${ip}</p>
                  <p><strong>Hostname:</strong> ${safe(ipInfo.hostname,'Unknown')}</p>
                  <p><strong>ISP / ASN:</strong> ${safe(ipInfo.isp,'Unknown')} / ${safe(ipInfo.asn,'Unknown')}</p>
                  <p><strong>Location:</strong> ${safe(ipInfo.city,'')}, ${safe(ipInfo.region,'')}, ${safe(ipInfo.country,'')}</p>
                  <p><strong>Coordinates:</strong> ${safe(ipInfo.latitude,0)}, ${safe(ipInfo.longitude,0)}</p>
                </div>
                <div class="col-md-6">
                  <h6>Threat Overview</h6>
                  <p><strong>Threat Level:</strong> <span class="badge ${getThreatLevelClass(threatLevel)}">${threatLevel}</span></p>
                  <p><strong>Risk Score:</strong> ${riskScore}</p>
                  <p><strong>Sophistication:</strong> ${sophistication}</p>
                  <p><strong>Total Events:</strong> ${threatCount}</p>
                  <p><strong>Attack Types:</strong> ${attackTypes.length ? attackTypes.join(', ') : 'N/A'}</p>
                </div>
              </div>
            </div>
            <div class="tab-pane fade" id="ip-tab-findings" role="tabpanel">
              <div class="list-group">
                ${findingsToShow.length ? findingsToShow.map(f => `<div class="list-group-item"><div class="small fw-bold">${safe(f.title, safe(f.name, 'Finding'))}</div><div class="small text-muted">${safe(f.summary, JSON.stringify(f))}</div></div>`).join('') : '<div class="text-muted">No findings available</div>'}
              </div>
            </div>
            <div class="tab-pane fade" id="ip-tab-recs" role="tabpanel">
              <ul class="list-unstyled">
                ${strategic_recommendations.length ? strategic_recommendations.map(r => `<li class="mb-2">• ${r}</li>`).join('') : (function(){
                  // synthesize recommendations based on threat level
                  const recs = [];
                  const t = (''+threatLevel).toLowerCase();
                  if (t === 'high') {
                    recs.push('Isolate and block the IP at perimeter firewall.');
                    recs.push('Open an incident ticket and escalate to SOC.');
                    recs.push('Search historical logs for related activity and indicators.');
                  } else if (t === 'medium') {
                    recs.push('Apply rate-limiting and monitor closely.');
                    recs.push('Apply additional IDS/IPS signatures for observed attack types.');
                  } else {
                    recs.push('Monitor and collect additional telemetry; no immediate block recommended.');
                  }
                  return recs.map(r => `<li class="mb-2">• ${r}</li>`).join('');
                })()}
              </ul>
            </div>
            <div class="tab-pane fade" id="ip-tab-raw" role="tabpanel">
              <pre style="max-height:300px; overflow:auto; background:#11131a; color:#e5e7eb; padding:10px; border-radius:4px;">${escapeHtml(JSON.stringify(actor && Object.keys(actor).length ? actor : ipInfo, null, 2))}</pre>
            </div>
          </div>
        </div>
      `;

      document.getElementById('ipDetailsModalLabel').textContent = `IP Details: ${ip}`;
      document.getElementById('ipDetailsContent').innerHTML = html;
    })
    .catch(err => {
      console.error('Failed to load IP info or threat context', err);
      document.getElementById('ipDetailsContent').innerHTML = `
        <div class="text-center text-danger py-3">
          <div class="mb-2">Failed to fetch IP details</div>
          <small class="text-muted">Please try again later.</small>
        </div>`;
    });
}

// escape helper for raw JSON in pre
function escapeHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function fetchVulnerabilities() {
  try {
    const minutes = document.getElementById("timeRangeSelect")?.value || 25;
    const response = await fetch(`/vulnerabilities?minutes=${minutes}`);
    const data = await response.json();
    
    const container = document.getElementById("vulnerabilitiesContainer");
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
      container.innerHTML = '<div class="text-muted text-center p-3">No vulnerabilities detected</div>';
      return;
    }
    
    let html = '<div class="list-group list-group-flush">';
    data.vulnerabilities.slice(0, 25).forEach(vuln => {
      html += `
        <div class="list-group-item p-2">
          <div class="d-flex justify-content-between align-items-start">
            <div class="flex-grow-1">
              <div class="fw-bold small">${vuln.signature}</div>
              <small class="text-muted">${vuln.count} attempts (${vuln.percentage}%)</small>
            </div>
          </div>
        </div>
      `;
    });
    html += '</div>';
    container.innerHTML = html;
  } catch (error) {
    console.error('Error fetching vulnerabilities:', error);
  }
}

async function fetchTopOffenders() {
  try {
    const minutes = document.getElementById("timeRangeSelect")?.value || 15;
    const response = await fetch(`/alerts?minutes=${minutes}&limit=1000&aggregate=ip`);
    const data = await response.json();
    
    const container = document.getElementById("topOffendersContainer");
    if (!data.alerts || data.alerts.length === 0) {
      container.innerHTML = '<div class="text-muted text-center p-3">No offending IPs detected</div>';
      return;
    }
    
    // Sort by count and take top 10
    const topOffenders = data.alerts
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    
    let html = '<div class="list-group list-group-flush">';
    topOffenders.forEach(offender => {
      const threatLevel = offender.threat_level || 'Low';
      html += `
        <div class="list-group-item p-2">
          <div class="d-flex justify-content-between align-items-center">
            <div>
              <div class="fw-bold small">
                <a href="#" onclick="showIPDetails('${offender.ip}'); return false;" class="text-decoration-none">${offender.ip}</a>
              </div>
              <small class="text-muted">${offender.city || 'Unknown location'}</small>
            </div>
            <div class="text-end">
              <span class="badge ${getThreatLevelClass(threatLevel)} mb-1">${threatLevel}</span>
              <div><small class="text-muted">${offender.count} events</small></div>
            </div>
          </div>
        </div>
      `;
    });
    html += '</div>';
    container.innerHTML = html;
  } catch (error) {
    console.error('Error fetching top offenders:', error);
  }
}

async function fetchAlerts(){
  const mode = document.getElementById("alertViewMode")?.value || "raw";
  const minutes = document.getElementById("timeRangeSelect").value || 15;
  const aggregate = mode === "aggregate" ? "&aggregate=ip" : "";
  const res = await fetch(`/alerts?minutes=${minutes}&limit=200${aggregate}`);
  const json = await res.json();
  // store in cache and render with filters/pagination
  alertsCache = json.alerts || [];
  alertsPage = 1;
  applyAlertsFiltersAndRender();
  
  // Also fetch vulnerabilities and top offenders if we're in the alerts tab
  const activeTab = document.querySelector('#navigationTabs .nav-link.active');
  if (activeTab && activeTab.getAttribute('aria-controls') === 'alertsTab') {
    await fetchVulnerabilities();
    await fetchTopOffenders();
  }
}

let alertsCache = [];
let alertsPage = 1;
let alertsPerPage = 17; // paginate to 17 rows per page per your preference
let alertsLevelFilter = 'all'; // all|high|medium|low

function applyAlertsFiltersAndRender() {
  const search = (document.getElementById('alertsSearch')?.value || '').toLowerCase().trim();
  const sort = document.getElementById('alertsSort')?.value || 'time_desc';

  let rows = alertsCache.slice();
  if (search) {
    rows = rows.filter(r => {
      const text = JSON.stringify(r).toLowerCase();
      return text.includes(search);
    });
  }

  // filter by threat level if set
  if (alertsLevelFilter !== 'all') {
    const target = alertsLevelFilter.toLowerCase();
    rows = rows.filter(r => (r.threat_level||'').toLowerCase() === target);
  }

  // sorting
  rows.sort((a, b) => {
    switch (sort) {
      case 'time_asc': return new Date(a.timestamp || a.last_seen) - new Date(b.timestamp || b.last_seen);
      case 'time_desc': return new Date(b.timestamp || b.last_seen) - new Date(a.timestamp || a.last_seen);
      case 'ip': return (a.ip||a.src_ip||'').localeCompare(b.ip||b.src_ip||'');
      case 'severity': return (b.threat_level||'').localeCompare(a.threat_level||'');
      case 'count': return (b.count||0) - (a.count||0);
      default: return 0;
    }
  });

  const totalPages = Math.max(1, Math.ceil(rows.length / alertsPerPage));
  if (alertsPage > totalPages) alertsPage = totalPages;
  document.getElementById('alertsTotalPages').textContent = totalPages;
  document.getElementById('alertsPageInput').value = alertsPage;

  const start = (alertsPage - 1) * alertsPerPage;
  const pageRows = rows.slice(start, start + alertsPerPage);
  renderAlertsTable(pageRows, rows.length === 0);
}

function renderAlertsTable(rows, empty=false){
  const container = document.getElementById("alertsContainer");
  container.innerHTML = "";
  if(empty || !rows.length){
    container.innerHTML = `
      <div class='text-center text-muted p-4'>
        <i class="bi bi-shield-check" style="font-size: 3rem; opacity: 0.3;"></i>
        <div>No alerts in the selected time range</div>
        <small>All systems operating normally</small>
      </div>`;
    return;
  }

  const table = document.createElement('table');
  table.className = 'table table-hover table-sm mb-0';
  table.innerHTML = `
    <thead class="table-light">
      <tr>
        <th class="ip-col">Source IP</th>
        <th>Signature/Location</th>
        <th>Time</th>
        <th>Threat Level</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;

  const tbody = table.querySelector('tbody');
  rows.forEach(r => {
    const tr = document.createElement('tr');
    const threatLevel = r.threat_level || 'Low';
    tr.className = getThreatLevelClass(threatLevel, true);
    const time = r.timestamp ? new Date(r.timestamp).toLocaleString() : (r.last_seen ? new Date(r.last_seen).toLocaleString() : '');

    const ipCell = document.createElement('td');
    ipCell.classList.add('ip-col');
    const ipVal = r.ip || r.src_ip || '';
    ipCell.innerHTML = `<strong><a href="#" class="text-decoration-none">${ipVal}</a></strong>`;
    ipCell.querySelector('a').addEventListener('click', (e)=>{ e.preventDefault(); showIPDetails(ipVal); });

    const sigCell = document.createElement('td');
    sigCell.innerHTML = `<div class="small">${r.signature || r.city || 'Unknown'}</div><small class="text-muted">${r.count? r.count+' attempts':''}</small>`;

    const timeCell = document.createElement('td'); timeCell.textContent = time;

    const threatCell = document.createElement('td');
    threatCell.innerHTML = `<span class="badge ${getThreatLevelClass(threatLevel)}">${threatLevel}</span> ${r.suspicious?'<span class="badge bg-warning text-dark ms-1">Suspicious</span>':''}`;

    const actionsCell = document.createElement('td');
    // Actions dropdown
    actionsCell.innerHTML = `
      <div class="btn-group">
        <button class="btn btn-sm btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown">Actions</button>
        <ul class="dropdown-menu dropdown-menu-end">
          <li><a class="dropdown-item" href="#" data-action="details">View Details</a></li>
          <li><a class="dropdown-item" href="#" data-action="locate">Locate Source</a></li>
          <li><a class="dropdown-item" href="#" data-action="block">Block</a></li>
          <li><a class="dropdown-item" href="#" data-action="allow">Allow</a></li>
        </ul>
      </div>
    `;

    // attach action handlers
    const actionItems = actionsCell.querySelectorAll('.dropdown-item');
    actionItems.forEach(it => it.addEventListener('click', (ev)=>{
      ev.preventDefault();
      const act = it.dataset.action;
      if(act === 'details') showIPDetails(ipVal);
      else if(act === 'locate') centerMap(r.lat || r.lat, r.lon || r.lon);
      else if(act === 'block') simulateAction(ipVal, 'block', tr);
      else if(act === 'allow') simulateAction(ipVal, 'allow', tr);
    }));

    tr.appendChild(ipCell);
    tr.appendChild(sigCell);
    tr.appendChild(timeCell);
    tr.appendChild(threatCell);
    tr.appendChild(actionsCell);
    tbody.appendChild(tr);
  });

  container.appendChild(table);
}

function simulateAction(ip, action, rowEl) {
  // optimistic UI change
  if(action === 'block') {
    const badge = document.createElement('span'); badge.className = 'badge bg-danger ms-2'; badge.textContent = 'Blocked';
    const td = rowEl.querySelector('td:nth-child(4)');
    if(td) td.appendChild(badge);
  } else {
    const badge = document.createElement('span'); badge.className = 'badge bg-success ms-2'; badge.textContent = 'Allowed';
    const td = rowEl.querySelector('td:nth-child(4)');
    if(td) td.appendChild(badge);
  }
}

function centerMap(lat, lon) {
  if(window.map && lat && lon) {
    // Switch to map tab first
    const mapTab = document.getElementById('map-tab');
    const tab = new bootstrap.Tab(mapTab);
    tab.show();
    
    // Wait for tab transition then drill down to the location
    setTimeout(() => {
      drillToLocation(lat, lon);
    }, 200);
  }
}

async function drillToLocation(lat, lon) {
  try {
    // Reset map state first
    if (window.currentLevel && window.breadcrumbPath) {
      window.currentLevel = "continent";
      window.breadcrumbPath = [];
      window.map.setView([29.0283, -81.3031], 4);
      await fetchMapData("continent");
      updateBreadcrumb();
    }
    
    // Find the best zoom level and drill down through the hierarchy
    const levels = ["continent", "region", "country", "city"];
    let targetLevel = "city"; // Default to most detailed level
    
    // Drill down through each level
    for (let i = 0; i < levels.length; i++) {
      const level = levels[i];
      
      // Fetch data for current level
      const minutes = document.getElementById("timeRangeSelect")?.value || 15;
      const response = await fetch(`/data?level=${level}&minutes=${minutes}&top_k=200`);
      const geoData = await response.json();
      
      // Find the feature that contains our target location
      let targetFeature = null;
      let minDistance = Infinity;
      
      if (geoData.features) {
        geoData.features.forEach(feature => {
          const [fLon, fLat] = feature.geometry.coordinates;
          const distance = Math.sqrt(Math.pow(lat - fLat, 2) + Math.pow(lon - fLon, 2));
          if (distance < minDistance) {
            minDistance = distance;
            targetFeature = feature;
          }
        });
      }
      
      if (targetFeature && i < levels.length - 1) {
        // Add to breadcrumb path
        const p = targetFeature.properties;
        const [fLon, fLat] = targetFeature.geometry.coordinates;
        window.breadcrumbPath.push({ 
          label: p.label, 
          level: levels[i + 1], 
          lat: fLat, 
          lon: fLon 
        });
        
        // Update current level
        window.currentLevel = levels[i + 1];
        
        // Fetch and render the next level
        await fetchMapData(levels[i + 1]);
        updateBreadcrumb();
      }
    }
    
    // Final zoom to the exact location
    window.map.flyTo([lat, lon], 12, {
      animate: true,
      duration: 1.5
    });
    
  } catch (error) {
    console.error('Error drilling to location:', error);
    // Fallback: just center the map at the location
    window.map.setView([lat, lon], 10);
  }
}

function clearAlerts() {
  const container = document.getElementById("alertsContainer");
  container.innerHTML = `
    <div class='text-center text-muted p-4'>
      <i class="bi bi-trash3" style="font-size: 3rem; opacity: 0.3;"></i>
      <div>Alerts cleared</div>
      <small>Will refresh automatically</small>
    </div>`;
  
  // Refresh after a short delay
  setTimeout(fetchAlerts, 2000);
}

// wire up view mode change
document.addEventListener("DOMContentLoaded", () => {
  const alertViewMode = document.getElementById("alertViewMode");
  const clearAlertsBtn = document.getElementById("clearAlerts");
  const timeRangeSelect = document.getElementById("timeRangeSelect");
  const alertsSearch = document.getElementById('alertsSearch');
  const alertsSort = document.getElementById('alertsSort');
  const alertsLevelSel = document.getElementById('alertsLevelFilter');
  const firstBtn = document.getElementById('alertsFirst');
  const prevBtn = document.getElementById('alertsPrev');
  const nextBtn = document.getElementById('alertsNext');
  const lastBtn = document.getElementById('alertsLast');
  const pageInput = document.getElementById('alertsPageInput');
  const navLinks = document.querySelectorAll('#navigationTabs .nav-link');
  
  if (alertViewMode) {
    alertViewMode.addEventListener("change", fetchAlerts);
  }
  
  if (clearAlertsBtn) {
    clearAlertsBtn.addEventListener("click", clearAlerts);
  }
  
  if (timeRangeSelect) {
    timeRangeSelect.addEventListener("change", fetchAlerts);
  }

  if (alertsSort) alertsSort.addEventListener('change', ()=>{ alertsPage=1; applyAlertsFiltersAndRender(); });
  if (alertsLevelSel) alertsLevelSel.addEventListener('change', ()=>{ alertsLevelFilter = alertsLevelSel.value || 'all'; alertsPage=1; applyAlertsFiltersAndRender(); });
  if (alertsSearch) {
    let debounce = null;
    alertsSearch.addEventListener('input', ()=>{
      clearTimeout(debounce);
      debounce = setTimeout(()=>{ alertsPage=1; applyAlertsFiltersAndRender(); }, 350);
    });
  }

  if (firstBtn) firstBtn.addEventListener('click', ()=>{ alertsPage=1; applyAlertsFiltersAndRender(); });
  if (prevBtn) prevBtn.addEventListener('click', ()=>{ if(alertsPage>1) alertsPage--; applyAlertsFiltersAndRender(); });
  if (nextBtn) nextBtn.addEventListener('click', ()=>{ alertsPage++; applyAlertsFiltersAndRender(); });
  if (lastBtn) lastBtn.addEventListener('click', ()=>{ alertsPage = parseInt(document.getElementById('alertsTotalPages').textContent) || alertsPage; applyAlertsFiltersAndRender(); });
  if (pageInput) pageInput.addEventListener('change', ()=>{ const v = parseInt(pageInput.value)||1; alertsPage = Math.max(1,v); applyAlertsFiltersAndRender(); });
  
  // Toggle page-theme classes on body based on active tab
  const applyPageTheme = () => {
    const activeTab = document.querySelector('#navigationTabs .nav-link.active');
    const body = document.body;
    body.classList.remove('page-alerts','page-stats','page-map');
    const id = activeTab ? activeTab.getAttribute('aria-controls') : '';
    if (id === 'alertsTab') body.classList.add('page-alerts');
    else if (id === 'statsTab') body.classList.add('page-stats');
    else if (id === 'mapTab') body.classList.add('page-map');
  };
  if (navLinks && navLinks.length) {
    navLinks.forEach(link => link.addEventListener('shown.bs.tab', applyPageTheme));
  }
  // Apply initial theme
  applyPageTheme();
  
  // Only auto-refresh alerts if we're not in the stats tab
  setInterval(() => {
    const activeTab = document.querySelector('#navigationTabs .nav-link.active');
    if (activeTab && activeTab.getAttribute('aria-controls') !== 'statsTab') {
      fetchAlerts();
    }
  }, 7000);
  // initial fetch
  fetchAlerts();
});
