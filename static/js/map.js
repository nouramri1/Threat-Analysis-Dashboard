// map.js
let map, bubbleLayer, currentLevel = "continent";
window.mapLocked = false; // Prevent auto-refresh when drilling down
let breadcrumbPath = [];
// initial state saved on first load so Refresh can revert to it
// North America default view at continent level (slightly closer)
let initialState = { level: 'continent', center: [40.0, -100.0], zoom: 3 };
let severityChart = null;

// --- Helper to standardize raw geographic labels ---
// Assumes raw label format is typically: Continent || State/Region || Country || City
// Returns an object with segments in the desired display order: Continent, Country, State, City
function getOrderedLabels(rawLabel) {
    const rawParts = (rawLabel || '').toString().split('||').map(s => s.trim()).filter(Boolean);
    const ordered = {};
    // Continent is always the first part if present
    if (rawParts.length >= 1) ordered.continent = rawParts[0];
    // Country is typically the third part in the raw data (index 2)
    if (rawParts.length >= 3) ordered.country = rawParts[2];
    // State/Region is typically the second part (index 1)
    if (rawParts.length >= 2) ordered.state = rawParts[1];
    // City is typically the fourth part (index 3)
    if (rawParts.length >= 4) ordered.city = rawParts[3];
    return ordered;
}

// --- Drill Status Banner Logic ---
(function(){
  const statusId = 'drillStatus';
  function ensureDrillStatus() {
    let el = document.getElementById(statusId);
    if (!el) {
      el = document.createElement('div');
      el.id = statusId;
      el.className = 'drill-status-banner alert alert-dark sticky-top mb-0 py-2';
      const container = document.querySelector('.main-content') || document.body;
      container.prepend(el);
    }
    return el;
  }

  function setDrillStatus(level, label) {
    const el = ensureDrillStatus();
    const levelTitle = ({
      continent: 'Continent',
      country: 'Country',
      state: 'State/Region',
      city: 'City',
      point: 'Point'
    })[level] || 'Global';
    el.innerHTML = `<i class="bi bi-geo-alt-fill me-2"></i> Viewing: <strong>${levelTitle}</strong>${label ? ` &mdash; ${label}` : ''}`;
  }
  // Expose setDrillStatus globally for use in map.js fetch/render functions
  window.setDrillStatus = setDrillStatus;
})();

function initMap(){
    map = L.map("map").setView(initialState.center, initialState.zoom);
    // Dark-themed map tiles (CartoDB Dark Matter)
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: '&copy; OpenStreetMap &copy; CartoDB',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(map);
    bubbleLayer = L.layerGroup().addTo(map);

    // Save initial state now that map exists
    try{
        initialState.center = map.getCenter() ? [map.getCenter().lat, map.getCenter().lng] : initialState.center;
        initialState.zoom = map.getZoom() || initialState.zoom;
        initialState.level = currentLevel || initialState.level;
    }catch(e){}
    // Ensure the map renders without gaps after layout settles and on resize
    setTimeout(()=>{ try{ map.invalidateSize(); } catch(_){} }, 200);
    window.addEventListener('resize', ()=>{ try{ map.invalidateSize(); } catch(_){} });
}

function ensureSeverityChart() {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    if (severityChart) return;
    severityChart = new Chart(ctx.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['High','Medium','Low'],
            datasets: [{ data: [0,0,0], backgroundColor: ['#dc3545','#ffc107','#198754'] }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

function updateBreadcrumb() {
    const breadcrumbEl = document.getElementById("breadcrumb");
    if (breadcrumbPath.length === 0) {
        // If no drill down, show the current level
        const currentLevelTitle = ({
            continent: 'Continent',
            country: 'Country',
            state: 'State/Region',
            city: 'City',
            point: 'Points'
        })[currentLevel] || 'Global';
        breadcrumbEl.innerHTML = `<span class="crumb-current">${currentLevelTitle}</span>`;
    } else {
        // Build breadcrumb using the simple, correct labels stored in the path
        const parts = breadcrumbPath.map((item, index) => {
            const leaf = item.label; // Use the stored friendly name
            if (index === breadcrumbPath.length - 1) {
                return `<span class="crumb-current">${leaf}</span>`;
            }
            // Use the index for slicing and re-navigation
            return `<a href="#" class="breadcrumb-link text-decoration-none" data-level="${item.level}" data-index="${index}" data-target-lat="${item.lat}" data-target-lon="${item.lon}">${leaf}</a>`;
        });
        breadcrumbEl.innerHTML = parts.join('<span class="crumb-sep">›</span>');

        // Add click handlers for breadcrumb navigation
        breadcrumbEl.querySelectorAll('.breadcrumb-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const index = parseInt(e.target.dataset.index);
                navigateToBreadcrumb(index);
            });
        });
    }
}

function navigateToBreadcrumb(index) {
    // Determine the target crumb and its level *before* slicing the array
    const targetCrumb = breadcrumbPath[index];
    
    // Trim breadcrumb path to the selected index (inclusive)
    breadcrumbPath = breadcrumbPath.slice(0, index + 1);
    
    // The target level for fetching data should be the level *stored* in the target crumb
    const targetLevel = targetCrumb.nextLevel; // Use 'nextLevel' from the stored crumb to refetch at that level
    currentLevel = targetLevel;

    // Center map to the lat/lon stored in the target crumb
    map.flyTo([targetCrumb.lat, targetCrumb.lon], map.getZoom(), {
        animate: true,
        duration: 0.5
    });

    fetchMapData(targetLevel);
    updateBreadcrumb();
    
    // Unlock map if returning to continent
    window.mapLocked = (targetLevel !== 'continent');
    // Set drill status banner
    try { window.setDrillStatus(currentLevel, breadcrumbPath.length ? breadcrumbPath[breadcrumbPath.length-1].label : ''); } catch(_){}
}

async function fetchMapData(level = "continent"){
    currentLevel = level;
    const minutes = document.getElementById("timeRangeSelect").value || 15;
    const url = `/data?level=${level}&minutes=${minutes}&top_k=200`;
    try{
        const res = await fetch(url);
        const gj = await res.json();
        // Update drill status banner if available
        const lastCrumb = breadcrumbPath[breadcrumbPath.length-1];
        try { 
            if (typeof setDrillStatus === 'function') {
                // Use the level and label from the *last* breadcrumb if one exists, otherwise use the level itself
                setDrillStatus(level, lastCrumb ? lastCrumb.label : '');
            }
        } catch(_){}
        renderGeo(gj);
        
        // update KPIs and severity chart
        try {
            const metrics = await (await fetch(`/metrics?minutes=${minutes}`)).json();
            document.getElementById('kpi-total').textContent = metrics.total_events || 0;
            document.getElementById('kpi-blocked').textContent = metrics.blocked_events || 0;
            const rate = metrics.total_events ? Math.round((metrics.blocked_events/metrics.total_events)*100) : 0;
            document.getElementById('kpi-block-rate').textContent = rate + '%';
            document.getElementById('kpi-unique-ips').textContent = metrics.unique_source_ips || 0;
            // severity chart
            ensureSeverityChart();
            if (severityChart && metrics.threat_levels) {
                severityChart.data.datasets[0].data = [metrics.threat_levels.High||0, metrics.threat_levels.Medium||0, metrics.threat_levels.Low||0];
                severityChart.update();
            }
            // populate top actors / iocs if available
            const ta = document.getElementById('threatActorsList');
            const ioc = document.getElementById('iocList');
            if(ta) ta.innerHTML = (metrics.top_signatures||[]).slice(0,5).map(s=>`<div class="small">${s.sig} <small class="text-muted">(${s.count})</small></div>`).join('');
            if(ioc) ioc.innerHTML = (metrics.malicious_ips||[]).slice(0,5).map(ip=>`<li>${ip}</li>`).join('');
        } catch(e) {
            console.warn('Failed to update metrics', e);
        }
    }catch(e){ console.error(e); }
}

function clearBubbles(){ bubbleLayer.clearLayers(); }

function radiusForCount(c){
    const base = Math.sqrt(c);
    // Increase minimum radius for visibility on dark map
    return Math.max(10, Math.min(base * 5 + 6, 70));
}

function colorForRatio(r){
    // Red for blocked-heavy, deeper blue for allowed-heavy
    const blockedColor = 'rgba(239, 68, 68, 0.85)';
    const allowedColor = 'rgba(30, 136, 229, 0.85)';
    const mix = r;
    return mix >= 0.5 ? allowedColor : blockedColor;
}

// Shade intensity based on count (log scaled opacity)
function shadeForCount(count){
    const c = Math.max(1, count||1);
    const norm = Math.min(1, Math.log10(c) / Math.log10(20000));
    return 0.35 + norm * (0.95 - 0.35);
}

function renderGeo(gj){
    if(!map) initMap();
    clearBubbles();
    if(!gj || !Array.isArray(gj.features)) return;
    const blockedOnlyEl = document.getElementById('blockedOnly');
    const blockedOnly = blockedOnlyEl ? blockedOnlyEl.checked : false;

    // Helper: generate spiral offsets to visibly separate overlapping points
    function spreadAround(lat, lon, count){
        const pts = [];
        const golden = Math.PI * (3 - Math.sqrt(5)); // golden angle
        // Scale radius based on count so clusters fill area proportionally, capped for performance
        const maxR = Math.min(0.05, 0.005 * Math.sqrt(Math.max(count,1))); // up to ~5km
        for(let i=0;i<count;i++){
            // Offset with 0.5 to avoid empty center; sqrt distribution keeps density even
            const r = maxR * Math.sqrt((i + 0.5) / Math.max(count, 1));
            const theta = i * golden;
            const dLat = r * Math.cos(theta);
            const dLon = r * Math.sin(theta);
            pts.push([lat + dLat, lon + dLon]);
        }
        return pts;
    }
    
    // If at 'point' level, fan out aggregated features with properties.events[] to individual event points
    if(currentLevel === 'point') {
        const points = [];
        gj.features.forEach(f => {
            const props = f.properties || {};
            const evs = Array.isArray(props.events) ? props.events : [];
            if (evs.length > 0) {
                // Group events by identical lat/lon to avoid overlap, then spread
                const groups = new Map();
                evs.forEach(ev => {
                    if (typeof ev.lat === 'number' && typeof ev.lon === 'number') {
                        const key = `${ev.lat.toFixed(6)},${ev.lon.toFixed(6)}`;
                        if (!groups.has(key)) groups.set(key, { lat: ev.lat, lon: ev.lon, list: [] });
                        groups.get(key).list.push(ev);
                    }
                });
                groups.forEach(({lat, lon, list}) => {
                    const offsets = spreadAround(lat, lon, list.length);
                    list.forEach((ev, idx) => {
                        const [sLat, sLon] = offsets[idx];
                        points.push({
                            lat: sLat,
                            lon: sLon,
                            p: { ...ev, lat: sLat, lon: sLon } // Merge jittered coords back
                        });
                    });
                });
            } else if (f.geometry && f.geometry.type === 'Point' && Array.isArray(f.geometry.coordinates)) {
                const [lon, lat] = f.geometry.coordinates;
                // Fallback: if we only have an aggregate with count, generate jittered points
                const cnt = Math.max(1, parseInt(props.count || 1, 10));
                if (cnt > 1) {
                    const n = Math.min(cnt, 200);
                    const offsets = spreadAround(lat, lon, n);
                    offsets.forEach(([sLat, sLon]) => points.push({ lat: sLat, lon: sLon, p: props }));
                } else {
                    points.push({ lat, lon, p: props });
                }
            }
        });

        // Render individual event points
        points.forEach(({lat, lon, p}) => {
            // Fallbacks for missing fields so tooltips don't show N/A
            const ip = p.ip || (Array.isArray(p.top_ips) && p.top_ips[0]) || 'Unknown IP';
            const signature = p.signature || p.top_signature || 'Unspecified';
            let blocked = typeof p.blocked === 'boolean' ? p.blocked : (typeof p.allowed === 'number' && typeof p.blocked === 'number' ? p.blocked > p.allowed : false);
            // Heuristic: treat high severity or known block signatures as blocked if missing
            if (typeof blocked !== 'boolean') {
                const sev = (p.severity||'').toString().toLowerCase();
                const sig = (signature||'').toString().toLowerCase();
                blocked = sev === 'high' || sig.includes('block') || sig.includes('deny');
            }
            // Filter if blocked-only is enabled
            if (blockedOnly && !blocked) return;

            const circle = L.circleMarker([lat, lon], {
                radius: 6,
                color: blocked ? '#ef4444' : '#0ea5a4',
                fillColor: blocked ? '#ef4444' : '#0ea5a4',
                fillOpacity: 0.95,
                weight: 2
            });
            const tooltipHtml = `<div><strong>${ip}</strong></div><div>Status: ${blocked ? 'Blocked' : 'Allowed'}</div><div>Signature: ${signature}</div>`;
            circle.bindTooltip(tooltipHtml, {direction: 'top', offset: [0, -8]});
            circle.on('click', () => { showEventDetailsModal({ ...p, ip, signature, blocked }); });
            circle.addTo(bubbleLayer);
        });
    } else {
        // Aggregate bubbles for other levels
        gj.features.forEach(f => {
            const p = f.properties;
            const [lon, lat] = f.geometry.coordinates;
            const r = radiusForCount(p.count);
            const col = colorForRatio(p.allowed_ratio || 0);
            // If blocked-only is enabled, skip aggregates with zero blocked
            if (blockedOnly && (!p.blocked || p.blocked <= 0)) return;

            const circle = L.circleMarker([lat, lon], {
                radius: r,
                color: '#ffffff',
                fillColor: col,
                fillOpacity: ((p.allowed_ratio||0) >= 0.5) ? shadeForCount(p.count) : 0.95,
                weight: 2
            });
            // Tooltip: show more info at wider zooms, concise at far zooms
            const z = map.getZoom ? map.getZoom() : initialState.zoom;
            const topIp = (p.top_ips||[])[0] || 'N/A';
            
            // Use the standard hierarchical getter for robust label extraction
            const orderedNames = getOrderedLabels(p.label);
            const fullLabel = [orderedNames.continent, orderedNames.country, orderedNames.state, orderedNames.city].filter(Boolean).join(' › ');
            const shortLabel = orderedNames.city || orderedNames.state || orderedNames.country || orderedNames.continent || 'Unknown';
            
            const concise = `<div><strong>${shortLabel}</strong></div><div>Count: ${p.count}</div>`;
            const detailed = `<div><strong>${fullLabel}</strong></div><div>Count: ${p.count} • Blocked: ${p.blocked}</div><div>Top: ${topIp}</div><div>Severity: ${p.severity || 'N/A'}</div>`;
            const tooltipHtml = z >= 6 ? detailed : concise;
            const tooltipOpts = { direction: 'top', offset: [0, -Math.max(r, 12)], permanent: z >= 7, opacity: 0.9, className: 'map-tooltip' };
            circle.bindTooltip(tooltipHtml, tooltipOpts);
            circle.bindPopup(`<b>${fullLabel}</b><br/>Count: ${p.count}<br/>Blocked: ${p.blocked} Allowed: ${p.allowed}<br/>Top IPs: ${(p.top_ips||[]).join(", ")}`);
            
            circle.on('click', () => {
                const next = nextLevel(currentLevel);
                if(next){
                    const names = getOrderedLabels(p.label);
                    let newCrumbLabel = '';
                    let targetNextLevel = next; // The level to fetch AFTER this click

                    // --- Custom Breadcrumb Logic to Enforce Hierarchy and Prevent Bounce ---
                    
                    if (currentLevel === 'continent') {
                        // Current level shows continents, but bubbles often represent countries
                        newCrumbLabel = names.continent;
                        targetNextLevel = 'country'; // Next fetch level is Country
                    } else if (currentLevel === 'country') {
                        // Current level shows countries, but bubbles often represent states/regions
                        newCrumbLabel = names.country;
                        targetNextLevel = 'state'; // Next fetch level is State
                    } else if (currentLevel === 'state') {
                        // Current level shows states, next is city/point
                        newCrumbLabel = names.state;
                        targetNextLevel = 'city'; // Next fetch level is City
                    } else if (currentLevel === 'city') {
                        // At the city level, format the label clearly (City, State/Country)
                        let cityLabel = names.city;
                        if (names.state && names.state !== names.city) {
                            cityLabel += `, ${names.state}`;
                        } else if (names.country && names.country !== names.city && !names.state) {
                            cityLabel += `, ${names.country}`;
                        }
                        newCrumbLabel = cityLabel;
                        targetNextLevel = 'point'; // Next fetch level is Point
                    }

                    // Remove any existing crumbs that are deeper than the one being pushed
                    // e.g., if current is 'country' and we click 'state', but the path already has 'city', trim it.
                    // This is the main fix for the double-click/bounce.
                    let existingPathSegments = breadcrumbPath.map(c => c.label);
                    let existingIndex = existingPathSegments.indexOf(newCrumbLabel);

                    if (existingIndex !== -1) {
                        // If the bubble label already exists in the path, trim the path to that point
                        // and proceed to fetch the next level. This fixes the bounce back.
                        breadcrumbPath = breadcrumbPath.slice(0, existingIndex + 1);
                        
                        // We must also update the level stored in the last crumb to reflect the
                        // level we are about to fetch, to ensure breadcrumb navigation works correctly.
                        breadcrumbPath[breadcrumbPath.length - 1].nextLevel = targetNextLevel;
                        
                    } else if (newCrumbLabel) {
                        // Push new segment if it is unique and valid
                        // Only add it if it's the next logical step from the last crumb OR we are starting fresh.
                        
                        // To achieve the desired sequence (e.g., NA > US > FL > Deland) 
                        // we use the full label extraction and check if the current path needs backfilling.
                        
                        let shouldPush = true;
                        
                        // Special handling for starting from 'continent' view:
                        if (currentLevel === 'continent' && breadcrumbPath.length === 0) {
                            // Start with Continent name
                            breadcrumbPath.push({ label: names.continent, nextLevel: 'country', lat: lat, lon: lon });
                            
                            // If the resulting data (bubble) also had a Country name, push Country immediately after Continent
                            if (names.country && names.country !== names.continent) {
                                breadcrumbPath.push({ label: names.country, nextLevel: 'state', lat: lat, lon: lon });
                            } else if (names.state) {
                                // If no country, push state/region directly
                                breadcrumbPath.push({ label: names.state, nextLevel: 'city', lat: lat, lon: lon });
                            }
                            shouldPush = false; // Already handled the first drill-down steps
                            
                        } else if (currentLevel === 'country' && names.state) {
                            // If drilling from country to state, only push state
                            breadcrumbPath.push({ label: names.state, nextLevel: 'city', lat: lat, lon: lon });
                            shouldPush = false;

                        } else if (currentLevel === 'state' && names.city) {
                            // If drilling from state to city/point, only push city
                            // Recalculate City Label
                            let cityLabel = names.city;
                            if (names.state && names.state !== names.city) {
                                cityLabel += `, ${names.state}`;
                            } else if (names.country && names.country !== names.city && !names.state) {
                                cityLabel += `, ${names.country}`;
                            }
                            breadcrumbPath.push({ label: cityLabel, nextLevel: 'point', lat: lat, lon: lon });
                            shouldPush = false;
                        }
                        
                        // Fallback for non-standard jumps (e.g. continent > city directly) or end of path
                        if (shouldPush && newCrumbLabel) {
                            breadcrumbPath.push({ label: newCrumbLabel, nextLevel: targetNextLevel, lat: lat, lon: lon });
                        }
                    }

                    currentLevel = targetNextLevel;
                    fetchMapData(targetNextLevel);
                    updateBreadcrumb();
                    
                    window.mapLocked = (targetNextLevel !== 'continent'); // Lock map when drilling down
                    // zoom to marker with smooth animation
                    map.flyTo([lat,lon], Math.min(12, map.getZoom()+2), {
                        animate: true,
                        duration: 1
                    });
                }
            });
            circle.addTo(bubbleLayer);
            // Count label: keep visible but reduce overlap at low zoom by shrinking
            const labelSize = z >= 7 ? 1.0 : z >= 5 ? 0.85 : 0.7;
            const label = L.divIcon({ className:'count-label', html:`<div class="bubble-count" style="transform: scale(${labelSize}); background:rgba(255,255,255,0.12); color:#fff; border:1px solid rgba(255,255,255,0.6)">${p.count}</div>`});
            L.marker([lat,lon], {icon: label, interactive:false}).addTo(bubbleLayer);
        });
    }

}

// Show modal with event details
function showEventDetailsModal(event) {
    const modal = document.getElementById('ipDetailsModal');
    const content = document.getElementById('ipDetailsContent');
    if (!modal || !content) return;
    content.innerHTML = `
        <div class="mb-2"><strong>IP:</strong> ${event.ip || 'N/A'}</div>
        <div class="mb-2"><strong>Status:</strong> <span class="${event.blocked ? 'text-danger' : 'text-success'}">${event.blocked ? 'Blocked' : 'Allowed'}</span></div>
        <div class="mb-2"><strong>Signature:</strong> ${event.signature || 'N/A'}</div>
        <div class="mb-2"><strong>Time:</strong> ${event.time || 'N/A'}</div>
        <div class="mb-2"><strong>Location:</strong> ${event.city || event.state || 'N/A'}, ${event.country || ''}</div>
        <div class="mb-2"><strong>Severity:</strong> ${event.severity || 'N/A'}</div>
    `;
    // Show modal (Bootstrap 5)
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
}


function nextLevel(l){
    // Drill-down order: continent > country/region > state > city > point
    const order = ["continent","country","state","city","point"];
    const i = order.indexOf(l);
    if(i<0||i>=order.length-1) return null;
    return order[i+1];
}

// init
document.addEventListener("DOMContentLoaded", () => {
    initMap();
    // Start at continent view centered on North America
    currentLevel = 'continent';
    breadcrumbPath = [];
    window.mapLocked = false; // allow normal drilldown from continent
    const levelSelectEl = document.getElementById('mapLevelSelect');
    if (levelSelectEl) levelSelectEl.value = 'continent';
    try { map.setView(initialState.center, initialState.zoom); } catch(_){}
    fetchMapData("continent");
    // refresh when time range changes
    document.getElementById("timeRangeSelect").addEventListener("change", () => {
        // Respect mapLocked: don't auto-refresh when drilled down
        if (window.mapLocked && currentLevel !== 'continent') return;
        fetchMapData(currentLevel);
    });
    // map level selector
    const levelSelect = document.getElementById('mapLevelSelect');
    if(levelSelect){
        levelSelect.addEventListener('change', (e)=>{
            const lvl = e.target.value || 'continent';
            // Dropdown should always control the current level directly
            currentLevel = lvl;
            breadcrumbPath = [];
            window.mapLocked = (lvl !== 'continent');
            fetchMapData(lvl);
        });
    }
    // Refresh & Show All Points buttons
    const refreshBtn = document.getElementById('refreshMap');
    if(refreshBtn) refreshBtn.addEventListener('click', ()=>{
        // Reset to initial state (as when page loaded)
        currentLevel = initialState.level || 'continent';
        breadcrumbPath = [];
        window.mapLocked = false; // Unlock map on manual refresh
        if(document.getElementById('mapLevelSelect')) document.getElementById('mapLevelSelect').value = currentLevel;
        fetchMapData(currentLevel);
        updateBreadcrumb();
        try{ map.setView(initialState.center, initialState.zoom); map.invalidateSize(); } catch(e){}
    });
    const showAll = document.getElementById('showAllPoints');
    if(showAll) showAll.addEventListener('click', ()=>{
        // Explicit action: allow switching to point view but lock refresh thereafter
        currentLevel='point';
        breadcrumbPath = [];
        const sel = document.getElementById('mapLevelSelect');
        if (sel) sel.value='point';
        window.mapLocked = true;
        fetchMapData('point');
    });
    // refresh on nav 'Map' tab click
    // When the map tab is shown (Bootstrap event), reset view and invalidate size
    const mapTabEl = document.getElementById('map-tab');
    if (mapTabEl) {
        mapTabEl.addEventListener('shown.bs.tab', (e)=>{
            // If map is locked (user selected a specific level or drilled down), don't reset level
            if (!window.mapLocked) {
                currentLevel = "continent";
                breadcrumbPath = [];
                window.mapLocked = false; // normal drilldown
                fetchMapData("continent");
            } else {
                // Just ensure layout/size without changing the current view
                try { map.invalidateSize(); } catch(_){}
            }
            updateBreadcrumb();
            setTimeout(()=>{ try{ map.invalidateSize(); map.setView(initialState.center, initialState.zoom); } catch(_){} }, 200);
        });
    }
    ensureSeverityChart();
    // Hook blocked-only toggle to re-render current view
    const blockedOnlyEl = document.getElementById('blockedOnly');
    if (blockedOnlyEl) blockedOnlyEl.addEventListener('change', ()=>{ fetchMapData(currentLevel); });
});

// capture initial state after first load
document.addEventListener('DOMContentLoaded', ()=>{
    // ensure initialState reflects the map defaults
    try{
        if (map) {
            initialState.center = map.getCenter() ? [map.getCenter().lat, map.getCenter().lng] : initialState.center;
            initialState.zoom = map.getZoom() || initialState.zoom;
            initialState.level = currentLevel || initialState.level;
        }
    }catch(e){}
});