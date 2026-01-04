#!/usr/bin/env python3
"""
server.py - lightweight Flask backend for the Splunk-like demo dashboard.

Endpoints:
  GET  /            -> dashboard HTML
  POST /ingest      -> ingest event or list of events (Suricata-style)
  GET  /data        -> GeoJSON-style aggregates used by map
  GET  /alerts      -> raw alerts or aggregated by IP
  GET  /metrics     -> simple KPIs for dashboard
"""

try:
    from flask import Flask, request, jsonify, render_template, send_from_directory
except ModuleNotFoundError:
    import sys
    print("Missing dependency: Flask is not installed. Install it with: pip install flask", file=sys.stderr)
    sys.exit(1)

from collections import deque, defaultdict
from datetime import datetime, timedelta
import threading, time, random, os, json
import logging


# Configure logging early
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    force=True
)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.logger.setLevel(logging.INFO)

# Add request logging
@app.before_request
def log_request_info():
    app.logger.info(f"Request: {request.method} {request.url} from {request.remote_addr}")

# Attempt to load geoip2 dynamically to avoid import-time errors when the package
# is not installed; only initialize GEOIP if both the package and DB file exist.
import importlib

try:
    geoip_pkg = importlib.import_module("geoip2.database")
    Reader = getattr(geoip_pkg, "Reader", None)
    if Reader and os.path.exists("GeoLite2-City.mmdb"):
        try:
            GEOIP = Reader("GeoLite2-City.mmdb")
            app.logger.info("GeoLite2 database loaded successfully.")
        except Exception as e:
            GEOIP = None
            app.logger.warning(f"⚠️ GeoIP database could not be opened: {e}")
    else:
        GEOIP = None
        if Reader is None:
            app.logger.info("geoip2 package found but Reader not available; GeoIP disabled.")
        else:
            app.logger.info("GeoLite2-City.mmdb not found; GeoIP disabled.")
except ModuleNotFoundError:
    GEOIP = None
    app.logger.info("geoip2 package not installed; GeoIP disabled.")
except Exception as e:
    GEOIP = None
    app.logger.warning(f"⚠️ GeoIP initialization failed: {e}")

# ---- Config ----
MAX_EVENTS = 20000
EVENT_RETENTION_MINUTES = 60

# In-memory event store (normalized dicts)
_events = deque(maxlen=MAX_EVENTS)
_lock = threading.Lock()

# Known malicious IP list (for demonstration)
MALICIOUS_IPS = {
    "185.220.101.182", "93.95.230.253", "104.244.72.115", "192.42.116.16",
    "198.98.51.189", "185.220.101.195", "109.70.100.24", "198.96.155.3",
    "185.220.102.8", "185.220.101.40", "185.220.101.186", "109.70.100.23"
}

# US-based IP ranges (for international detection)
US_IP_RANGES = ["129.25.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "192.168.", "10."]  # Including Stetson + US states

# Comprehensive fallback geo mapping for all regions
FALLBACK = [
    # USA - Florida (Stetson)
    ("129.25.", 29.0283, -81.3031, "DeLand, FL", "United States", "Florida", "North America"),
    ("10.77.", 29.0283, -81.3031, "DeLand, FL", "United States", "Florida", "North America"),
    ("10.0.", 28.5383, -81.3792, "Orlando, FL", "United States", "Florida", "North America"),
    ("192.168.", 27.9506, -82.4572, "Tampa, FL", "United States", "Florida", "North America"),
    # USA - New York
    ("172.16.", 40.7128, -74.0060, "New York, NY", "United States", "New York", "North America"),
    # USA - California
    ("172.17.", 37.7749, -122.4194, "San Francisco, CA", "United States", "California", "North America"),
    # USA - Texas
    ("172.18.", 29.7604, -95.3698, "Houston, TX", "United States", "Texas", "North America"),
    # USA - Washington
    ("172.19.", 47.6062, -122.3321, "Seattle, WA", "United States", "Washington", "North America"),
    # USA - Illinois
    ("172.20.", 41.8781, -87.6298, "Chicago, IL", "United States", "Illinois", "North America"),
    # USA - Georgia
    ("172.21.", 33.7490, -84.3880, "Atlanta, GA", "United States", "Georgia", "North America"),
    # Canada
    ("203.", 43.6532, -79.3832, "Toronto, ON", "Canada", "Ontario", "North America"),
    # Brazil
    ("201.", -23.5505, -46.6333, "São Paulo, BR", "Brazil", "São Paulo", "South America"),
    # South America
    ("200.", -12.0464, -77.0428, "Lima, PE", "Peru", "Lima", "South America"),
    # United Kingdom
    ("185.200.", 51.5074, -0.1278, "London, UK", "United Kingdom", "England", "Europe"),
    # Europe (broader)
    ("10.20", 52.5200, 13.4050, "Berlin, DE", "Germany", "Berlin", "Europe"),
    # Asia - India
    ("172.30.", 19.0760, 72.8777, "Mumbai, IN", "India", "Maharashtra", "Asia"),
    # Asia - Japan
    ("172.31.", 35.6762, 139.6503, "Tokyo, JP", "Japan", "Tokyo", "Asia"),
    # Asia - Singapore
    ("180.", 1.3521, 103.8198, "Singapore, SG", "Singapore", "Singapore", "Asia"),
]

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def fallback_geo(ip):
    # Try to match IP prefix with fallback geo mappings
    for prefix, lat, lon, city, country, region, continent in FALLBACK:
        if ip.startswith(prefix):
            return (lat, lon, city, country, region, continent)
    
    # If GeoIP also failed AND not internal → unknown external
    return (0.0, 0.0, "Unknown", "Unknown", "Unknown", "Unknown")

def calculate_risk_score(events, src_ip):
    """Calculate risk score for an IP based on its activities."""
    risk_score = 0
    ip_events = [e for e in events if e.get("src_ip") == src_ip]
    
    if not ip_events:
        return 0, "Low"
    
    # +30 if multiple failed logins (blocked SSH/login attempts)
    failed_logins = len([e for e in ip_events if e.get("action") == "blocked" and 
                        ("ssh" in e.get("signature", "").lower() or 
                         "login" in e.get("signature", "").lower() or
                         "brute" in e.get("signature", "").lower())])
    if failed_logins >= 3:
        risk_score += 30
    
    # +20 if IP is international (not in US ranges)
    is_international = not any(src_ip.startswith(prefix) for prefix in US_IP_RANGES)
    if is_international:
        risk_score += 20
    
    # +25 if multiple unique signatures from same IP
    unique_signatures = len(set(e.get("signature_id") for e in ip_events if e.get("signature_id")))
    if unique_signatures >= 3:
        risk_score += 25
    
    # +40 if on known malicious IP list  
    if src_ip in MALICIOUS_IPS:
        risk_score += 40
    
    # Determine threat level
    if risk_score >= 70:
        threat_level = "High"
    elif risk_score >= 35:
        threat_level = "Medium"
    else:
        threat_level = "Low"
    
    return risk_score, threat_level

def normalize(ev: dict):
    """Normalize incoming Suricata-like event into a stable shape."""
    ts = ev.get("timestamp") or now_iso()
    src_ip = ev.get("src_ip") or ev.get("flow", {}).get("src_ip", "0.0.0.0")
    src_port = int(ev.get("src_port") or ev.get("flow", {}).get("src_port", 0) or 0)
    dest_ip = ev.get("dest_ip") or ev.get("flow", {}).get("dest_ip", "0.0.0.0")
    dest_port = int(ev.get("dest_port") or ev.get("flow", {}).get("dest_port", 0) or 0)
    proto = ev.get("proto", "N/A")
    alert = ev.get("alert") or {}
    action = (alert.get("action") or "blocked").lower()
    signature = alert.get("signature") or ""
    signature_id = alert.get("signature_id")
    severity = int(alert.get("severity") or 0)

    # Try GeoIP lookup first — if available and valid
    if GEOIP:
        try:
            response = GEOIP.city(src_ip)
            lat = response.location.latitude or 0.0
            lon = response.location.longitude or 0.0
            city = response.city.name or "Unknown"
            country = response.country.name or "Unknown"
            region = response.subdivisions.most_specific.name or "Unknown"
            continent = response.continent.name or "Unknown"
        except:
            # GeoIP exists but lookup failed → fallback
            lat, lon, city, country, region, continent = fallback_geo(src_ip)
    else:
        # GeoIP not available at all → fallback
        lat, lon, city, country, region, continent = fallback_geo(src_ip)

    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "action": action,
        "signature": signature,
        "signature_id": signature_id,
        "severity": severity,
        "lat": lat,
        "lon": lon,
        "city": city,
        "country": country,
        "region": region,
        "continent": continent,
        "risk_score": 0,
        "threat_level": "Low"
    }


# Background cleanup thread to expire old events
def cleanup_loop():
    while True:
        time.sleep(15)
        cutoff = datetime.utcnow() - timedelta(minutes=EVENT_RETENTION_MINUTES)
        cutoff_s = cutoff.isoformat() + "Z"
        removed = 0
        with _lock:
            while _events and _events[0]["timestamp"] < cutoff_s:
                _events.popleft(); removed += 1
        if removed:
            app.logger.info(f"Cleaned {removed} old events")

threading.Thread(target=cleanup_loop, daemon=True).start()

# ---- Routes ----

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/ingest", methods=["POST"])
def ingest():
    print(f">>> INGEST REQUEST RECEIVED FROM {request.remote_addr}")  # Simple print for debugging
    payload = request.get_json(silent=True)
    if not payload:
        app.logger.warning("Received invalid or empty JSON")
        print(">>> ERROR: Invalid or empty JSON")
        return jsonify({"error": "invalid or empty JSON"}), 400

    batch = payload if isinstance(payload, list) else [payload]
    added = 0
    app.logger.info(f"Processing batch of {len(batch)} events")
    print(f">>> Processing batch of {len(batch)} events")
    
    with _lock:
        for ev in batch:
            try:
                n = normalize(ev)
                # normalize timestamp format (best-effort)
                try:
                    # ensure Z-terminated ISO
                    if n["timestamp"].endswith("Z") is False:
                        # attempt parse / convert
                        n["timestamp"] = datetime.fromisoformat(n["timestamp"].replace("Z", "+00:00")).isoformat().replace("+00:00","Z")
                except Exception:
                    n["timestamp"] = now_iso()
                _events.append(n); added += 1
            except Exception as e:
                app.logger.warning(f"Skip event: {e}")
                print(f">>> WARNING: Skip event: {e}")
    
    app.logger.info(f"Successfully ingested {added} events. Total events in memory: {len(_events)}")
    print(f">>> Successfully ingested {added} events. Total events in memory: {len(_events)}")
    return jsonify({"ingested": added}), 200

@app.route("/data")
def data():
    """
    Return aggregates as FeatureCollection (simple aggregation by requested level).
    Params:
      level: continent|region|country|city|point  (default continent)
      minutes: window (default 15)
      top_k: limit of returned features (default 200)
      status: allowed|blocked|all
    """
    level = request.args.get("level", "continent")
    minutes = int(request.args.get("minutes", "15"))
    top_k = int(request.args.get("top_k", "200"))
    status = request.args.get("status", "all")

    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_s = cutoff.isoformat() + "Z"

    agg = {}
    with _lock:
        for ev in list(_events):
            if ev["timestamp"] < cutoff_s: continue
            if status != "all" and ev["action"] != status: continue

            if level == "continent":
                key = ev["continent"]
                rep = (ev["lat"], ev["lon"])
            elif level == "region":
                key = f"{ev['continent']}||{ev['region']}"
                rep = (ev["lat"], ev["lon"])
            elif level == "country":
                key = f"{ev['continent']}||{ev['region']}||{ev['country']}"
                rep = (ev["lat"], ev["lon"])
            elif level == "city":
                key = f"{ev['continent']}||{ev['region']}||{ev['country']}||{ev['city']}"
                rep = (ev["lat"], ev["lon"])
            elif level == "point":
                key = f"{round(ev['lat'],4)}||{round(ev['lon'],4)}"
                rep = (ev["lat"], ev["lon"])
            else:
                key = ev["continent"]; rep = (ev["lat"], ev["lon"])

            s = agg.get(key)
            if s is None:
                s = {"count":0,"allowed":0,"blocked":0,"ips":defaultdict(int),"lat":rep[0],"lon":rep[1],"label":key}
                agg[key]=s
            s["count"] += 1
            s["ips"][ev["src_ip"]] += 1
            if ev["action"]=="allowed":
                s["allowed"] += 1
            else:
                s["blocked"] += 1

    items = sorted(agg.items(), key=lambda kv: kv[1]["count"], reverse=True)[:top_k]
    features = []
    rank = 0
    for key, s in items:
        rank += 1
        total = s["count"]
        allowed_ratio = s["allowed"]/ (total or 1)
        suspicious_score = s["blocked"]/ (total or 1)
        top_ips = sorted(s["ips"].items(), key=lambda x: x[1], reverse=True)[:3]
        features.append({
            "type":"Feature",
            "properties":{
                "label": s["label"],
                "count": s["count"],
                "allowed": s["allowed"],
                "blocked": s["blocked"],
                "allowed_ratio": round(allowed_ratio,3),
                "suspicious_score": round(suspicious_score,3),
                "rank": rank,
                "top_ips": [ip for ip,_ in top_ips],
                "suspicious": suspicious_score >= 0.7 or s["blocked"] >= 20,
                "campus": s.get("campus","Unknown"),
                "color": "#377eb8"
            },
            "geometry":{"type":"Point","coordinates":[s["lon"], s["lat"]]}
        })
    # Return the FeatureCollection response
    return jsonify({
        "type":"FeatureCollection",
        "features":features,
        "meta":{
            "level":level,
            "minutes":minutes
        }
    })
    

@app.route("/alerts")
def alerts():
    """
    Returns recent raw alerts or aggregated by IP.
    params: minutes (default 15), limit (default 200), aggregate=ip
    """
    minutes = int(request.args.get("minutes","15"))
    limit = int(request.args.get("limit","200"))
    aggregate = request.args.get("aggregate")
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_s = cutoff.isoformat() + "Z"

    rows = []
    with _lock:
        for ev in list(_events):
            if ev["timestamp"] < cutoff_s: continue
            rows.append(ev)
    rows = rows[-limit:]

    if aggregate == "ip":
        grouped = {}
        for r in rows:
            ip=r["src_ip"]
            g=grouped.setdefault(ip, {"ip":ip,"count":0,"blocked":0,"allowed":0,"last_seen":r["timestamp"],"lat":r["lat"],"lon":r["lon"],"city":r["city"]})
            g["count"]+=1
            if r["action"]=="allowed": g["allowed"]+=1
            else: g["blocked"]+=1
            if r["timestamp"]>g["last_seen"]: g["last_seen"]=r["timestamp"]
        out=[]
        # Calculate threat levels for aggregated IPs
        all_events = list(_events)  # Get all events once for risk calculation
        for ip,g in grouped.items():
            g["suspicious"] = (g["blocked"] / (g["count"] or 1) >= 0.7) or g["blocked"] >= 10
            # Calculate risk score for this IP
            risk_score, threat_level = calculate_risk_score(all_events, ip)
            g["risk_score"] = risk_score
            g["threat_level"] = threat_level
            out.append(g)
        out.sort(key=lambda x: x["count"], reverse=True)
        return jsonify({"alerts": out[:limit]})
    else:
        # For raw alerts, calculate threat levels on the fly for recent events
        all_events = list(_events)
        for r in rows:
            if "threat_level" not in r or not r["threat_level"] or r["threat_level"] == "Low":
                risk_score, threat_level = calculate_risk_score(all_events, r["src_ip"])
                r["risk_score"] = risk_score
                r["threat_level"] = threat_level
    
    return jsonify({"alerts": rows})

@app.route("/metrics")
def metrics():
    # Enhanced KPIs with threat levels
    minutes = int(request.args.get("minutes","60"))
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_s = cutoff.isoformat() + "Z"
    total=0; blocked=0; ips=set(); by_sig=defaultdict(int)
    threat_counts = {"Low": 0, "Medium": 0, "High": 0}
    
    with _lock:
        recent_events = [ev for ev in list(_events) if ev["timestamp"] >= cutoff_s]
        all_events = list(_events)  # For threat calculation
        
        # Calculate threat levels for unique IPs
        ip_threat_levels = {}
        for ev in recent_events:
            total += 1
            if ev["action"] != "allowed": 
                blocked += 1
            ips.add(ev["src_ip"])
            if ev.get("signature"):
                by_sig[ev["signature"]] += 1
            
            # Calculate threat level for this IP if not already done
            if ev["src_ip"] not in ip_threat_levels:
                _, threat_level = calculate_risk_score(all_events, ev["src_ip"])
                ip_threat_levels[ev["src_ip"]] = threat_level
        
        # Count threat levels by unique IPs (not events)
        for threat_level in ip_threat_levels.values():
            if threat_level in threat_counts:
                threat_counts[threat_level] += 1
    
    top_sigs = sorted(by_sig.items(), key=lambda x: x[1], reverse=True)[:5]
    return jsonify({
        "total_events": total,
        "blocked_events": blocked,
        "unique_source_ips": len(ips),
        "threat_levels": threat_counts,
        "top_signatures": [{"sig":s,"count":c} for s,c in top_sigs]
    })

@app.route("/ipinfo")
def ipinfo():
    """Get detailed information about an IP address"""
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "IP parameter required"}), 400
    
    # Get events for this IP
    with _lock:
        ip_events = [e for e in _events if e.get("src_ip") == ip]
    
    if not ip_events:
        return jsonify({"error": "No data found for this IP"}), 404
    
    latest_event = ip_events[-1]
    risk_score, threat_level = calculate_risk_score(ip_events, ip)
    
    # Basic IP info (in production, you'd use a real IP API like ipapi.co)
    try:
        # Try reverse DNS lookup
        import socket
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"
        
        # Mock ISP/ASN data (in production, use ipwhois or similar)
        isp_info = "Unknown ISP"
        asn_info = "Unknown ASN"
        
        if ip.startswith("129.25."):
            isp_info = "Stetson University"
            asn_info = "AS7018 (STETSON-AS)"
        elif ip.startswith(("185.", "93.", "109.")):
            isp_info = "European ISP"
            asn_info = "AS12345 (EU-PROVIDER)"
        elif ip.startswith(("13.", "52.", "54.")):
            isp_info = "Amazon Web Services"
            asn_info = "AS16509 (AMAZON-02)"
        
    except Exception as e:
        hostname = "Lookup failed"
        isp_info = "Unknown"
        asn_info = "Unknown"
    
    return jsonify({
        "ip": ip,
        "hostname": hostname,
        "isp": isp_info,
        "asn": asn_info,
        "city": latest_event.get("city", "Unknown"),
        "region": latest_event.get("region", "Unknown"), 
        "country": latest_event.get("country", "Unknown"),
        "latitude": latest_event.get("lat", 0),
        "longitude": latest_event.get("lon", 0),
        "risk_score": risk_score,
        "threat_level": threat_level,
        "total_events": len(ip_events),
        "is_malicious": ip in MALICIOUS_IPS,
        "event_summary": {
            "blocked": len([e for e in ip_events if e.get("action") == "blocked"]),
            "allowed": len([e for e in ip_events if e.get("action") == "allowed"]),
            "unique_signatures": len(set(e.get("signature_id") for e in ip_events if e.get("signature_id")))
        }
    })

@app.route("/vulnerabilities")
def top_vulnerabilities():
    """Get top vulnerabilities from past timeframe"""
    minutes = int(request.args.get("minutes", "15"))
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_s = cutoff.isoformat() + "Z"
    
    by_sig = defaultdict(int)
    total_attacks = 0
    
    with _lock:
        for ev in list(_events):
            if ev["timestamp"] < cutoff_s: continue
            if ev.get("signature") and ev.get("action") == "blocked":
                by_sig[ev["signature"]] += 1
                total_attacks += 1
    
    top_vulns = []
    for sig, count in sorted(by_sig.items(), key=lambda x: x[1], reverse=True)[:10]:
        percentage = (count / total_attacks * 100) if total_attacks > 0 else 0
        top_vulns.append({
            "signature": sig,
            "count": count,
            "percentage": round(percentage, 1)
        })
    
    return jsonify({
        "vulnerabilities": top_vulns,
        "total_attacks": total_attacks,
        "timeframe_minutes": minutes
    })

@app.route("/simulate")
def simulate_attack():
    """Trigger specific attack simulation scenarios"""
    attack_type = request.args.get("type", "bruteforce")
    
    # This endpoint would trigger the simulator to generate specific attack patterns
    # For now, just return success - the actual implementation would coordinate with simulator.py
    return jsonify({
        "status": "success", 
        "message": f"Simulating {attack_type} attack scenario",
        "type": attack_type
    })

@app.route("/export")
def export_data():
    """Export alerts data in CSV or JSON format"""
    format_type = request.args.get("format", "json").lower()
    minutes = int(request.args.get("minutes", "60"))
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    cutoff_s = cutoff.isoformat() + "Z"
    
    # Get filtered events
    with _lock:
        filtered_events = [e for e in _events if e["timestamp"] >= cutoff_s]
    
    if format_type == "csv":
        import csv
        from io import StringIO
        
        output = StringIO()
        if filtered_events:
            fieldnames = filtered_events[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(filtered_events)
        
        response = app.response_class(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=security_alerts_{minutes}min.csv'}
        )
        return response
    
    else:  # JSON format
        response = app.response_class(
            json.dumps({
                "export_timestamp": datetime.utcnow().isoformat() + "Z",
                "timeframe_minutes": minutes,
                "total_events": len(filtered_events),
                "events": filtered_events
            }, indent=2),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=security_alerts_{minutes}min.json'}
        )
        return response

if __name__ == "__main__":
    # Ensure logging is configured for the main process too
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        force=True
    )
    app.logger.setLevel(logging.INFO)
    
    # optionally restore persisted events (if present)
    if os.path.exists("events_restore.json"):
        try:
            with open("events_restore.json","r") as f:
                dump=json.load(f)
            with _lock:
                for ev in dump[-MAX_EVENTS:]:
                    _events.append(ev)
            app.logger.info("restored events")
        except Exception:
            app.logger.exception("restore failed")

    app.logger.info("Starting Flask server on 0.0.0.0:5000 with debug=True")
    print("=== LOGS SHOULD APPEAR BELOW ===")  # Add a clear marker
    app.run(host="0.0.0.0", port=5000, debug=True)
