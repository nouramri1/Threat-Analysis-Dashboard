#!/usr/bin/env python3
"""
simulator.py - generate Suricata-like events and POST them to /ingest
"""

import requests, random, time
from datetime import datetime, timezone

SERVER = "http://127.0.0.1:5000"
INGEST = SERVER + "/ingest"

# Stetson University data centers and global locations
STETSON_DATACENTERS = [
    ("129.25.10.254", 2222, "Stetson University Main DC"),  # DeLand, FL
    ("129.25.20.10", 22, "Stetson Business School DC"),
    ("129.25.30.5", 80, "Stetson Library DC"),
    ("129.25.40.77", 443, "Stetson Research DC")
]

GLOBAL_DATACENTERS = [
    ("185.199.108.10", 443, "London, UK"),
    ("13.107.42.14", 80, "Dublin, Ireland"), 
    ("104.16.249.249", 443, "San Francisco, USA"),
    ("172.217.3.142", 443, "Mountain View, USA"),
    ("52.84.230.120", 80, "Virginia, USA"),
    ("13.35.23.75", 443, "Frankfurt, Germany"),
    ("54.230.87.200", 80, "Tokyo, Japan"),
    ("13.225.103.118", 443, "Sydney, Australia"),
    ("157.240.11.35", 443, "Singapore"),
    ("31.13.64.35", 80, "Stockholm, Sweden")
]

# Combine destinations with weighted selection (70% Stetson, 30% Global)
ALL_DESTINATIONS = STETSON_DATACENTERS + GLOBAL_DATACENTERS

# Attack signature categories for different scenarios
SSH_BRUTE_SIGS = [
    (1002001, "SSH brute force attempt", 4),
    (1002002, "SSH login failure", 3),
    (1002003, "SSH multiple login attempts", 4),
    (1002004, "SSH dictionary attack", 5),
    (1002005, "SSH credential stuffing", 4)
]

WEB_EXPLOIT_SIGS = [
    (1003001, "HTTP suspicious URI", 3),
    (1003002, "SQL injection attempt", 5),
    (1003003, "XSS attack detected", 4),
    (1003004, "Directory traversal attempt", 4),
    (1003005, "PHP code injection", 5),
    (1003006, "Apache Struts exploit", 5),
    (1003007, "WordPress vulnerability scan", 3)
]

MALWARE_SIGS = [
    (1007001, "Malware command and control", 5),
    (1007002, "Botnet communication", 5),
    (1007003, "Suspicious DNS query", 3),
    (1007004, "Data exfiltration attempt", 5),
    (1007005, "Cryptominer traffic", 4),
    (1007006, "Ransomware communication", 5)
]

GENERAL_SIGS = [
    (1001002, "Cowrie probe to :2222", 3),
    (1004001, "Potential data exfiltration", 5),
    (1005001, "VPN connection anomaly", 3),
    (1006001, "Database query injection attempt", 4),
    (1008001, "Unusual network traffic pattern", 2)
]

# Current attack scenario
CURRENT_SCENARIO = "normal"  # normal, bruteforce, webexploit, malware

# More diverse source IP pools representing different global regions
SRC_POOLS = {
    'stetson': [f"129.25.{i%10}.{100+i}" for i in range(1,30)],  # Stetson campus IPs (Florida)
    'us_ny': [f"172.16.{i%50}.{10+i}" for i in range(1,15)],  # US New York
    'us_ca': [f"172.17.{i%50}.{10+i}" for i in range(1,15)],  # US California
    'us_tx': [f"172.18.{i%50}.{10+i}" for i in range(1,15)],  # US Texas
    'us_wa': [f"172.19.{i%50}.{10+i}" for i in range(1,12)],  # US Washington
    'us_ill': [f"172.20.{i%50}.{10+i}" for i in range(1,12)],  # US Illinois
    'us_ga': [f"172.21.{i%50}.{10+i}" for i in range(1,12)],  # US Georgia
    'us_other': [f"192.168.{100+i%30}.{1+i}" for i in range(1,20)],  # US Other states
    'canada': [f"203.{i%50}.{100+i%50}.{5+i}" for i in range(1,10)],  # Canada
    'brazil': [f"201.{i%40}.{80+i%50}.{10+i}" for i in range(1,8)],  # Brazil
    'south_america': [f"200.{i%50}.{70+i%50}.{15+i}" for i in range(1,8)],  # South America
    'uk': [f"185.{200+i%30}.{50+i%100}.{5+i}" for i in range(1,8)],  # United Kingdom
    'europe': [f"10.{200+i%10}.{50+i%200}.{5+i}" for i in range(1,20)],  # Europe (DE, NL, FR, etc)
    'asia_india': [f"172.30.{i%50}.{10+i}" for i in range(1,8)],  # Asia - India
    'asia_jp': [f"172.31.{i%50}.{10+i}" for i in range(1,8)],  # Asia - Japan
    'asia_sg': [f"180.{i%30}.{100+i%50}.{5+i}" for i in range(1,8)],  # Asia - Singapore
}

# Weighted pool selection to favor US
POOL_WEIGHTS = {
    'stetson': 20,
    'us_ny': 12,
    'us_ca': 12,
    'us_tx': 10,
    'us_wa': 8,
    'us_ill': 8,
    'us_ga': 8,
    'us_other': 10,
    'canada': 3,
    'brazil': 2,
    'south_america': 2,
    'uk': 2,
    'europe': 3,
    'asia_india': 2,
    'asia_jp': 2,
    'asia_sg': 2
}

RATE_PER_SECOND = 3   # events per second
BATCH_SIZE = 1

def get_destination():
    """Select destination with 70% probability for Stetson, 30% for global"""
    if random.random() < 0.7:  # 70% chance for Stetson
        return random.choice(STETSON_DATACENTERS)
    else:  # 30% chance for global
        return random.choice(GLOBAL_DATACENTERS)

def get_source_ip(dest_info):
    """Select source IP based on destination context, globally diverse with US bias"""
    dest_ip, _, location = dest_info
    
    # Use weighted random selection to bias towards US
    pools = list(POOL_WEIGHTS.keys())
    weights = list(POOL_WEIGHTS.values())
    chosen_pool = random.choices(pools, weights=weights)[0]
    return random.choice(SRC_POOLS[chosen_pool])

def now():
    return datetime.now(timezone.utc).isoformat()

def get_signatures_for_scenario():
    """Get appropriate signatures based on current attack scenario"""
    global CURRENT_SCENARIO
    
    if CURRENT_SCENARIO == "bruteforce":
        return SSH_BRUTE_SIGS
    elif CURRENT_SCENARIO == "webexploit":
        return WEB_EXPLOIT_SIGS
    elif CURRENT_SCENARIO == "malware":
        return MALWARE_SIGS
    else:
        # Normal scenario - mix of all signatures
        return SSH_BRUTE_SIGS + WEB_EXPLOIT_SIGS + MALWARE_SIGS + GENERAL_SIGS

def make_event():
    dest_info = get_destination()
    dest, dport, location = dest_info
    src = get_source_ip(dest_info)
    
    # Select signature based on current scenario
    available_sigs = get_signatures_for_scenario()
    sig = random.choice(available_sigs)
    
    # Adjust action probability based on scenario
    if CURRENT_SCENARIO == "bruteforce":
        action = random.choices(["allowed","blocked"], weights=[0.1,0.9])[0]  # More blocks for brute force
    elif CURRENT_SCENARIO == "malware":
        action = random.choices(["allowed","blocked"], weights=[0.3,0.7])[0]  # More blocks for malware
    else:
        action = random.choices(["allowed","blocked"], weights=[0.6,0.4])[0]  # Normal distribution
    
    ev = {
        "timestamp": now(),
        "flow_id": random.randint(1, 2**48),
        "in_iface": "br-demo",
        "event_type": "alert",
        "src_ip": src,
        "src_port": random.randint(1024, 60000),
        "dest_ip": dest,
        "dest_port": dport,
        "proto": random.choice(["TCP","UDP"]),
        "pkt_src": "wire/pcap",
        "alert": {
            "action": action,
            "gid": 1,
            "signature_id": sig[0],
            "rev": 1,
            "signature": sig[1],
            "category": "",
            "severity": sig[2]
        },
        "direction": "to_server",
        "flow": {
            "pkts_toserver": 1, "pkts_toclient": 0,
            "bytes_toserver": random.randint(40,1500), "bytes_toclient":0,
            "start": now(), "src_ip": src, "dest_ip": dest, "src_port": random.randint(1024,60000), "dest_port": dport
        }
    }
    return ev

def set_attack_scenario(scenario):
    """Set the current attack scenario"""
    global CURRENT_SCENARIO
    valid_scenarios = ["normal", "bruteforce", "webexploit", "malware"]
    if scenario in valid_scenarios:
        CURRENT_SCENARIO = scenario
        print(f"Attack scenario changed to: {scenario}")
    else:
        print(f"Invalid scenario. Valid options: {valid_scenarios}")

def simulate_coordinated_attack(scenario, duration=60):
    """Simulate a coordinated attack for a specific duration"""
    global RATE_PER_SECOND
    print(f"Starting {scenario} attack simulation for {duration} seconds...")
    
    original_scenario = CURRENT_SCENARIO
    original_rate = RATE_PER_SECOND
    
    set_attack_scenario(scenario)
    
    if scenario == "bruteforce":
        RATE_PER_SECOND = 5  # Increase rate for brute force
    elif scenario == "malware":
        RATE_PER_SECOND = 2  # Lower rate for malware beaconing
    elif scenario == "webexploit":
        RATE_PER_SECOND = 4  # Medium rate for web exploits
    
    start_time = time.time()
    while time.time() - start_time < duration:
        batch = [make_event() for _ in range(BATCH_SIZE)]
        try:
            r = requests.post(INGEST, json=batch, timeout=3)
            if r.status_code != 200:
                print("POST failed:", r.status_code, r.text)
        except Exception as e:
            print("post err", e)
        time.sleep(1.0 / RATE_PER_SECOND)
    
    # Restore original settings
    set_attack_scenario(original_scenario)
    RATE_PER_SECOND = original_rate
    print(f"Completed {scenario} attack simulation")

def run():
    sent = 0
    print("Commands available:")
    print("  normal - Normal traffic simulation")
    print("  bruteforce - SSH brute force attack")
    print("  webexploit - Web exploitation attempts")  
    print("  malware - Malware beaconing simulation")
    print("  Ctrl+C to stop")
    print()
    
    try:
        while True:
            batch = [make_event() for _ in range(BATCH_SIZE)]
            try:
                r = requests.post(INGEST, json=batch, timeout=3)
                if r.status_code!=200:
                    print("POST failed:", r.status_code, r.text)
            except Exception as e:
                print("post err", e)
            sent += len(batch)
            
            # Show current scenario status occasionally
            if sent % 50 == 0:
                print(f"Scenario: {CURRENT_SCENARIO} | Events sent: {sent} | Rate: {RATE_PER_SECOND}/sec")
            
            time.sleep(1.0 / RATE_PER_SECOND)
    except KeyboardInterrupt:
        print("stopped. total:", sent)

if __name__ == "__main__":
    import sys
    
    print("simulator ->", INGEST)
    
    # Check for command line arguments to set initial scenario
    if len(sys.argv) > 1:
        scenario = sys.argv[1].lower()
        if scenario in ["bruteforce", "webexploit", "malware", "normal"]:
            set_attack_scenario(scenario)
            print(f"Starting with {scenario} scenario")
        elif scenario == "demo":
            # Run a demo of all attack types
            print("Running attack scenario demonstration:")
            simulate_coordinated_attack("bruteforce", 30)
            time.sleep(5)
            simulate_coordinated_attack("webexploit", 30)
            time.sleep(5)
            simulate_coordinated_attack("malware", 30)
            set_attack_scenario("normal")
            print("Demo complete, returning to normal operations")
    
    run()
