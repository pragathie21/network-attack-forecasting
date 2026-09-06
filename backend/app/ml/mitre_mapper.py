"""
MITRE ATT&CK Framework Mapping and SOC Defensive Playbooks
"""

MITRE_ATTACK_MAPPING = {
    "Benign": {
        "technique_id": "N/A",
        "technique_name": "Standard Operational Traffic",
        "tactic": "Normal Operations",
        "description": "Baseline network communications conforming to expected enterprise profile.",
        "recommended_action": "Routine passive monitoring; maintain standard telemetry retention."
    },
    "DDoS": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversary floods target services with excessive packet volume or connection requests to degrade or deny availability.",
        "recommended_action": "Engage upstream scrubbing provider / CDN DDoS mitigation, activate SYN flood protection on border edge, rate-limit ingress UDP/ICMP traffic, and deploy dynamic BGP blackholing."
    },
    "DoS": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversary targets server application resources (e.g. Slowloris, Apache Killer) via prolonged connection exhaustion.",
        "recommended_action": "Tune web server request timeout thresholds, restrict maximum concurrent connections per IP, deploy reverse proxy connection buffering, and recycle hanging worker threads."
    },
    "Brute Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force Authentication",
        "tactic": "Credential Access",
        "description": "Automated attempts to guess credentials across exposed management interfaces (SSH, RDP, FTP, Telnet).",
        "recommended_action": "Enable automatic IP lockout policies (e.g. Fail2Ban), enforce mandatory Multi-Factor Authentication (MFA), restrict SSH/RDP to internal bastion hosts or VPN, and rotate potentially exposed credentials."
    },
    "Botnet": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (Command and Control)",
        "tactic": "Command and Control",
        "description": "Compromised internal host communicating periodically with external Command & Control (C2) servers via standard protocols.",
        "recommended_action": "Isolate the infected endpoint immediately from the local subnet, sinkhole destination C2 domains via DNS firewall, inspect host processes for persistence mechanisms, and initiate forensic disk imaging."
    },
    "Infiltration": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversary actively scanning internal subnets, exploiting vulnerable SMB/RPC services to propagate across network boundaries.",
        "recommended_action": "Block lateral SMB/RPC ports (445, 139, 135) between internal user VLANs, audit network segment access control lists, update vulnerable operating systems, and monitor LSASS process memory."
    },
    "Web Attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Attacks targeting web applications (SQL Injection, Cross-Site Scripting, Command Injection) via HTTP request parameters.",
        "recommended_action": "Enable Web Application Firewall (WAF) virtual patching rules for SQLi/XSS patterns, sanitize and parameterize backend database queries, and inspect application server request logs."
    }
}

def get_mitre_mapping(attack_type: str) -> dict:
    """Retrieve MITRE ATT&CK details for a classified attack type."""
    normalized = attack_type.strip()
    return MITRE_ATTACK_MAPPING.get(normalized, {
        "technique_id": "T1000",
        "technique_name": "Uncategorized Anomaly",
        "tactic": "Suspicious Activity",
        "description": "Unclassified abnormal traffic signature deviating from baseline metrics.",
        "recommended_action": "Inspect packet headers and quarantine originating IP address."
    })
