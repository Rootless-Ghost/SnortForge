"""
SnortForge - Detection Rule Templates
"""

from .rule import SnortRule

TEMPLATES = {
    "SQL Injection - Basic": {
        "description": "Detects common SQL injection patterns in HTTP traffic.",
        "category": "Web Application",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "$HTTP_PORTS",
            "msg": "SNORTFORGE SQL Injection Attempt Detected",
            "content": "' OR '1'='1", "content_nocase": True,
            "flow": "to_server,established",
            "classtype": "web-application-attack", "sid": 1000001, "rev": 1, "priority": 1,
        },
    },
    "SQL Injection - UNION SELECT": {
        "description": "Detects UNION-based SQL injection attempts.",
        "category": "Web Application",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "$HTTP_PORTS",
            "msg": "SNORTFORGE UNION SELECT SQL Injection Attempt",
            "content": "UNION SELECT", "content_nocase": True,
            "flow": "to_server,established",
            "classtype": "web-application-attack", "sid": 1000002, "rev": 1, "priority": 1,
        },
    },
    "XSS - Script Tag": {
        "description": "Detects Cross-Site Scripting via script tags.",
        "category": "Web Application",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "$HTTP_PORTS",
            "msg": "SNORTFORGE XSS Script Tag Detected",
            "content": "<script>", "content_nocase": True,
            "flow": "to_server,established",
            "classtype": "web-application-attack", "sid": 1000003, "rev": 1, "priority": 2,
        },
    },
    "Port Scan - SYN Scan": {
        "description": "Detects potential SYN-based port scanning activity.",
        "category": "Reconnaissance",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "any",
            "msg": "SNORTFORGE Possible SYN Port Scan Detected",
            "flow": "stateless", "classtype": "attempted-recon",
            "sid": 1000004, "rev": 1, "priority": 2,
            "threshold_type": "threshold", "threshold_track": "by_src",
            "threshold_count": 5, "threshold_seconds": 60,
        },
    },
    "SSH Brute Force": {
        "description": "Detects multiple SSH connection attempts (brute force).",
        "category": "Brute Force",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "22",
            "msg": "SNORTFORGE SSH Brute Force Attempt Detected",
            "flow": "to_server,established", "classtype": "attempted-admin",
            "sid": 1000005, "rev": 1, "priority": 1,
            "threshold_type": "threshold", "threshold_track": "by_src",
            "threshold_count": 5, "threshold_seconds": 120,
        },
    },
    "FTP Brute Force": {
        "description": "Detects multiple failed FTP login attempts.",
        "category": "Brute Force",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "21",
            "msg": "SNORTFORGE FTP Brute Force Attempt Detected",
            "content": "USER", "flow": "to_server,established",
            "classtype": "attempted-admin", "sid": 1000006, "rev": 1, "priority": 1,
            "threshold_type": "threshold", "threshold_track": "by_src",
            "threshold_count": 5, "threshold_seconds": 60,
        },
    },
    "ICMP Ping Sweep": {
        "description": "Detects ICMP-based network reconnaissance.",
        "category": "Reconnaissance",
        "rule": {
            "action": "alert", "protocol": "icmp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "any",
            "msg": "SNORTFORGE ICMP Ping Sweep Detected",
            "classtype": "attempted-recon", "sid": 1000007, "rev": 1, "priority": 3,
            "threshold_type": "threshold", "threshold_track": "by_src",
            "threshold_count": 10, "threshold_seconds": 30,
        },
    },
    "DNS Zone Transfer": {
        "description": "Detects DNS zone transfer attempts (AXFR).",
        "category": "Reconnaissance",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "any", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "53",
            "msg": "SNORTFORGE DNS Zone Transfer Attempt",
            "content": "|00 FC|", "flow": "to_server,established",
            "classtype": "attempted-recon", "sid": 1000008, "rev": 1, "priority": 2,
        },
    },
    "Reverse Shell - Netcat": {
        "description": "Detects potential Netcat-based reverse shell activity.",
        "category": "Malware / C2",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$HOME_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$EXTERNAL_NET", "dst_port": "any",
            "msg": "SNORTFORGE Possible Netcat Reverse Shell",
            "content": "/bin/sh", "flow": "established",
            "classtype": "trojan-activity", "sid": 1000009, "rev": 1, "priority": 1,
        },
    },
    "HTTP Directory Traversal": {
        "description": "Detects directory traversal attempts in HTTP requests.",
        "category": "Web Application",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "$EXTERNAL_NET", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "$HTTP_PORTS",
            "msg": "SNORTFORGE HTTP Directory Traversal Attempt",
            "content": "../", "flow": "to_server,established",
            "classtype": "web-application-attack", "sid": 1000010, "rev": 1, "priority": 2,
        },
    },
    "SMB EternalBlue Probe": {
        "description": "Detects SMB traffic targeting EternalBlue (MS17-010).",
        "category": "Exploit",
        "rule": {
            "action": "alert", "protocol": "tcp",
            "src_ip": "any", "src_port": "any",
            "direction": "->", "dst_ip": "$HOME_NET", "dst_port": "445",
            "msg": "SNORTFORGE Possible EternalBlue SMB Exploit Attempt",
            "content": "|FF|SMB", "flow": "to_server,established",
            "classtype": "attempted-admin", "sid": 1000011, "rev": 1, "priority": 1,
        },
    },
    "DNS Tunneling Indicator": {
        "description": "Detects unusually long DNS queries indicating DNS tunneling.",
        "category": "Malware / C2",
        "rule": {
            "action": "alert", "protocol": "udp",
            "src_ip": "$HOME_NET", "src_port": "any",
            "direction": "->", "dst_ip": "any", "dst_port": "53",
            "msg": "SNORTFORGE Possible DNS Tunneling - Long Query",
            "pcre": "/[a-zA-Z0-9]{50,}/",
            "classtype": "trojan-activity", "sid": 1000012, "rev": 1, "priority": 2,
        },
    },
}


def get_template_names():
    return list(TEMPLATES.keys())


def get_template_categories():
    return sorted(set(t["category"] for t in TEMPLATES.values()))


def get_templates_by_category(category=None):
    if not category or category == "all":
        return TEMPLATES
    return {n: d for n, d in TEMPLATES.items() if d["category"] == category}


def load_template(name):
    if name not in TEMPLATES:
        return None
    return SnortRule.from_dict(TEMPLATES[name]["rule"])


def get_templates_json():
    """Return templates as JSON-ready list."""
    result = []
    for name, data in TEMPLATES.items():
        rule = SnortRule.from_dict(data["rule"])
        result.append({
            "name": name,
            "category": data["category"],
            "description": data["description"],
            "rule_text": rule.build(),
            "rule_data": data["rule"],
        })
    return result
