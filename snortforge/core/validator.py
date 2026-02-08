"""
SnortForge - Rule Validator
"""

import re
from .rule import SnortRule

VALID_ACTIONS = ["alert", "log", "pass", "drop", "reject", "sdrop"]
VALID_PROTOCOLS = ["tcp", "udp", "icmp", "ip"]
VALID_DIRECTIONS = ["->", "<>"]
VALID_CLASSTYPES = [
    "attempted-admin", "attempted-user", "inappropriate-content",
    "policy-violation", "shellcode-detect", "successful-admin",
    "successful-user", "trojan-activity", "unsuccessful-user",
    "web-application-attack", "attempted-dos", "attempted-recon",
    "bad-unknown", "default-login-attempt", "denial-of-service",
    "misc-attack", "non-standard-protocol", "rpc-portmap-decode",
    "successful-dos", "successful-recon-largescale",
    "successful-recon-limited", "suspicious-filename-detect",
    "suspicious-login", "system-call-detect",
    "unusual-client-port-connection", "web-application-activity",
    "icmp-event", "misc-activity", "network-scan", "not-suspicious",
    "protocol-command-decode", "string-detect", "unknown", "tcp-connection",
]
VALID_FLOW_OPTIONS = [
    "to_client", "to_server", "from_client", "from_server",
    "established", "not_established", "stateless",
    "no_stream", "only_stream", "no_frag", "only_frag",
]

IP_PATTERN = re.compile(
    r'^(any|\$\w+|!?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?'
    r'|!?\[[\d\.\,/\s\!\$\w]+\])$'
)
PORT_PATTERN = re.compile(
    r'^(any|\$\w+|!?\d{1,5}(:\d{1,5})?|!?\[\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*\])$'
)


def validate_rule(rule: SnortRule) -> dict:
    """Validate a rule and return dict with errors, warnings, is_valid."""
    errors = []
    warnings = []

    # Action
    if rule.action not in VALID_ACTIONS:
        errors.append(f"Invalid action '{rule.action}'. Must be: {', '.join(VALID_ACTIONS)}")

    # Protocol
    if rule.protocol not in VALID_PROTOCOLS:
        errors.append(f"Invalid protocol '{rule.protocol}'. Must be: {', '.join(VALID_PROTOCOLS)}")

    # Network
    for label, value in [("Source IP", rule.src_ip), ("Destination IP", rule.dst_ip)]:
        if not IP_PATTERN.match(value):
            errors.append(f"Invalid {label}: '{value}'")
    for label, value in [("Source port", rule.src_port), ("Destination port", rule.dst_port)]:
        if not PORT_PATTERN.match(value):
            errors.append(f"Invalid {label}: '{value}'")
    if rule.src_ip == "any" and rule.dst_ip == "any":
        warnings.append("Both source and destination IPs are 'any' — rule may be overly broad.")
    if rule.src_port == "any" and rule.dst_port == "any":
        warnings.append("Both ports are 'any' — consider narrowing scope.")

    # Direction
    if rule.direction not in VALID_DIRECTIONS:
        errors.append(f"Invalid direction '{rule.direction}'. Must be '->' or '<>'.")

    # Message
    if not rule.msg:
        errors.append("Rule message (msg) is required.")
    elif len(rule.msg) < 5:
        warnings.append("Rule message is very short — use a descriptive message.")
    elif '"' in rule.msg or ";" in rule.msg:
        errors.append("Message must not contain '\"' or ';' characters.")

    # SID
    if rule.sid < 1000000:
        warnings.append(f"SID {rule.sid} is reserved (< 1,000,000). Custom rules should use >= 1,000,000.")
    if rule.rev < 1:
        errors.append("Revision must be >= 1.")

    # Content
    if not rule.content and not rule.pcre:
        warnings.append("No content or PCRE — rule matches on header only.")
    if rule.content and "|" in rule.content:
        hex_parts = re.findall(r'\|([^|]*)\|', rule.content)
        for part in hex_parts:
            cleaned = part.replace(" ", "")
            if len(cleaned) % 2 != 0:
                errors.append(f"Invalid hex: '|{part}|' — must have even number of hex chars.")
            if not re.match(r'^[0-9a-fA-F\s]+$', part):
                errors.append(f"Invalid hex: '|{part}|' — contains non-hex characters.")

    # Flow
    if rule.flow:
        parts = [p.strip() for p in rule.flow.split(",")]
        for part in parts:
            if part not in VALID_FLOW_OPTIONS:
                errors.append(f"Invalid flow option '{part}'.")
    elif rule.protocol == "tcp":
        warnings.append("No flow option for TCP — consider adding 'established'.")

    # Classtype
    if rule.classtype and rule.classtype not in VALID_CLASSTYPES:
        warnings.append(f"Classtype '{rule.classtype}' is non-standard.")

    # PCRE
    if rule.pcre:
        if not rule.pcre.startswith("/") or rule.pcre.count("/") < 2:
            errors.append("PCRE must be in format: /pattern/flags")

    # Threshold
    if rule.threshold_type:
        if rule.threshold_type not in ["limit", "threshold", "both"]:
            errors.append("Threshold type must be 'limit', 'threshold', or 'both'.")
        if rule.threshold_track not in ["by_src", "by_dst"]:
            errors.append("Threshold track must be 'by_src' or 'by_dst'.")
        if rule.threshold_count <= 0:
            errors.append("Threshold count must be > 0.")
        if rule.threshold_seconds <= 0:
            errors.append("Threshold seconds must be > 0.")

    # Depth/Offset
    if rule.depth > 0 and not rule.content:
        errors.append("Depth requires content.")
    if rule.offset > 0 and not rule.content:
        errors.append("Offset requires content.")
    if rule.depth > 0 and rule.offset >= rule.depth:
        warnings.append("Offset >= depth — content may never match.")

    return {
        "is_valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }
