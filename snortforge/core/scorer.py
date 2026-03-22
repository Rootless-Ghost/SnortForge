"""
SnortForge - Rule Performance Scorer

Evaluates Snort rules against detection engineering best practices
and returns a score (0–100) with a detailed breakdown.

Scoring criteria based on Snort documentation and community guidelines:
  - Content matching presence and quality
  - Positional modifier usage (depth, offset, distance, within)
  - Flow state tracking
  - Protocol and network scope
  - PCRE usage patterns
  - Threshold configuration
  - Metadata completeness
"""

from .rule import SnortRule


# ── Scoring weights (total = 100) ──

CRITERIA = {
    "content_match":     {"weight": 25, "label": "Content Match"},
    "positional_mods":   {"weight": 15, "label": "Positional Modifiers"},
    "flow_state":        {"weight": 15, "label": "Flow State"},
    "network_scope":     {"weight": 15, "label": "Network Scope"},
    "pcre_efficiency":   {"weight": 10, "label": "PCRE Efficiency"},
    "threshold_config":  {"weight": 5,  "label": "Threshold Config"},
    "metadata_quality":  {"weight": 10, "label": "Metadata Quality"},
    "general_hygiene":   {"weight": 5,  "label": "General Hygiene"},
}


def score_rule(rule: SnortRule) -> dict:
    """
    Score a Snort rule and return a detailed breakdown.

    Returns:
        {
            "score": int (0-100),
            "grade": str ("A" through "F"),
            "breakdown": [
                {"name": str, "label": str, "score": int, "max": int,
                 "details": str},
                ...
            ],
            "tips": [str, ...]
        }
    """
    breakdown = []
    tips = []

    # ── 1. Content Match (25 pts) ──
    pts, detail = _score_content(rule, tips)
    breakdown.append({
        "name": "content_match",
        "label": CRITERIA["content_match"]["label"],
        "score": pts,
        "max": CRITERIA["content_match"]["weight"],
        "details": detail,
    })

    # ── 2. Positional Modifiers (15 pts) ──
    pts, detail = _score_positional(rule, tips)
    breakdown.append({
        "name": "positional_mods",
        "label": CRITERIA["positional_mods"]["label"],
        "score": pts,
        "max": CRITERIA["positional_mods"]["weight"],
        "details": detail,
    })

    # ── 3. Flow State (15 pts) ──
    pts, detail = _score_flow(rule, tips)
    breakdown.append({
        "name": "flow_state",
        "label": CRITERIA["flow_state"]["label"],
        "score": pts,
        "max": CRITERIA["flow_state"]["weight"],
        "details": detail,
    })

    # ── 4. Network Scope (15 pts) ──
    pts, detail = _score_network(rule, tips)
    breakdown.append({
        "name": "network_scope",
        "label": CRITERIA["network_scope"]["label"],
        "score": pts,
        "max": CRITERIA["network_scope"]["weight"],
        "details": detail,
    })

    # ── 5. PCRE Efficiency (10 pts) ──
    pts, detail = _score_pcre(rule, tips)
    breakdown.append({
        "name": "pcre_efficiency",
        "label": CRITERIA["pcre_efficiency"]["label"],
        "score": pts,
        "max": CRITERIA["pcre_efficiency"]["weight"],
        "details": detail,
    })

    # ── 6. Threshold Config (5 pts) ──
    pts, detail = _score_threshold(rule, tips)
    breakdown.append({
        "name": "threshold_config",
        "label": CRITERIA["threshold_config"]["label"],
        "score": pts,
        "max": CRITERIA["threshold_config"]["weight"],
        "details": detail,
    })

    # ── 7. Metadata Quality (10 pts) ──
    pts, detail = _score_metadata(rule, tips)
    breakdown.append({
        "name": "metadata_quality",
        "label": CRITERIA["metadata_quality"]["label"],
        "score": pts,
        "max": CRITERIA["metadata_quality"]["weight"],
        "details": detail,
    })

    # ── 8. General Hygiene (5 pts) ──
    pts, detail = _score_hygiene(rule, tips)
    breakdown.append({
        "name": "general_hygiene",
        "label": CRITERIA["general_hygiene"]["label"],
        "score": pts,
        "max": CRITERIA["general_hygiene"]["weight"],
        "details": detail,
    })

    total = sum(b["score"] for b in breakdown)
    grade = _grade(total)

    return {
        "score": total,
        "grade": grade,
        "breakdown": breakdown,
        "tips": tips,
    }


# ── Individual scoring functions ──

def _score_content(rule: SnortRule, tips: list) -> tuple:
    """Score content matching quality."""
    weight = CRITERIA["content_match"]["weight"]
    matches = rule.get_content_matches()

    if not matches and not rule.pcre:
        tips.append("Add a content match or PCRE pattern — header-only rules generate excessive alerts.")
        return 0, "No content or PCRE — header-only detection"

    pts = 0

    if matches:
        pts += 12  # Base points for having content

        # Multi-content bonus — chained matches are more precise
        if len(matches) > 1:
            pts += min(len(matches) - 1, 3) * 2  # Up to 6 bonus pts for chaining
        
        # Evaluate first (primary) content
        primary = matches[0]
        if len(primary.content) >= 8:
            pts += 4
        elif len(primary.content) >= 4:
            pts += 2
        else:
            tips.append("Primary content match is very short — consider a longer, more specific string.")
            pts += 1

        # Check for nocase and HTTP scoping across any match
        has_nocase = any(cm.nocase for cm in matches)
        has_http_scope = any(cm.http_uri or cm.http_header for cm in matches)
        if has_nocase:
            pts += 2
        if has_http_scope:
            pts += 2

    elif rule.pcre:
        pts += 10
        tips.append("Consider adding a fast-pattern content match before your PCRE to improve performance.")

    return min(pts, weight), _content_detail(rule)


def _content_detail(rule: SnortRule) -> str:
    matches = rule.get_content_matches()
    count = len(matches)
    if count > 1 and rule.pcre:
        return f"{count} chained content matches + PCRE"
    elif count > 1:
        return f"{count} chained content matches"
    elif count == 1 and rule.pcre:
        clen = len(matches[0].content)
        return f"Content ({clen} chars) + PCRE"
    elif count == 1:
        clen = len(matches[0].content)
        return f"Content match ({clen} chars)"
    elif rule.pcre:
        return "PCRE only — no fast-pattern content"
    return "No content match"


def _score_positional(rule: SnortRule, tips: list) -> tuple:
    """Score use of depth/offset/distance/within across all content matches."""
    weight = CRITERIA["positional_mods"]["weight"]
    matches = rule.get_content_matches()

    if not matches:
        return 0, "No content — positional modifiers not applicable"

    pts = 0
    all_mods = set()

    for i, cm in enumerate(matches):
        if cm.depth > 0:
            pts += 3
            all_mods.add("depth")
        if cm.offset > 0:
            pts += 2
            all_mods.add("offset")
        if cm.distance > 0:
            pts += 3
            all_mods.add("distance")
        if cm.within > 0:
            pts += 3
            all_mods.add("within")

    if not all_mods:
        tips.append("Add depth/offset modifiers to narrow the search window — improves performance on high-traffic networks.")
        return 0, "No positional modifiers — full payload scan"

    return min(pts, weight), f"Using: {', '.join(sorted(all_mods))}"


def _score_flow(rule: SnortRule, tips: list) -> tuple:
    """Score flow state configuration."""
    weight = CRITERIA["flow_state"]["weight"]

    if rule.protocol not in ("tcp", "udp"):
        # ICMP/IP don't use flow the same way
        return weight, f"Protocol {rule.protocol} — flow not required"

    if not rule.flow:
        tips.append("Add flow:established,to_server (or similar) to limit matching to established sessions.")
        return 0, "No flow option — matches all packets"

    pts = 0
    parts = [p.strip() for p in rule.flow.split(",")]

    if "established" in parts:
        pts += 10
    elif "stateless" in parts:
        pts += 5  # Valid but niche

    if "to_server" in parts or "to_client" in parts or "from_server" in parts or "from_client" in parts:
        pts += 5

    return min(pts, weight), f"Flow: {rule.flow}"


def _score_network(rule: SnortRule, tips: list) -> tuple:
    """Score network scope (IPs and ports)."""
    weight = CRITERIA["network_scope"]["weight"]
    pts = 0

    # IP scoping
    has_src_scope = rule.src_ip != "any"
    has_dst_scope = rule.dst_ip != "any"

    if has_src_scope and has_dst_scope:
        pts += 8
    elif has_src_scope or has_dst_scope:
        pts += 5
    else:
        tips.append("Use variables like $HOME_NET/$EXTERNAL_NET instead of 'any' to reduce scope.")

    # Port scoping
    has_src_port = rule.src_port != "any"
    has_dst_port = rule.dst_port != "any"

    if has_dst_port:
        pts += 5
    elif has_src_port:
        pts += 3
    else:
        if rule.protocol in ("tcp", "udp"):
            tips.append("Specify a destination port to narrow rule scope.")

    # Bonus for using Snort variables
    uses_vars = any(
        v.startswith("$") for v in [rule.src_ip, rule.dst_ip, rule.src_port, rule.dst_port]
    )
    if uses_vars:
        pts += 2

    return min(pts, weight), _network_detail(rule)


def _network_detail(rule: SnortRule) -> str:
    parts = []
    if rule.src_ip != "any":
        parts.append(f"src:{rule.src_ip}")
    if rule.dst_ip != "any":
        parts.append(f"dst:{rule.dst_ip}")
    if rule.dst_port != "any":
        parts.append(f"port:{rule.dst_port}")
    if not parts:
        return "All traffic — any:any → any:any"
    return "Scoped: " + ", ".join(parts)


def _score_pcre(rule: SnortRule, tips: list) -> tuple:
    """Score PCRE usage efficiency."""
    weight = CRITERIA["pcre_efficiency"]["weight"]

    if not rule.pcre:
        # No PCRE is fine — not a penalty, just no bonus
        return weight, "No PCRE — content-based detection"

    pts = 5  # Base for having PCRE

    # Check if content is also present (fast_pattern + PCRE is best practice)
    if rule.content:
        pts += 5
    else:
        tips.append("Add a content match to anchor PCRE — Snort checks content first as a fast-pattern.")

    # Check for expensive patterns
    pcre = rule.pcre
    if ".*" in pcre and ".+" not in pcre:
        # Greedy .* without bounds
        if rule.content:
            pts -= 1  # Minor penalty if content is present
        else:
            pts -= 3
            tips.append("PCRE uses greedy .* without a content anchor — very expensive on high-traffic networks.")

    return max(0, min(pts, weight)), f"PCRE present{' + content anchor' if rule.content else ' (no anchor)'}"


def _score_threshold(rule: SnortRule, tips: list) -> tuple:
    """Score threshold configuration."""
    weight = CRITERIA["threshold_config"]["weight"]

    if rule.threshold_type and rule.threshold_count > 0 and rule.threshold_seconds > 0:
        return weight, f"Threshold: {rule.threshold_type}, count {rule.threshold_count}/{rule.threshold_seconds}s"

    # Threshold is optional — no penalty, but no bonus
    return 2, "No threshold — alerts on every match"


def _score_metadata(rule: SnortRule, tips: list) -> tuple:
    """Score metadata completeness."""
    weight = CRITERIA["metadata_quality"]["weight"]
    pts = 0

    # Message quality
    if rule.msg:
        pts += 3
        if len(rule.msg) >= 15:
            pts += 2
    else:
        tips.append("Add a descriptive alert message for analysts to triage effectively.")

    # SID in custom range
    if rule.sid >= 1000000:
        pts += 2
    else:
        tips.append("SID below 1,000,000 conflicts with official Snort rulesets — use >= 1,000,000.")

    # Classtype
    if rule.classtype:
        pts += 2

    # References
    if rule.references and any(r for r in rule.references):
        pts += 1

    return min(pts, weight), _metadata_detail(rule)


def _metadata_detail(rule: SnortRule) -> str:
    items = []
    if rule.msg:
        items.append("msg")
    if rule.classtype:
        items.append("classtype")
    if rule.references and any(r for r in rule.references):
        items.append(f"{len([r for r in rule.references if r])} ref(s)")
    if rule.sid >= 1000000:
        items.append("custom SID")
    return f"Has: {', '.join(items)}" if items else "Minimal metadata"


def _score_hygiene(rule: SnortRule, tips: list) -> tuple:
    """Score general rule hygiene."""
    weight = CRITERIA["general_hygiene"]["weight"]
    pts = 0

    # Rev >= 1
    if rule.rev >= 1:
        pts += 2

    # Priority set
    if rule.priority > 0:
        pts += 1

    # Not using bidirectional when unidirectional would work
    if rule.direction == "->":
        pts += 2
    elif rule.direction == "<>":
        tips.append("Bidirectional rules (<>) double the processing load — use -> unless truly needed.")
        pts += 1

    return min(pts, weight), f"Direction: {rule.direction}, rev: {rule.rev}"


def _grade(score: int) -> str:
    """Map score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"
