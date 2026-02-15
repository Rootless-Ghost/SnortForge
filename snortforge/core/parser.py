"""
SnortForge - Rule Parser
"""

import re
import logging
from .rule import SnortRule

logger = logging.getLogger(__name__)


class ParseError(Exception):
    pass


def parse_rule(rule_string: str) -> SnortRule:
    rule_string = rule_string.strip()
    if not rule_string or rule_string.startswith("#"):
        raise ParseError("Empty or commented rule.")

    match = re.match(r'^(\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s*\((.+)\)\s*$', rule_string)
    if not match:
        raise ParseError("Could not parse rule structure.")

    header_parts = match.group(1).split()
    if len(header_parts) != 7:
        raise ParseError(f"Expected 7 header fields, got {len(header_parts)}.")

    rule = SnortRule()
    rule.action, rule.protocol = header_parts[0], header_parts[1]
    rule.src_ip, rule.src_port = header_parts[2], header_parts[3]
    rule.direction = header_parts[4]
    rule.dst_ip, rule.dst_port = header_parts[5], header_parts[6]

    _parse_options(match.group(2), rule)
    return rule


def _parse_options(options_str, rule):
    tokens = _tokenize_options(options_str)
    for opt in tokens:
        opt = opt.strip()
        if not opt:
            continue
        if ":" in opt:
            key, _, value = opt.partition(":")
            key, value = key.strip(), value.strip()
        else:
            key, value = opt.strip(), ""
        _apply_option(key, value, rule)


def _tokenize_options(options_str):
    tokens, current, in_quotes = [], [], False
    for char in options_str:
        if char == '"' and (not current or current[-1] != '\\'):
            in_quotes = not in_quotes
            current.append(char)
        elif char == ';' and not in_quotes:
            tokens.append(''.join(current))
            current = []
        else:
            current.append(char)
    if current:
        tokens.append(''.join(current))
    return tokens


def _apply_option(key, value, rule):
    value = value.strip('"').strip("'")
    mapping = {
        "msg": ("msg", str), "sid": ("sid", int), "rev": ("rev", int),
        "classtype": ("classtype", str), "priority": ("priority", int),
        "content": None, "pcre": ("pcre", str), "flow": ("flow", str),
        "depth": ("depth", int), "offset": ("offset", int),
        "distance": ("distance", int), "within": ("within", int),
        "reference": ("reference", str), "metadata": ("metadata", str),
        "nocase": None, "threshold": None,
    }

    if key == "content":
        if value.startswith("!"):
            rule.content_negated = True
            rule.content = value[1:].strip('"')
        else:
            rule.content = value
    elif key == "nocase":
        rule.content_nocase = True
    elif key == "threshold":
        for part in value.split(","):
            kv = part.strip().split()
            if len(kv) == 2:
                k, v = kv
                if k == "type": rule.threshold_type = v
                elif k == "track": rule.threshold_track = v
                elif k == "count":
                    try: rule.threshold_count = int(v)
                    except: pass
                elif k == "seconds":
                    try: rule.threshold_seconds = int(v)
                    except: pass
    elif key in mapping and mapping[key]:
        attr, typ = mapping[key]
        try:
            setattr(rule, attr, typ(value))
        except (ValueError, TypeError):
            pass


def parse_rules_file(filepath):
    rules, errors = [], []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
                # Controlled, user-friendly parse error message
            try:
                rules.append(parse_rule(line))
            except ParseError as e:
                errors.append(f"Line {line_num}: {str(e)}")
            except Exception:
                # Log detailed exception server-side, but return a generic message to the client
                logger.exception("Unexpected error while parsing rule on line %d", line_num)
                errors.append(f"Line {line_num}: Internal parsing error.")
    return rules, errors
