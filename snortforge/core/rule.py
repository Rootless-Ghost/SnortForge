"""
SnortForge - Snort Rule Data Model

Supports both single-content (legacy) and multi-content (chained) rules.
When `contents` is populated, it takes priority over the legacy single
content/depth/offset/etc. fields.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ContentMatch:
    """A single content match entry with its own modifiers."""
    content: str = ""
    nocase: bool = False
    negated: bool = False
    http_uri: bool = False
    http_header: bool = False
    depth: int = 0
    offset: int = 0
    distance: int = 0
    within: int = 0

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "nocase": self.nocase,
            "negated": self.negated,
            "http_uri": self.http_uri,
            "http_header": self.http_header,
            "depth": self.depth,
            "offset": self.offset,
            "distance": self.distance,
            "within": self.within,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ContentMatch":
        cm = cls()
        for key, value in data.items():
            if hasattr(cm, key):
                setattr(cm, key, value)
        return cm


@dataclass
class SnortRule:
    """Represents a complete Snort IDS/IPS rule."""

    action: str = "alert"
    protocol: str = "tcp"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"

    msg: str = ""
    sid: int = 1000001
    rev: int = 1
    classtype: str = ""
    priority: int = 0
    references: List[str] = field(default_factory=list)

    # Legacy single-content fields (backward compat)
    content: str = ""
    content_nocase: bool = False
    content_negated: bool = False
    content_http_uri: bool = False
    content_http_header: bool = False
    pcre: str = ""
    depth: int = 0
    offset: int = 0
    distance: int = 0
    within: int = 0

    # Multi-content support
    contents: List[ContentMatch] = field(default_factory=list)

    flow: str = ""

    threshold_type: str = ""
    threshold_track: str = ""
    threshold_count: int = 0
    threshold_seconds: int = 0

    metadata: str = ""

    # ── Helpers ──

    def get_content_matches(self) -> List[ContentMatch]:
        """Return the effective list of content matches.

        If `contents` has entries, use those.
        Otherwise, promote the legacy single content field.
        """
        if self.contents:
            return self.contents
        if self.content:
            return [ContentMatch(
                content=self.content,
                nocase=self.content_nocase,
                negated=self.content_negated,
                http_uri=self.content_http_uri,
                http_header=self.content_http_header,
                depth=self.depth,
                offset=self.offset,
                distance=self.distance,
                within=self.within,
            )]
        return []

    # ── Snort 2 Build ──

    def build(self) -> str:
        header = self._build_header()
        options = self._build_options()
        return f"{header} ({options})"

    def _build_header(self) -> str:
        return (
            f"{self.action} {self.protocol} {self.src_ip} {self.src_port} "
            f"{self.direction} {self.dst_ip} {self.dst_port}"
        )

    def _build_options(self) -> str:
        opts = []
        if self.msg:
            opts.append(f'msg:"{self.msg}"')
        if self.flow:
            opts.append(f"flow:{self.flow}")

        # Content matches (multi or single)
        for cm in self.get_content_matches():
            prefix = "!" if cm.negated else ""
            content_str = f'content:"{prefix}{cm.content}"'
            if cm.nocase:
                content_str += "; nocase"
            if cm.http_uri:
                content_str += "; http_uri"
            if cm.http_header:
                content_str += "; http_header"
            opts.append(content_str)
            if cm.depth > 0:
                opts.append(f"depth:{cm.depth}")
            if cm.offset > 0:
                opts.append(f"offset:{cm.offset}")
            if cm.distance > 0:
                opts.append(f"distance:{cm.distance}")
            if cm.within > 0:
                opts.append(f"within:{cm.within}")

        if self.pcre:
            opts.append(f'pcre:"{self.pcre}"')
        if self.classtype:
            opts.append(f"classtype:{self.classtype}")
        if self.priority > 0:
            opts.append(f"priority:{self.priority}")
        for ref in self.references:
            if ref:
                opts.append(f"reference:{ref}")
        if self.metadata:
            opts.append(f"metadata:{self.metadata}")
        if self.threshold_type and self.threshold_count > 0 and self.threshold_seconds > 0:
            opts.append(
                f"threshold:type {self.threshold_type}, "
                f"track {self.threshold_track}, "
                f"count {self.threshold_count}, "
                f"seconds {self.threshold_seconds}"
            )
        opts.append(f"sid:{self.sid}")
        opts.append(f"rev:{self.rev}")
        return "; ".join(opts) + ";"

    # ── Snort 3 Build ──

    def build_snort3(self) -> str:
        """Build the rule in Snort 3 syntax.

        Key differences from Snort 2:
        - 'http_uri' becomes the sticky buffer 'http.uri; content:...'
        - 'http_header' becomes the sticky buffer 'http.header; content:...'
        - 'nocase' is still valid but follows content immediately
        - Threshold uses 'detection_filter' keyword for Snort 3
        - Positional modifiers use space instead of colon (depth 4 vs depth:4)
        """
        header = self._build_header()
        opts = self._build_snort3_options()
        return f"{header} ({opts})"

    def _build_snort3_options(self) -> str:
        opts = []
        if self.msg:
            opts.append(f'msg:"{self.msg}"')
        if self.flow:
            opts.append(f"flow:{self.flow}")

        # Content matches — Snort 3 sticky buffers
        for cm in self.get_content_matches():
            prefix = "!" if cm.negated else ""

            # Sticky buffer declared BEFORE content in Snort 3
            if cm.http_uri:
                opts.append("http.uri")
            elif cm.http_header:
                opts.append("http.header")

            content_str = f'content:"{prefix}{cm.content}"'
            if cm.nocase:
                content_str += "; nocase"
            opts.append(content_str)

            # Snort 3 uses space instead of colon for positional mods
            if cm.depth > 0:
                opts.append(f"depth {cm.depth}")
            if cm.offset > 0:
                opts.append(f"offset {cm.offset}")
            if cm.distance > 0:
                opts.append(f"distance {cm.distance}")
            if cm.within > 0:
                opts.append(f"within {cm.within}")

        if self.pcre:
            opts.append(f'pcre:"{self.pcre}"')
        if self.classtype:
            opts.append(f"classtype:{self.classtype}")
        if self.priority > 0:
            opts.append(f"priority:{self.priority}")
        for ref in self.references:
            if ref:
                opts.append(f"reference:{ref}")
        if self.metadata:
            opts.append(f"metadata:{self.metadata}")

        # Snort 3: detection_filter replaces threshold
        if self.threshold_type and self.threshold_count > 0 and self.threshold_seconds > 0:
            opts.append(
                f"detection_filter:track {self.threshold_track}, "
                f"count {self.threshold_count}, "
                f"seconds {self.threshold_seconds}"
            )

        opts.append(f"sid:{self.sid}")
        opts.append(f"rev:{self.rev}")
        return "; ".join(opts) + ";"

    # ── Serialization ──

    def to_dict(self) -> dict:
        d = {
            "action": self.action, "protocol": self.protocol,
            "src_ip": self.src_ip, "src_port": self.src_port,
            "direction": self.direction,
            "dst_ip": self.dst_ip, "dst_port": self.dst_port,
            "msg": self.msg, "sid": self.sid, "rev": self.rev,
            "classtype": self.classtype, "priority": self.priority,
            "references": self.references,
            "content": self.content,
            "content_nocase": self.content_nocase,
            "content_negated": self.content_negated,
            "content_http_uri": self.content_http_uri,
            "content_http_header": self.content_http_header,
            "pcre": self.pcre, "depth": self.depth, "offset": self.offset,
            "distance": self.distance, "within": self.within,
            "contents": [cm.to_dict() for cm in self.contents],
            "flow": self.flow,
            "threshold_type": self.threshold_type,
            "threshold_track": self.threshold_track,
            "threshold_count": self.threshold_count,
            "threshold_seconds": self.threshold_seconds,
            "metadata": self.metadata,
        }
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "SnortRule":
        rule = cls()
        for key, value in data.items():
            # Backward compat: accept old "reference" string key
            if key == "reference" and isinstance(value, str):
                if value:
                    rule.references = [value]
                continue
            # Deserialize contents list
            if key == "contents" and isinstance(value, list):
                rule.contents = [
                    ContentMatch.from_dict(c) if isinstance(c, dict) else c
                    for c in value
                    if isinstance(c, dict) and c.get("content")
                ]
                continue
            if hasattr(rule, key):
                setattr(rule, key, value)
        return rule
