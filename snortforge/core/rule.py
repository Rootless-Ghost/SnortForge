"""
SnortForge - Snort Rule Data Model
"""

from dataclasses import dataclass, field
from typing import Optional


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
    reference: str = ""

    content: str = ""
    content_nocase: bool = False
    content_negated: bool = False
    pcre: str = ""
    depth: int = 0
    offset: int = 0
    distance: int = 0
    within: int = 0

    flow: str = ""

    threshold_type: str = ""
    threshold_track: str = ""
    threshold_count: int = 0
    threshold_seconds: int = 0

    metadata: str = ""

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
        if self.content:
            prefix = "!" if self.content_negated else ""
            content_str = f'content:"{prefix}{self.content}"'
            if self.content_nocase:
                content_str += "; nocase"
            opts.append(content_str)
        if self.depth > 0:
            opts.append(f"depth:{self.depth}")
        if self.offset > 0:
            opts.append(f"offset:{self.offset}")
        if self.distance > 0:
            opts.append(f"distance:{self.distance}")
        if self.within > 0:
            opts.append(f"within:{self.within}")
        if self.pcre:
            opts.append(f'pcre:"{self.pcre}"')
        if self.classtype:
            opts.append(f"classtype:{self.classtype}")
        if self.priority > 0:
            opts.append(f"priority:{self.priority}")
        if self.reference:
            opts.append(f"reference:{self.reference}")
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

    def to_dict(self) -> dict:
        return {
            "action": self.action, "protocol": self.protocol,
            "src_ip": self.src_ip, "src_port": self.src_port,
            "direction": self.direction,
            "dst_ip": self.dst_ip, "dst_port": self.dst_port,
            "msg": self.msg, "sid": self.sid, "rev": self.rev,
            "classtype": self.classtype, "priority": self.priority,
            "reference": self.reference, "content": self.content,
            "content_nocase": self.content_nocase,
            "content_negated": self.content_negated,
            "pcre": self.pcre, "depth": self.depth, "offset": self.offset,
            "distance": self.distance, "within": self.within,
            "flow": self.flow,
            "threshold_type": self.threshold_type,
            "threshold_track": self.threshold_track,
            "threshold_count": self.threshold_count,
            "threshold_seconds": self.threshold_seconds,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SnortRule":
        rule = cls()
        for key, value in data.items():
            if hasattr(rule, key):
                setattr(rule, key, value)
        return rule
