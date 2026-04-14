"""
Command — lightweight descriptor for a single tool invocation.

A ``Command`` is returned by ``ToolSpec.build_commands()`` (future use) and
can also be constructed directly when migrating tools.

Example::

    cmd = Command(
        args=["nmap", "-sT", target],
        output_path="/tmp/nmap_out_abc123",
    )
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Command:
    args: List[str]
    output_path: str
    sudo: bool = True
    env: Optional[Dict[str, str]] = None
