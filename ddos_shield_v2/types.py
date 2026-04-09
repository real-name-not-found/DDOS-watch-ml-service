from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ProviderResult:
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class FeatureBuildContext:
    cymru: Optional[ProviderResult] = None
    shodan: Optional[ProviderResult] = None
    abuseipdb: Optional[ProviderResult] = None
    rdns: Optional[ProviderResult] = None
    ipwho: Optional[ProviderResult] = None

