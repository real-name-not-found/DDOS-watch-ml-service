from __future__ import annotations

from typing import Dict

from ddos_shield_v2.providers.base import RequestsProvider
from ddos_shield_v2.types import ProviderResult


class ShodanInternetDbClient(RequestsProvider):
    """Free Shodan InternetDB lookups for exposure context."""

    def lookup(self, ip: str) -> ProviderResult:
        result = self.get_json(f"https://internetdb.shodan.io/{ip}")
        if not result.success:
            return result

        if result.data.get("not_found"):
            return ProviderResult(
                success=True,
                data={
                    "in_shodan": 0,
                    "ports": [],
                    "vulns": [],
                    "hostnames": [],
                    "tags": [],
                    "cpes": [],
                },
            )

        payload = result.data
        normalized: Dict[str, object] = {
            "in_shodan": 1,
            "ports": payload.get("ports") or [],
            "vulns": payload.get("vulns") or [],
            "hostnames": payload.get("hostnames") or [],
            "tags": payload.get("tags") or [],
            "cpes": payload.get("cpes") or [],
        }
        return ProviderResult(success=True, data=normalized)

