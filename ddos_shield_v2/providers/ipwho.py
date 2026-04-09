from __future__ import annotations

from ddos_shield_v2.providers.base import RequestsProvider
from ddos_shield_v2.types import ProviderResult


class IpWhoClient(RequestsProvider):
    """
    Optional display metadata source.

    The security fields are explicitly marked as optional because ipwho.is only
    returns them on higher plans when `security=1` is used.
    """

    def lookup(self, ip: str) -> ProviderResult:
        result = self.get_json(f"https://ipwho.is/{ip}?security=1")
        if not result.success:
            return result

        payload = result.data
        if not payload.get("success", False):
            return ProviderResult(success=False, error=str(payload.get("message", "api_error")))

        security = payload.get("security") if isinstance(payload.get("security"), dict) else {}
        connection = payload.get("connection") if isinstance(payload.get("connection"), dict) else {}
        normalized = {
            "display_country": payload.get("country", "") or "",
            "display_country_code": payload.get("country_code", "") or "",
            "display_isp": connection.get("isp", "") or "",
            "display_org": connection.get("org", "") or "",
            "ipwho_security_available": 1 if security else 0,
            "is_hosting_provider": 1 if security.get("hosting") else 0,
            "is_proxy": 1 if security.get("proxy") else 0,
            "is_vpn": 1 if security.get("vpn") else 0,
            "is_tor": 1 if security.get("tor") else 0,
            "is_anonymous": 1 if security.get("anonymous") else 0,
        }
        return ProviderResult(success=True, data=normalized)
