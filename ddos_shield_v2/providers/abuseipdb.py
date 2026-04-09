from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Dict

from ddos_shield_v2.providers.base import RequestsProvider
from ddos_shield_v2.types import ProviderResult


def _parse_iso_age_days(value: str) -> int:
    if not value:
        return -1
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return max((now - parsed).days, 0)
    except ValueError:
        return -1


class AbuseIpDbClient(RequestsProvider):
    def __init__(
        self,
        api_key: str,
        max_age_days: int = 90,
        block_max_age_days: int = 30,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.api_key = api_key
        self.max_age_days = max_age_days
        self.block_max_age_days = block_max_age_days
        self._block_cache: Dict[str, ProviderResult] = {}

    def _headers(self) -> Dict[str, str]:
        return {"Key": self.api_key, "Accept": "application/json"}

    def lookup(self, ip: str) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(success=False, error="missing_api_key")

        params = {"ipAddress": ip, "maxAgeInDays": self.max_age_days, "verbose": ""}
        result = self.get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params=params,
            headers=self._headers(),
        )
        if not result.success:
            return result

        payload = result.data.get("data") or {}
        normalized = {
            "abuse_confidence_score": int(payload.get("abuseConfidenceScore") or 0),
            "abuse_total_reports": int(payload.get("totalReports") or 0),
            "abuse_num_distinct_users": int(payload.get("numDistinctUsers") or 0),
            "abuse_is_whitelisted": 1 if payload.get("isWhitelisted") is True else 0,
            "abuse_is_tor": 1 if payload.get("isTor") is True else 0,
            "abuse_usage_type": payload.get("usageType") or "",
            "abuse_report_age_days": _parse_iso_age_days(payload.get("lastReportedAt") or ""),
            "abuse_country_code": payload.get("countryCode") or "",
            "abuse_domain": payload.get("domain") or "",
            "abuse_isp": payload.get("isp") or "",
        }
        return ProviderResult(success=True, data=normalized)

    def lookup_block(self, ip: str) -> ProviderResult:
        if not self.api_key:
            return ProviderResult(success=False, error="missing_api_key")

        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        cache_key = str(network)
        if cache_key in self._block_cache:
            return self._block_cache[cache_key]

        params = {"network": cache_key, "maxAgeInDays": self.block_max_age_days}
        result = self.get_json(
            "https://api.abuseipdb.com/api/v2/check-block",
            params=params,
            headers=self._headers(),
        )
        if not result.success:
            self._block_cache[cache_key] = result
            return result

        payload = result.data.get("data") or {}
        num_possible_hosts = int(payload.get("numPossibleHosts") or 0)
        reported_addresses = payload.get("reportedAddress") or []
        confidence_scores = [int(item.get("abuseConfidenceScore") or 0) for item in reported_addresses]
        report_ages = [_parse_iso_age_days(item.get("mostRecentReport") or item.get("lastReportedAt") or "") for item in reported_addresses]

        normalized = {
            "subnet_abuse_mean_score": round(sum(confidence_scores) / len(confidence_scores), 4) if confidence_scores else 0.0,
            "subnet_max_abuse_score": max(confidence_scores) if confidence_scores else 0,
            "subnet_reported_ip_count": len(reported_addresses),
            "subnet_report_density": round((len(reported_addresses) / num_possible_hosts), 6) if num_possible_hosts > 0 else 0.0,
            "subnet_last_report_age_days": min((age for age in report_ages if age >= 0), default=-1),
        }
        provider_result = ProviderResult(success=True, data=normalized)
        self._block_cache[cache_key] = provider_result
        return provider_result
