from __future__ import annotations

import ipaddress
import re
from datetime import date, datetime, timezone
from typing import Dict, Optional

import requests

from ddos_shield_v2.config import Settings
from ddos_shield_v2.providers.abuseipdb import AbuseIpDbClient
from ddos_shield_v2.providers.ipwho import IpWhoClient
from ddos_shield_v2.providers.rdns import ReverseDnsClient
from ddos_shield_v2.providers.shodan import ShodanInternetDbClient
from ddos_shield_v2.providers.team_cymru import TeamCymruClient
from ddos_shield_v2.schema import (
    ABUSE_USAGE_TYPE_MAP,
    PROVIDER_FAMILY_KEYWORDS,
    REGISTRY_CODE_MAP,
    empty_feature_row,
)
from ddos_shield_v2.types import FeatureBuildContext, ProviderResult


GENERIC_RDNS_PATTERNS = [
    "vps", "cloud", "server", "dedicated", "static", "dynamic", "pool",
    "host", "node", "instance", "compute", "vm-", "colo",
]

MOBILE_KEYWORDS = [
    "mobile", "cellular", "wireless", "4g", "5g", "lte", "airtel", "jio",
    "vodafone", "t-mobile", "verizon wireless", "telefonica", "orange mobile",
]


def _parse_date_to_days(value: str) -> int:
    if not value:
        return -1
    for fmt in ("%Y-%m-%d", "%Y/%m/%d"):
        try:
            parsed = datetime.strptime(value, fmt).date()
            return max((date.today() - parsed).days, 0)
        except ValueError:
            continue
    return -1


def _provider_family_code(text: str) -> int:
    lowered = text.lower()
    for code, keywords in PROVIDER_FAMILY_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return code
    return 0


def _prefix_length(prefix: str) -> int:
    if "/" not in prefix:
        return -1
    try:
        return int(prefix.split("/", 1)[1])
    except ValueError:
        return -1


def _normalize_boolish(value: object) -> int:
    return 1 if value in (1, True, "1", "true", "True") else 0


def _digits_ratio(text: str) -> float:
    return (sum(ch.isdigit() for ch in text) / len(text)) if text else 0.0


def _count_risky_ports(ports: list[int]) -> int:
    risky_ports = {21, 23, 25, 53, 445, 3389}
    return sum(1 for port in ports if port in risky_ports)


def _subnet_of(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


class IPFeatureBuilder:
    """
    Shared feature builder for both offline dataset generation and online scoring.

    The same feature code should be used during training and inference to avoid
    train/serve skew.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or Settings.from_env()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ddos-shield-v2/1.0"})
        self.cymru = TeamCymruClient(timeout=self.settings.request_timeout_seconds)
        self.shodan = ShodanInternetDbClient(session=self.session, timeout=self.settings.request_timeout_seconds)
        self.abuseipdb = AbuseIpDbClient(
            api_key=self.settings.abuseipdb_api_key,
            max_age_days=self.settings.abuseipdb_max_age_days,
            block_max_age_days=self.settings.abuseipdb_block_max_age_days,
            session=self.session,
            timeout=self.settings.request_timeout_seconds,
        )
        self.rdns = ReverseDnsClient()
        self.ipwho = IpWhoClient(session=self.session, timeout=self.settings.request_timeout_seconds)

    def close(self) -> None:
        self.session.close()

    def prefetch_cymru(self, ips: list[str]) -> Dict[str, ProviderResult]:
        return self.cymru.lookup_many(ips)

    def build_context(
        self,
        ip: str,
        cymru_prefetch: Optional[Dict[str, ProviderResult]] = None,
        enable_abuseipdb: bool = True,
        enable_ipwho: bool = True,
    ) -> FeatureBuildContext:
        context = FeatureBuildContext()
        context.cymru = (cymru_prefetch or {}).get(ip) if cymru_prefetch else self.cymru.lookup_one(ip)
        context.shodan = self.shodan.lookup(ip)
        context.rdns = self.rdns.lookup(ip)
        context.abuseipdb = self.abuseipdb.lookup(ip) if enable_abuseipdb else ProviderResult(success=False, error="disabled")
        context.ipwho = (
            self.ipwho.lookup(ip)
            if enable_ipwho and self.settings.use_ipwho_display_lookup
            else ProviderResult(success=False, error="disabled")
        )
        return context

    def build_row(
        self,
        ip: str,
        label: object = "",
        label_name: str = "",
        position: object = "",
        cymru_prefetch: Optional[Dict[str, ProviderResult]] = None,
        enable_abuseipdb: bool = True,
        enable_ipwho: bool = True,
    ) -> Dict[str, object]:
        context = self.build_context(
            ip,
            cymru_prefetch=cymru_prefetch,
            enable_abuseipdb=enable_abuseipdb,
            enable_ipwho=enable_ipwho,
        )
        return self.row_from_context(
            ip=ip,
            context=context,
            label=label,
            label_name=label_name,
            position=position,
        )

    def row_from_context(
        self,
        ip: str,
        context: FeatureBuildContext,
        label: object = "",
        label_name: str = "",
        position: object = "",
    ) -> Dict[str, object]:
        row = empty_feature_row()
        row["position"] = position
        row["ip"] = ip
        row["label"] = label
        row["label_name"] = label_name
        row["cymru_success"] = 1 if context.cymru and context.cymru.success else 0
        row["shodan_success"] = 1 if context.shodan and context.shodan.success else 0
        row["abuseipdb_success"] = 1 if context.abuseipdb and context.abuseipdb.success else 0
        row["rdns_success"] = 1 if context.rdns and context.rdns.success else 0
        row["ipwho_success"] = 1 if context.ipwho and context.ipwho.success else 0
        row["cymru_error"] = "" if not context.cymru or context.cymru.success else context.cymru.error
        row["shodan_error"] = "" if not context.shodan or context.shodan.success else context.shodan.error
        row["abuseipdb_error"] = "" if not context.abuseipdb or context.abuseipdb.success else context.abuseipdb.error
        row["rdns_error"] = "" if not context.rdns or context.rdns.success else context.rdns.error
        row["ipwho_error"] = "" if not context.ipwho or context.ipwho.success else context.ipwho.error

        self._apply_cymru(row, context.cymru)
        self._apply_shodan(row, context.shodan)
        self._apply_abuseipdb(row, context.abuseipdb)
        self._apply_rdns(row, context.rdns)
        self._apply_ipwho(row, context.ipwho)
        self._finalize_derived(row)
        return row

    def _apply_cymru(self, row: Dict[str, object], result: Optional[ProviderResult]) -> None:
        if not result or not result.success:
            return
        data = result.data
        row["asn_number"] = int(data.get("asn_number") or 0)
        row["prefix"] = data.get("prefix", "") or ""
        row["prefix_length"] = _prefix_length(str(row["prefix"]))
        row["registry"] = data.get("registry", "") or ""
        row["registry_code"] = REGISTRY_CODE_MAP.get(str(row["registry"]).lower(), 0)
        row["prefix_age_days"] = _parse_date_to_days(str(data.get("prefix_allocated", "")))
        row["display_asn_name"] = data.get("asn_name", "") or ""
        row["provider_family_code"] = _provider_family_code(str(row["display_asn_name"]))
        row["asn_age_days"] = _parse_date_to_days(str(data.get("asn_allocated", "")))

    def _apply_shodan(self, row: Dict[str, object], result: Optional[ProviderResult]) -> None:
        if not result or not result.success:
            return
        data = result.data
        ports = [int(port) for port in data.get("ports", [])]
        tags = [str(tag).lower() for tag in data.get("tags", [])]
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        cpes = data.get("cpes", [])

        row["in_shodan"] = int(data.get("in_shodan", 0))
        row["num_open_ports"] = len(ports)
        row["num_risky_ports"] = _count_risky_ports(ports)
        row["has_ssh"] = 1 if 22 in ports else 0
        row["has_telnet"] = 1 if 23 in ports else 0
        row["has_http"] = 1 if 80 in ports else 0
        row["has_https"] = 1 if 443 in ports else 0
        row["has_smb"] = 1 if 445 in ports else 0
        row["has_rdp"] = 1 if 3389 in ports else 0
        row["has_mysql"] = 1 if 3306 in ports else 0
        row["has_smtp"] = 1 if 25 in ports else 0
        row["has_dns"] = 1 if 53 in ports else 0
        row["has_ftp"] = 1 if 21 in ports else 0
        row["num_vulns"] = len(vulns)
        row["has_vulns"] = 1 if vulns else 0
        row["num_hostnames"] = len(hostnames)
        row["has_hostname"] = 1 if hostnames else 0
        row["num_tags"] = len(tags)
        row["is_vpn_tagged"] = 1 if "vpn" in tags else 0
        row["is_compromised_tagged"] = 1 if "compromised" in tags else 0
        row["is_iot_tagged"] = 1 if "iot" in tags else 0
        row["num_cpes"] = len(cpes)

    def _apply_abuseipdb(self, row: Dict[str, object], result: Optional[ProviderResult]) -> None:
        if not result or not result.success:
            return
        data = result.data
        row["abuse_confidence_score"] = int(data.get("abuse_confidence_score", 0))
        row["abuse_total_reports"] = int(data.get("abuse_total_reports", 0))
        row["abuse_num_distinct_users"] = int(data.get("abuse_num_distinct_users", 0))
        row["abuse_is_whitelisted"] = int(data.get("abuse_is_whitelisted", 0))
        row["abuse_is_tor"] = int(data.get("abuse_is_tor", 0))
        row["abuse_usage_type_code"] = ABUSE_USAGE_TYPE_MAP.get(str(data.get("abuse_usage_type", "")), 0)
        row["abuse_report_age_days"] = int(data.get("abuse_report_age_days", -1))

        block_result = self.abuseipdb.lookup_block(str(row["ip"]))
        if block_result.success:
            block_data = block_result.data
            row["subnet_abuse_mean_score"] = float(block_data.get("subnet_abuse_mean_score", 0.0))
            row["subnet_max_abuse_score"] = int(block_data.get("subnet_max_abuse_score", 0))
            row["subnet_reported_ip_count"] = int(block_data.get("subnet_reported_ip_count", 0))
            row["subnet_report_density"] = float(block_data.get("subnet_report_density", 0.0))
            row["subnet_last_report_age_days"] = int(block_data.get("subnet_last_report_age_days", -1))

        if not row["display_isp"] and data.get("abuse_isp"):
            row["display_isp"] = data.get("abuse_isp", "")

    def _apply_rdns(self, row: Dict[str, object], result: Optional[ProviderResult]) -> None:
        if not result or not result.success:
            return
        hostname = str(result.data.get("hostname", "") or "")
        row["display_rdns_hostname"] = hostname
        row["has_rdns"] = 1 if hostname else 0
        row["rdns_length"] = len(hostname)
        row["rdns_generic"] = 1 if any(pattern in hostname.lower() for pattern in GENERIC_RDNS_PATTERNS) else 0
        row["rdns_has_numbers"] = 1 if _digits_ratio(hostname) > 0.30 else 0

    def _apply_ipwho(self, row: Dict[str, object], result: Optional[ProviderResult]) -> None:
        if not result or not result.success:
            return
        data = result.data
        row["display_country"] = data.get("display_country", "") or row["display_country"]
        row["display_country_code"] = data.get("display_country_code", "") or row["display_country_code"]
        row["display_isp"] = data.get("display_isp", "") or row["display_isp"]
        row["display_org"] = data.get("display_org", "") or row["display_org"]
        row["ipwho_security_available"] = int(data.get("ipwho_security_available", 0))
        for field in ("is_hosting_provider", "is_proxy", "is_vpn", "is_tor", "is_anonymous"):
            if data.get(field, "") != "":
                row[field] = data[field]

    def _finalize_derived(self, row: Dict[str, object]) -> None:
        combined = " ".join(
            str(value or "")
            for value in (
                row.get("display_isp", ""),
                row.get("display_org", ""),
                row.get("display_asn_name", ""),
                row.get("display_rdns_hostname", ""),
            )
        ).lower()

        if not row["provider_family_code"]:
            row["provider_family_code"] = _provider_family_code(combined)
        row["is_cloud_provider"] = 1 if row["provider_family_code"] else 0

        if row["is_hosting_provider"] == "":
            row["is_hosting_provider"] = 1 if any(word in combined for word in ("hosting", "colo", "datacenter", "data center")) else 0

        row["mobile_network_hint"] = 1 if any(keyword in combined for keyword in MOBILE_KEYWORDS) else 0

        for field in (
            "asn_number",
            "prefix_length",
            "registry_code",
            "asn_age_days",
            "prefix_age_days",
            "provider_family_code",
            "is_cloud_provider",
            "is_hosting_provider",
            "is_proxy",
            "is_vpn",
            "is_tor",
            "is_anonymous",
            "mobile_network_hint",
            "abuse_confidence_score",
            "abuse_total_reports",
            "abuse_num_distinct_users",
            "abuse_is_whitelisted",
            "abuse_is_tor",
            "abuse_usage_type_code",
            "abuse_report_age_days",
            "subnet_abuse_mean_score",
            "subnet_max_abuse_score",
            "subnet_reported_ip_count",
            "subnet_report_density",
            "subnet_last_report_age_days",
            "in_shodan",
            "num_open_ports",
            "num_risky_ports",
            "has_ssh",
            "has_telnet",
            "has_http",
            "has_https",
            "has_smb",
            "has_rdp",
            "has_mysql",
            "has_smtp",
            "has_dns",
            "has_ftp",
            "num_vulns",
            "has_vulns",
            "num_hostnames",
            "has_hostname",
            "num_tags",
            "is_vpn_tagged",
            "is_compromised_tagged",
            "is_iot_tagged",
            "num_cpes",
            "has_rdns",
            "rdns_generic",
            "rdns_length",
            "rdns_has_numbers",
            "ipwho_security_available",
        ):
            if row[field] == "":
                row[field] = -1 if field.endswith("_days") else 0


def prefix_group(ip: str) -> str:
    try:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(network)
    except ValueError:
        return ip
