from __future__ import annotations

import ipaddress
import os
from typing import Dict, Iterable, List

from ddos_shield_v2.types import ProviderResult

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - handled at runtime
    dns = None


def _txt_strings(answer) -> List[str]:
    if hasattr(answer, "strings"):
        return [
            part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
            for part in answer.strings
        ]
    return [answer.to_text().strip('"')]


class TeamCymruClient:
    """
    Team Cymru IP-to-ASN mapping via the official DNS interface.

    The official docs recommend the DNS-based service for regular, recurring
    bulk queries and note that IPv4 /24 aggregation is appropriate because more
    specific routes are unlikely. This is also much more Colab-friendly than
    raw TCP WHOIS on port 43.
    """

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout
        self._asn_cache: Dict[int, ProviderResult] = {}
        self._resolver = None
        self._fallback_resolver = None
        if dns is not None:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = timeout
            resolver.lifetime = timeout
            self._resolver = resolver

            # Some local/system DNS resolvers time out on Team Cymru TXT queries
            # even when the records are valid. Keep the system resolver first, but
            # fall back to public resolvers for this specific provider path.
            fallback_nameservers = [
                ns.strip()
                for ns in os.getenv("DDS_DNS_NAMESERVERS", "1.1.1.1,8.8.8.8").split(",")
                if ns.strip()
            ]
            if fallback_nameservers:
                fallback_resolver = dns.resolver.Resolver(configure=False)
                fallback_resolver.nameservers = fallback_nameservers
                fallback_resolver.timeout = timeout
                fallback_resolver.lifetime = timeout
                self._fallback_resolver = fallback_resolver

    def lookup_one(self, ip: str) -> ProviderResult:
        return self.lookup_many([ip]).get(ip, ProviderResult(success=False, error="missing_lookup"))

    def lookup_many(self, ips: Iterable[str]) -> Dict[str, ProviderResult]:
        ip_list = list(dict.fromkeys(ips))
        if not ip_list:
            return {}
        if self._resolver is None:
            return {ip: ProviderResult(success=False, error="dnspython_not_installed") for ip in ip_list}

        prefix_to_ips: Dict[str, List[str]] = {}
        for ip in ip_list:
            try:
                prefix = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except ValueError:
                prefix_to_ips.setdefault(ip, []).append(ip)
                continue
            prefix_to_ips.setdefault(prefix, []).append(ip)

        results: Dict[str, ProviderResult] = {}
        for prefix, prefix_ips in prefix_to_ips.items():
            origin_result = self._lookup_origin(prefix)
            if not origin_result.success:
                for ip in prefix_ips:
                    results[ip] = ProviderResult(success=False, error=origin_result.error)
                continue

            data = dict(origin_result.data)
            asn_number = int(data.get("asn_number") or 0)
            if asn_number > 0:
                asn_result = self._lookup_asn(asn_number)
                if asn_result.success:
                    data.update(asn_result.data)

            provider_result = ProviderResult(success=True, data=data)
            for ip in prefix_ips:
                results[ip] = provider_result

        return results

    def _lookup_origin(self, prefix: str) -> ProviderResult:
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return ProviderResult(success=False, error="invalid_prefix")

        octets = str(network.network_address).split(".")
        query_name = ".".join(reversed(octets[:3])) + ".origin.asn.cymru.com"
        txt_result = self._lookup_txt(query_name)
        if not txt_result.success:
            return txt_result

        record = txt_result.data["record"]
        parts = [part.strip() for part in record.split("|")]
        if len(parts) < 5:
            return ProviderResult(success=False, error="unexpected_origin_format")

        asn_text, returned_prefix, cc, registry, allocated = parts[:5]
        try:
            asn_number = int(asn_text.split()[0])
        except (IndexError, ValueError):
            asn_number = 0

        return ProviderResult(
            success=True,
            data={
                "asn_number": asn_number,
                "prefix": returned_prefix,
                "registry": registry.lower(),
                "prefix_country_code": cc,
                "prefix_allocated": allocated,
            },
        )

    def _lookup_asn(self, asn_number: int) -> ProviderResult:
        cached = self._asn_cache.get(asn_number)
        if cached is not None:
            return cached

        txt_result = self._lookup_txt(f"AS{asn_number}.asn.cymru.com")
        if not txt_result.success:
            self._asn_cache[asn_number] = txt_result
            return txt_result

        record = txt_result.data["record"]
        parts = [part.strip() for part in record.split("|")]
        if len(parts) < 5:
            result = ProviderResult(success=False, error="unexpected_asn_format")
            self._asn_cache[asn_number] = result
            return result

        _, cc, registry, allocated, asn_name = parts[:5]
        result = ProviderResult(
            success=True,
            data={
                "asn_country_code": cc,
                "asn_registry": registry.lower(),
                "asn_allocated": allocated,
                "asn_name": asn_name,
            },
        )
        self._asn_cache[asn_number] = result
        return result

    def _lookup_txt(self, query_name: str) -> ProviderResult:
        last_error: str | None = None

        # Public DNS resolvers are tried first because some local resolvers time
        # out on Team Cymru TXT lookups even when the records themselves are valid.
        resolvers = []
        if self._fallback_resolver is not None:
            resolvers.append(("fallback", self._fallback_resolver))
        if self._resolver is not None:
            resolvers.append(("system", self._resolver))

        for resolver_name, resolver in resolvers:
            try:
                answers = resolver.resolve(query_name, "TXT")
            except dns.resolver.NXDOMAIN:
                return ProviderResult(success=False, error="nxdomain")
            except dns.resolver.NoAnswer:
                return ProviderResult(success=False, error="no_answer")
            except dns.resolver.NoNameservers:
                last_error = "fallback_no_nameservers" if resolver_name == "fallback" else "no_nameservers"
                continue
            except dns.exception.Timeout:
                last_error = "fallback_timeout" if resolver_name == "fallback" else "timeout"
                continue
            except Exception:
                last_error = "fallback_dns_lookup_failed" if resolver_name == "fallback" else "dns_lookup_failed"
                continue

            records: List[str] = []
            for answer in answers:
                records.append("".join(_txt_strings(answer)))

            if not records:
                return ProviderResult(success=False, error="empty_answer")
            return ProviderResult(success=True, data={"record": records[0]})

        return ProviderResult(success=False, error=last_error or "dns_lookup_failed")
