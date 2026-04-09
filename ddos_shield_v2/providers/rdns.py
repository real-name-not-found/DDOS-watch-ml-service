from __future__ import annotations

import socket

from ddos_shield_v2.types import ProviderResult


class ReverseDnsClient:
    def lookup(self, ip: str) -> ProviderResult:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return ProviderResult(success=True, data={"hostname": ""})
        except Exception:
            return ProviderResult(success=False, error="rdns_lookup_failed")
        return ProviderResult(success=True, data={"hostname": hostname})

