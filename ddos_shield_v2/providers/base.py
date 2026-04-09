from __future__ import annotations

from typing import Optional

import requests

from ddos_shield_v2.types import ProviderResult


class RequestsProvider:
    def __init__(self, session: Optional[requests.Session] = None, timeout: int = 12) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout
        self.session.headers.setdefault("User-Agent", "ddos-shield-v2/1.0")

    def get_json(self, url: str, **kwargs) -> ProviderResult:
        try:
            response = self.session.get(url, timeout=self.timeout, **kwargs)
            if response.status_code == 404:
                return ProviderResult(success=True, data={"not_found": True})
            response.raise_for_status()
            return ProviderResult(success=True, data=response.json())
        except requests.exceptions.Timeout:
            return ProviderResult(success=False, error="timeout")
        except requests.exceptions.ConnectionError:
            return ProviderResult(success=False, error="connection_error")
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "http"
            return ProviderResult(success=False, error=f"http_{status}")
        except ValueError:
            return ProviderResult(success=False, error="invalid_json")
        except Exception:
            return ProviderResult(success=False, error="unexpected_error")
