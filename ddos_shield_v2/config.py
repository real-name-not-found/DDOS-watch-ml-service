from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    request_timeout_seconds: int = 12
    abuseipdb_max_age_days: int = 90
    abuseipdb_block_max_age_days: int = 30
    use_ipwho_display_lookup: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "").strip(),
            greynoise_api_key=os.getenv("GREYNOISE_API_KEY", "").strip(),
            request_timeout_seconds=int(os.getenv("DDS_REQUEST_TIMEOUT", "12")),
            abuseipdb_max_age_days=int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90")),
            abuseipdb_block_max_age_days=int(os.getenv("ABUSEIPDB_BLOCK_MAX_AGE_DAYS", "30")),
            use_ipwho_display_lookup=os.getenv("USE_IPWHO_DISPLAY_LOOKUP", "1").strip() not in {"0", "false", "False"},
        )

