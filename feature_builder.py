from __future__ import annotations

"""
Simple shared feature builder for the final-year project version.

Use this file from:
- collect_data_final.py
- train_model_final.py
- predict_ip_final.py

This keeps the feature logic in one place without forcing a big enterprise
folder structure on the project.
"""

from typing import Dict, List, Optional

from ddos_shield_v2.config import Settings
from ddos_shield_v2.feature_builder import IPFeatureBuilder as _V2FeatureBuilder
from ddos_shield_v2.schema import CORE_NUMERIC_FEATURES, DISPLAY_COLUMNS, PROVIDER_STATUS_COLUMNS


MODEL_FEATURES: List[str] = list(CORE_NUMERIC_FEATURES)
DISPLAY_FIELDS: List[str] = list(DISPLAY_COLUMNS)
STATUS_FIELDS: List[str] = list(PROVIDER_STATUS_COLUMNS)


class FeatureBuilder:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self._builder = _V2FeatureBuilder(settings=settings)

    def prefetch_cymru(self, ips: List[str]):
        return self._builder.prefetch_cymru(ips)

    def build_features(
        self,
        ip: str,
        label: object = "",
        label_name: str = "",
        position: object = "",
        cymru_prefetch=None,
        enable_abuseipdb: bool = False,
        enable_ipwho: bool = True,
    ) -> Dict[str, object]:
        return self._builder.build_row(
            ip=ip,
            label=label,
            label_name=label_name,
            position=position,
            cymru_prefetch=cymru_prefetch,
            enable_abuseipdb=enable_abuseipdb,
            enable_ipwho=enable_ipwho,
        )

    def close(self) -> None:
        self._builder.close()
