from __future__ import annotations

import atexit
import ipaddress
from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd

from feature_builder import FeatureBuilder


def validate_public_ipv4(ip_text: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip_text.strip())
    except ValueError as exc:
        raise ValueError("Invalid IP address format") from exc

    if parsed.version != 4:
        raise ValueError("This ML model currently supports public IPv4 addresses only")

    if not parsed.is_global:
        raise ValueError("Private/reserved IP addresses cannot be analyzed by the ML model")

    return str(parsed)


def probability_to_band(probability: float, low_threshold: float, high_threshold: float, middle_label: str) -> str:
    if probability >= high_threshold:
        return "high_risk"
    if probability <= low_threshold:
        return "low_risk"
    return middle_label


class MLPredictor:
    def __init__(self, bundle_path: str | Path = "ml_deployment_bundle.joblib") -> None:
        self.bundle_path = Path(bundle_path)
        artifact = joblib.load(self.bundle_path)

        self.model = artifact["model"]
        self.preprocessor = artifact["preprocessor"]
        self.raw_feature_columns = list(artifact["raw_feature_columns"])
        self.low_risk_threshold = float(artifact["low_risk_threshold"])
        self.high_risk_threshold = float(artifact["high_risk_threshold"])
        self.middle_band_label = str(artifact.get("middle_band_label", "monitor"))
        self.metrics = artifact.get("metrics", {})

        self.builder = FeatureBuilder()
        atexit.register(self.close)

    def close(self) -> None:
        if getattr(self, "builder", None) is not None:
            self.builder.close()
            self.builder = None

    def build_feature_row(self, ip: str) -> Dict[str, Any]:
        safe_ip = validate_public_ipv4(ip)
        return self.builder.build_features(
            ip=safe_ip,
            enable_abuseipdb=False,
            enable_ipwho=False,
        )

    def predict_one(self, ip: str) -> Dict[str, Any]:
        safe_ip = validate_public_ipv4(ip)
        row = self.build_feature_row(safe_ip)

        frame = pd.DataFrame(
            [{column: row.get(column) for column in self.raw_feature_columns}]
        )
        processed = self.preprocessor.transform(frame)
        probability = float(self.model.predict_proba(processed)[:, 1][0])
        band = probability_to_band(
            probability=probability,
            low_threshold=self.low_risk_threshold,
            high_threshold=self.high_risk_threshold,
            middle_label=self.middle_band_label,
        )

        return {
            "ip": safe_ip,
            "ml_malicious_probability": round(probability, 6),
            "risk_band": band,
            "thresholds": {
                "low_risk_below_or_equal": self.low_risk_threshold,
                "high_risk_from_or_equal": self.high_risk_threshold,
                "middle_label": self.middle_band_label,
            },
            "provider_status": {
                "cymru_success": row.get("cymru_success"),
                "shodan_success": row.get("shodan_success"),
                "rdns_success": row.get("rdns_success"),
                "ipwho_success": row.get("ipwho_success"),
                "abuseipdb_success": row.get("abuseipdb_success"),
            },
            "display_context": {
                "country": row.get("display_country"),
                "country_code": row.get("display_country_code"),
                "isp": row.get("display_isp"),
                "org": row.get("display_org"),
                "asn_name": row.get("display_asn_name"),
                "rdns_hostname": row.get("display_rdns_hostname"),
            },
            "model_metadata": self.metrics,
        }
