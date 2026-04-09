from __future__ import annotations

from typing import Dict, List


REGISTRY_CODE_MAP = {
    "arin": 1,
    "ripe": 2,
    "apnic": 3,
    "lacnic": 4,
    "afrinic": 5,
}

ABUSE_USAGE_TYPE_MAP = {
    "Commercial": 1,
    "Organization": 2,
    "Government": 3,
    "Military": 4,
    "University/College/School": 5,
    "Library": 6,
    "Content Delivery Network": 7,
    "Fixed Line ISP": 8,
    "Mobile ISP": 9,
    "Data Center/Web Hosting/Transit": 10,
    "Search Engine Spider": 11,
    "Reserved": 12,
}

PROVIDER_FAMILY_KEYWORDS = {
    1: ["amazon", "aws", "cloudfront"],
    2: ["google", "gcp"],
    3: ["microsoft", "azure"],
    4: ["cloudflare"],
    5: ["digitalocean"],
    6: ["hetzner"],
    7: ["ovh"],
    8: ["linode", "akamai linode"],
    9: ["vultr", "choopa"],
    10: ["oracle cloud", "oracle"],
}

DISPLAY_COLUMNS: List[str] = [
    "ip",
    "label",
    "label_name",
    "display_country",
    "display_country_code",
    "display_isp",
    "display_org",
    "display_asn_name",
    "display_rdns_hostname",
]

PROVIDER_STATUS_COLUMNS: List[str] = [
    "cymru_success",
    "shodan_success",
    "abuseipdb_success",
    "rdns_success",
    "ipwho_success",
    "ipwho_security_available",
]

CORE_NUMERIC_FEATURES: List[str] = [
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
]

ALL_OUTPUT_COLUMNS: List[str] = (
    ["position", "ip", "label", "label_name"]
    + PROVIDER_STATUS_COLUMNS
    + [
        "cymru_error",
        "shodan_error",
        "abuseipdb_error",
        "rdns_error",
        "ipwho_error",
        "display_country",
        "display_country_code",
        "display_isp",
        "display_org",
        "display_asn_name",
        "display_rdns_hostname",
        "prefix",
        "registry",
    ]
    + CORE_NUMERIC_FEATURES
)


def empty_feature_row() -> Dict[str, object]:
    row: Dict[str, object] = {column: "" for column in ALL_OUTPUT_COLUMNS}
    row["label"] = ""
    row["position"] = ""
    return row
