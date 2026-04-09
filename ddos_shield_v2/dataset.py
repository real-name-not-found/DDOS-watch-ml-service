from __future__ import annotations

import csv
import ipaddress
import random
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import requests


MALICIOUS_FEEDS = {
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
}

TRANCO_LATEST_LIST_URL = "https://tranco-list.eu/latest_list"
TRANCO_MIN_DOMAIN_LIMIT = 5000
TRANCO_DOMAIN_MULTIPLIER = 20

DEFAULT_DOMAIN_TIERS = {
    "major": [
        "google.com", "youtube.com", "facebook.com", "instagram.com", "reddit.com",
        "wikipedia.org", "amazon.com", "microsoft.com", "apple.com", "github.com",
        "stackoverflow.com", "dropbox.com", "cloudflare.com", "adobe.com", "figma.com",
        "canva.com", "notion.so", "python.org", "nodejs.org", "pypi.org",
        "docker.com", "mozilla.org", "bbc.com", "reuters.com", "nytimes.com",
    ],
    "education": [
        "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk", "cam.ac.uk",
        "iitb.ac.in", "iitd.ac.in", "iisc.ac.in", "ethz.ch", "epfl.ch",
        "nus.edu.sg", "utoronto.ca", "imperial.ac.uk", "ucl.ac.uk", "cern.ch",
    ],
    "government": [
        "nasa.gov", "nih.gov", "cdc.gov", "usa.gov", "gov.uk",
        "canada.ca", "australia.gov.au", "india.gov.in", "who.int", "un.org",
    ],
    "regional": [
        "flipkart.com", "zomato.com", "paytm.com", "baidu.com", "qq.com",
        "taobao.com", "yandex.ru", "vk.com", "rakuten.co.jp", "mercadolibre.com",
        "globo.com", "uol.com.br", "tokopedia.com", "lazada.com", "grab.com",
    ],
    "infra": [
        "dns.google", "one.one.one.one", "dns.quad9.net", "pool.ntp.org",
        "time.google.com", "time.apple.com", "time.windows.com", "security.ubuntu.com",
        "archive.ubuntu.com", "registry.npmjs.org", "rubygems.org", "crates.io",
    ],
}


def is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_global


def write_csv(path: Path, rows: Sequence[Dict[str, object]], headers: Sequence[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(headers))
        writer.writeheader()
        for row in rows:
            writer.writerow({header: row.get(header, "") for header in headers})


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def fetch_text(session: requests.Session, url: str, timeout: int = 30) -> str:
    response = session.get(url, timeout=timeout)
    response.raise_for_status()
    return response.text


def parse_ipv4_lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
            yield line


def collect_malicious_ips(session: requests.Session) -> List[str]:
    sources: Dict[str, set[str]] = {"ipsum": set(), "feodo": set(), "blocklist_de": set()}

    text = fetch_text(session, MALICIOUS_FEEDS["ipsum"])
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        ip = parts[0].strip()
        try:
            score = int(parts[1])
        except ValueError:
            continue
        if score >= 2 and is_public_ipv4(ip):
            sources["ipsum"].add(ip)

    text = fetch_text(session, MALICIOUS_FEEDS["feodo"])
    for ip in parse_ipv4_lines(text):
        if is_public_ipv4(ip):
            sources["feodo"].add(ip)

    text = fetch_text(session, MALICIOUS_FEEDS["blocklist_de"])
    for ip in parse_ipv4_lines(text):
        if is_public_ipv4(ip):
            sources["blocklist_de"].add(ip)

    return sorted(set().union(*sources.values()))


def resolve_domain_ipv4s(domain: str) -> List[str]:
    resolved = set()
    try:
        answers = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    for answer in answers:
        ip = answer[4][0]
        if is_public_ipv4(ip):
            resolved.add(ip)
    return sorted(resolved)


def resolve_domains_parallel(domains: Sequence[str], max_workers: int = 64) -> set[str]:
    results: set[str] = set()
    if not domains:
        return results
    worker_count = max(1, min(max_workers, len(domains)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(resolve_domain_ipv4s, domain): domain for domain in domains}
        for future in as_completed(futures):
            try:
                results.update(future.result())
            except Exception:
                continue
    return results


def get_tranco_download_url(session: requests.Session) -> Tuple[str, str]:
    response = session.get(TRANCO_LATEST_LIST_URL, timeout=30, allow_redirects=True)
    response.raise_for_status()
    match = re.search(r"/list/([^/]+)/", response.url)
    if not match:
        raise ValueError("Could not determine latest Tranco list id")
    list_id = match.group(1)
    return list_id, f"https://tranco-list.eu/download/{list_id}/1000000"


def iter_tranco_domains(session: requests.Session, domain_limit: int) -> Iterable[str]:
    _, download_url = get_tranco_download_url(session)
    response = session.get(download_url, timeout=60, stream=True)
    response.raise_for_status()
    try:
        count = 0
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            parts = raw_line.split(",", 1)
            if len(parts) != 2:
                continue
            domain = parts[1].strip()
            if not domain:
                continue
            yield domain
            count += 1
            if count >= domain_limit:
                break
    finally:
        response.close()


def collect_benign_ips(
    session: requests.Session,
    target_count: int,
    extra_domains: Sequence[str] | None = None,
    dns_workers: int = 64,
    use_tranco: bool = True,
    tranco_domain_limit: int = 0,
) -> List[str]:
    benign_ips: set[str] = set()
    seen_domains: set[str] = set()

    for tier_domains in DEFAULT_DOMAIN_TIERS.values():
        fresh_domains = [domain for domain in tier_domains if domain not in seen_domains]
        seen_domains.update(fresh_domains)
        benign_ips.update(resolve_domains_parallel(fresh_domains, max_workers=dns_workers))

    if extra_domains:
        fresh_domains = [domain for domain in extra_domains if domain not in seen_domains]
        seen_domains.update(fresh_domains)
        benign_ips.update(resolve_domains_parallel(fresh_domains, max_workers=dns_workers))

    target_with_buffer = target_count + max(10, target_count // 5)
    if use_tranco and len(benign_ips) < target_with_buffer:
        auto_limit = max(TRANCO_MIN_DOMAIN_LIMIT, target_count * TRANCO_DOMAIN_MULTIPLIER)
        domain_limit = tranco_domain_limit if tranco_domain_limit > 0 else auto_limit
        batch: List[str] = []

        for domain in iter_tranco_domains(session, domain_limit):
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            batch.append(domain)
            if len(batch) >= 500:
                benign_ips.update(resolve_domains_parallel(batch, max_workers=dns_workers))
                batch.clear()
                if len(benign_ips) >= target_with_buffer:
                    break
        if batch and len(benign_ips) < target_with_buffer:
            benign_ips.update(resolve_domains_parallel(batch, max_workers=dns_workers))

    return sorted(benign_ips)


def sample_balanced_sets(
    malicious_ips: Sequence[str],
    benign_ips: Sequence[str],
    malicious_sample: int,
    benign_sample: int,
    seed: int,
) -> Tuple[List[str], List[str]]:
    malicious_set = set(filter(is_public_ipv4, malicious_ips))
    benign_set = set(filter(is_public_ipv4, benign_ips))
    overlap = malicious_set & benign_set
    malicious_set -= overlap
    benign_set -= overlap

    rnd = random.Random(seed)
    malicious_sorted = sorted(malicious_set)
    benign_sorted = sorted(benign_set)

    if len(malicious_sorted) > malicious_sample:
        malicious_sorted = sorted(rnd.sample(malicious_sorted, malicious_sample))
    if len(benign_sorted) > benign_sample:
        benign_sorted = sorted(rnd.sample(benign_sorted, benign_sample))

    min_count = min(len(malicious_sorted), len(benign_sorted))
    return malicious_sorted[:min_count], benign_sorted[:min_count]


def build_worklist(malicious_ips: Sequence[str], benign_ips: Sequence[str], seed: int) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for ip in malicious_ips:
        rows.append({"ip": ip, "label": 1, "label_name": "malicious"})
    for ip in benign_ips:
        rows.append({"ip": ip, "label": 0, "label_name": "low_risk"})

    rnd = random.Random(seed)
    rnd.shuffle(rows)
    for index, row in enumerate(rows, start=1):
        row["position"] = index
    return rows
