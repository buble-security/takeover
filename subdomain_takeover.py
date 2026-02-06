import argparse
import csv
import json
import logging
import random
import re
import socket
import sys
import time
import concurrent.futures
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import dns.resolver
    import dns.name
    import dns.rdatatype
    import dns.exception
except ImportError:
    sys.exit("[!] Modul 'dnspython' belum install. Install: pip install dnspython")

try:
    import requests
except ImportError:
    sys.exit("[!] Modul 'requests' belum install. Install: pip install requests")

FINGERPRINT_URL = (
    "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz"
    "/refs/heads/master/fingerprints.json"
)
FINGERPRINT_CACHE = Path("fingerprints_cache.json")

FRESH_RESOLVERS_URL = (
    "https://raw.githubusercontent.com/proabiral/Fresh-Resolvers"
    "/refs/heads/master/resolvers.txt"
)
RESOLVER_CACHE = Path("resolvers_cache.txt")

STATIC_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"]

USER_AGENT_URLS = [
    "https://raw.githubusercontent.com/HyperBeats/User-Agent-List/main/useragents-desktop.txt",
    "https://raw.githubusercontent.com/HyperBeats/User-Agent-List/main/useragents-linux.txt",
]
USER_AGENT_CACHE = Path("useragents_cache.txt")
FALLBACK_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


DNS_TIMEOUT = 5.0
HTTP_TIMEOUT = 10
MAX_WORKERS = 20
RESOLVER_HEALTH_TIMEOUT = 3.0
RESOLVER_HEALTH_DOMAIN = "google.com"
MAX_RESOLVERS_TO_USE = 5000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("SubTakeover")


@dataclass
class Fingerprint:
    service: str
    cname: list[str]
    fingerprint: str
    nxdomain: bool
    vulnerable: bool
    status: str
    http_status: Optional[int] = None
    cicd_pass: bool = False
    discussion: str = ""
    documentation: str = ""


@dataclass
class DNSResult:
    subdomain: str
    has_cname: bool = False
    cname_chain: list[str] = field(default_factory=list)
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    nxdomain: bool = False
    servfail: bool = False
    no_answer: bool = False
    error: str = ""
    resolver_used: str = ""


@dataclass
class TakeoverResult:
    subdomain: str
    risk_level: str

    service: str
    description: str
    cname_chain: list[str] = field(default_factory=list)
    evidence: str = ""
    dangling: bool = False
    vulnerable_service: bool = False


class ResolverManager:

    def __init__(
        self,
        mode: str = "fresh",
        url: str = FRESH_RESOLVERS_URL,
        cache: Path = RESOLVER_CACHE,
        custom_file: str | None = None,
        max_resolvers: int = MAX_RESOLVERS_TO_USE,
    ):
        self.mode = mode
        self.url = url
        self.cache = cache
        self.custom_file = custom_file
        self.max_resolvers = max_resolvers
        self.resolvers: list[str] = []
        self._healthy: list[str] = []

    def load(self) -> list[str]:
        if self.mode == "fresh":
            self.resolvers = self._fetch_fresh()
        elif self.mode == "static":
            self.resolvers = list(STATIC_RESOLVERS)
            log.info("Menggunakan %d resolver statis (Google/CF/Quad9)",
                     len(self.resolvers))
        elif self.mode == "custom" and self.custom_file:
            self.resolvers = self._load_custom(self.custom_file)
        else:
            self.resolvers = list(STATIC_RESOLVERS)

        if not self.resolvers:
            log.warning("Tidak ada resolver yang dimuat, fallback ke statis")
            self.resolvers = list(STATIC_RESOLVERS)

        return self.resolvers

    def validate(self, max_workers: int = 30) -> list[str]:
        if self.mode == "static":
            self._healthy = list(self.resolvers)
            return self._healthy

        log.info(
            "Memvalidasi %d resolver (maks %d digunakan)...",
            len(self.resolvers), self.max_resolvers,
        )

        candidates = self.resolvers
        if len(candidates) > self.max_resolvers * 3:
            candidates = random.sample(candidates, self.max_resolvers * 3)

        healthy = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self._health_check, ip): ip
                for ip in candidates
            }
            for future in concurrent.futures.as_completed(future_map):
                ip = future_map[future]
                try:
                    if future.result():
                        healthy.append(ip)
                        if len(healthy) >= self.max_resolvers:

                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                except Exception:
                    pass

        self._healthy = healthy[:self.max_resolvers]
        log.info(
            "✓ %d resolver siap digunakan (dari %d kandidat)",
            len(self._healthy), len(candidates),
        )
        return self._healthy

    def get_healthy(self) -> list[str]:
        return self._healthy if self._healthy else self.resolvers

    def get_random_subset(self, count: int = 3) -> list[str]:
        pool = self._healthy if self._healthy else self.resolvers
        if len(pool) <= count:
            return list(pool)
        return random.sample(pool, count)

    def _fetch_fresh(self) -> list[str]:
        try:
            log.info("Mengunduh fresh resolvers dari proabiral...")
            resp = requests.get(self.url, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            raw = resp.text.strip()
            resolvers = self._parse_resolver_list(raw)

            self.cache.write_text(raw, encoding="utf-8")
            log.info(
                "✓ %d fresh resolvers diunduh (resolver diperbarui setiap jam)",
                len(resolvers),
            )
            return resolvers
        except Exception as exc:
            log.warning("Gagal mengunduh fresh resolvers: %s", exc)
            if self.cache.exists():
                log.info("Memuat resolvers dari cache lokal: %s", self.cache)
                raw = self.cache.read_text(encoding="utf-8")
                resolvers = self._parse_resolver_list(raw)
                log.info("✓ %d resolvers dimuat dari cache", len(resolvers))
                return resolvers
            log.warning("Tidak ada cache, fallback ke resolver statis")
            return list(STATIC_RESOLVERS)

    def _load_custom(self, filepath: str) -> list[str]:
        path = Path(filepath)
        if not path.exists():
            log.error("File resolver tidak ditemukan: %s", filepath)
            return list(STATIC_RESOLVERS)
        raw = path.read_text(encoding="utf-8")
        resolvers = self._parse_resolver_list(raw)
        log.info("✓ %d resolvers dimuat dari file: %s",
                 len(resolvers), filepath)
        return resolvers

    @staticmethod
    def _parse_resolver_list(text: str) -> list[str]:
        resolvers = []
        ip_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        )
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):

                ip = line.split(":")[0].split("#")[0].strip()
                if ip_pattern.match(ip):
                    resolvers.append(ip)
        return resolvers

    @staticmethod
    def _health_check(resolver_ip: str) -> bool:
        try:
            test_resolver = dns.resolver.Resolver()
            test_resolver.nameservers = [resolver_ip]
            test_resolver.timeout = RESOLVER_HEALTH_TIMEOUT
            test_resolver.lifetime = RESOLVER_HEALTH_TIMEOUT
            test_resolver.resolve(RESOLVER_HEALTH_DOMAIN, "A")
            return True
        except Exception:
            return False


class FingerprintDB:
    def __init__(self, url: str = FINGERPRINT_URL, cache: Path = FINGERPRINT_CACHE):
        self.url = url
        self.cache = cache
        self.fingerprints: list[Fingerprint] = []

    def load(self) -> list[Fingerprint]:
        raw = self._fetch()
        self.fingerprints = [self._parse(entry) for entry in raw]
        vuln_count = sum(1 for fp in self.fingerprints if fp.vulnerable)
        log.info(
            "Fingerprint DB dimuat: %d layanan (%d rentan)",
            len(self.fingerprints), vuln_count,
        )
        return self.fingerprints

    def _fetch(self) -> list[dict]:
        try:
            log.info("Mengunduh fingerprint dari %s ...", self.url)
            resp = requests.get(self.url, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            self.cache.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return data
        except Exception as exc:
            log.warning("Gagal mengunduh fingerprint: %s", exc)
            if self.cache.exists():
                log.info("Memuat fingerprint dari cache lokal: %s", self.cache)
                return json.loads(self.cache.read_text(encoding="utf-8"))
            raise RuntimeError(
                "Tidak dapat memuat fingerprint (online maupun cache)."
            ) from exc

    @staticmethod
    def _parse(entry: dict) -> Fingerprint:
        return Fingerprint(
            service=entry.get("service", "Unknown"),
            cname=entry.get("cname", []),
            fingerprint=entry.get("fingerprint", ""),
            nxdomain=entry.get("nxdomain", False),
            vulnerable=entry.get("vulnerable", False),
            status=entry.get("status", ""),
            http_status=entry.get("http_status"),
            cicd_pass=entry.get("cicd_pass", False),
            discussion=entry.get("discussion", ""),
            documentation=entry.get("documentation", ""),
        )


class DNSChecker:

    def __init__(
        self,
        resolver_manager: ResolverManager,
        timeout: float = DNS_TIMEOUT,
        rotate: bool = True,
    ):
        self.resolver_manager = resolver_manager
        self.timeout = timeout
        self.rotate = rotate

    def _create_resolver(self) -> tuple[dns.resolver.Resolver, str]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        if self.rotate:

            nameservers = self.resolver_manager.get_random_subset(3)
        else:
            nameservers = self.resolver_manager.get_healthy()[:3]

        resolver.nameservers = nameservers
        return resolver, nameservers[0] if nameservers else "unknown"

    def check(self, subdomain: str) -> DNSResult:
        result = DNSResult(subdomain=subdomain)
        resolver, resolver_ip = self._create_resolver()
        result.resolver_used = resolver_ip
        self._resolve_cname(result, resolver)
        self._resolve_a(result, resolver)
        self._resolve_aaaa(result, resolver)
        self._resolve_ns(result, resolver)
        return result

    def _resolve_cname(self, result: DNSResult, resolver: dns.resolver.Resolver):
        try:
            answers = resolver.resolve(result.subdomain, "CNAME")
            for rdata in answers:
                target = str(rdata.target).rstrip(".")
                result.cname_chain.append(target)
            result.has_cname = len(result.cname_chain) > 0

            visited = set(result.cname_chain)
            to_resolve = list(result.cname_chain)
            depth = 0
            while to_resolve and depth < 10:

                current = to_resolve.pop(0)
                depth += 1
                try:
                    deeper = resolver.resolve(current, "CNAME")
                    for rdata in deeper:
                        target = str(rdata.target).rstrip(".")
                        if target not in visited:
                            visited.add(target)
                            result.cname_chain.append(target)
                            to_resolve.append(target)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.exception.DNSException):
                    pass

        except dns.resolver.NXDOMAIN:
            result.nxdomain = True
        except dns.resolver.NoAnswer:
            result.no_answer = True
        except dns.resolver.NoNameservers:
            result.servfail = True
        except dns.exception.DNSException as exc:
            result.error = str(exc)

    def _resolve_a(self, result: DNSResult, resolver: dns.resolver.Resolver):
        try:
            answers = resolver.resolve(result.subdomain, "A")
            result.a_records = [str(rdata) for rdata in answers]
        except dns.exception.DNSException:
            pass

    def _resolve_aaaa(self, result: DNSResult, resolver: dns.resolver.Resolver):
        try:
            answers = resolver.resolve(result.subdomain, "AAAA")
            result.aaaa_records = [str(rdata) for rdata in answers]
        except dns.exception.DNSException:
            pass

    def _resolve_ns(self, result: DNSResult, resolver: dns.resolver.Resolver):
        try:
            answers = resolver.resolve(result.subdomain, "NS")
            result.ns_records = [str(rdata).rstrip(".") for rdata in answers]
        except dns.exception.DNSException:
            pass


class UserAgentManager:
    def __init__(
        self,
        urls: list[str] = None,
        cache: Path = USER_AGENT_CACHE,
        fallback: list[str] = None,
    ):
        self.urls = urls or list(USER_AGENT_URLS)
        self.cache = cache
        self.fallback = fallback or list(FALLBACK_USER_AGENTS)
        self._agents: list[str] = []

    def load(self) -> list[str]:
        all_agents: list[str] = []
        for url in self.urls:
            try:
                log.info("Mengunduh User-Agent dari %s ...", url)
                resp = requests.get(url, timeout=HTTP_TIMEOUT)
                resp.raise_for_status()
                agents = [
                    line.strip()
                    for line in resp.text.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                log.info("  ✓ %d User-Agent diunduh dari %s",
                         len(agents), url.split("/")[-1])
                all_agents.extend(agents)
            except Exception as exc:
                log.warning("Gagal mengunduh User-Agent dari %s: %s", url, exc)

        if all_agents:
            seen = set()
            unique = []
            for ua in all_agents:
                if ua not in seen:
                    seen.add(ua)
                    unique.append(ua)
            self._agents = unique
            self.cache.write_text("\n".join(self._agents), encoding="utf-8")
            log.info(
                "✓ Total %d User-Agent unik dimuat dan di-cache ke %s",
                len(self._agents), self.cache,
            )
        elif self.cache.exists():
            log.warning(
                "Gagal mengunduh, memuat User-Agent dari cache lokal: %s", self.cache)
            raw = self.cache.read_text(encoding="utf-8")
            self._agents = [line.strip()
                            for line in raw.splitlines() if line.strip()]
            log.info("✓ %d User-Agent dimuat dari cache", len(self._agents))
        else:
            log.warning(
                "Tidak ada User-Agent yang tersedia, menggunakan fallback")
            self._agents = list(self.fallback)

        return self._agents

    def get_random(self) -> str:
        if not self._agents:
            self.load()
        return random.choice(self._agents)

    def count(self) -> int:
        return len(self._agents)


class HTTPProber:
    def __init__(self, timeout: int = HTTP_TIMEOUT, ua_manager: UserAgentManager = None):
        self.timeout = timeout
        self.ua_manager = ua_manager or UserAgentManager()
        if not self.ua_manager._agents:
            self.ua_manager.load()
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        self.session.verify = False

    def _rotate_user_agent(self):
        ua = self.ua_manager.get_random()
        self.session.headers["User-Agent"] = ua
        log.debug("User-Agent dirotasi: %s", ua[:80])

    def probe(self, subdomain: str) -> tuple[int | None, str]:
        for scheme in ("https", "http"):
            try:
                self._rotate_user_agent()
                resp = self.session.get(
                    f"{scheme}://{subdomain}",
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                return resp.status_code, resp.text[:5000]
            except Exception:
                continue
        return None, ""


class TakeoverAnalyzer:
    def __init__(self, fingerprints: list[Fingerprint]):
        self.fingerprints = fingerprints
        self.prober = HTTPProber()

    def analyze(self, dns_result: DNSResult) -> list[TakeoverResult]:
        findings: list[TakeoverResult] = []

        if dns_result.nxdomain and dns_result.has_cname:
            findings.append(TakeoverResult(
                subdomain=dns_result.subdomain,
                risk_level="HIGH",
                service="Unknown",
                description="CNAME menunjuk ke domain yang mengembalikan NXDOMAIN",
                cname_chain=dns_result.cname_chain,
                dangling=True,
            ))

        if dns_result.nxdomain:
            for fp in self.fingerprints:
                if fp.nxdomain and fp.vulnerable:
                    for cname_pattern in fp.cname:
                        if any(cname_pattern in c for c in dns_result.cname_chain):
                            findings.append(TakeoverResult(
                                subdomain=dns_result.subdomain,
                                risk_level="CRITICAL",
                                service=fp.service,
                                description=(
                                    f"NXDOMAIN + CNAME cocok dengan layanan rentan: "
                                    f"{fp.service}"
                                ),
                                cname_chain=dns_result.cname_chain,
                                evidence="NXDOMAIN",
                                dangling=True,
                                vulnerable_service=True,
                            ))

        if dns_result.has_cname:
            matched_services = self._match_cname_fingerprints(dns_result)
            for fp in matched_services:
                if fp.vulnerable:
                    status_code, body = self.prober.probe(dns_result.subdomain)
                    fp_match = self._check_fingerprint_body(
                        fp.fingerprint, body)

                    if fp_match or (fp.http_status and status_code == fp.http_status):
                        findings.append(TakeoverResult(
                            subdomain=dns_result.subdomain,
                            risk_level="CRITICAL",
                            service=fp.service,
                            description=(
                                f"Fingerprint terdeteksi! Layanan '{fp.service}' "
                                f"rentan terhadap subdomain takeover."
                            ),
                            cname_chain=dns_result.cname_chain,
                            evidence=fp.fingerprint[:200],
                            dangling=True,
                            vulnerable_service=True,
                        ))
                    else:
                        findings.append(TakeoverResult(
                            subdomain=dns_result.subdomain,
                            risk_level="MEDIUM",
                            service=fp.service,
                            description=(
                                f"CNAME mengarah ke layanan rentan '{fp.service}', "
                                f"tetapi fingerprint tidak sepenuhnya cocok."
                            ),
                            cname_chain=dns_result.cname_chain,
                            vulnerable_service=True,
                        ))
                else:
                    findings.append(TakeoverResult(
                        subdomain=dns_result.subdomain,
                        risk_level="INFO",
                        service=fp.service,
                        description=(
                            f"CNAME mengarah ke '{fp.service}' "
                            f"(status: {fp.status})."
                        ),
                        cname_chain=dns_result.cname_chain,
                    ))

        if (dns_result.has_cname
                and not dns_result.a_records
                and not dns_result.aaaa_records
                and not dns_result.nxdomain):
            already_reported = any(f.dangling for f in findings)
            if not already_reported:
                findings.append(TakeoverResult(
                    subdomain=dns_result.subdomain,
                    risk_level="HIGH",
                    service="Unknown",
                    description=(
                        "Dangling DNS: CNAME ada tetapi tidak ada A/AAAA record "
                        "yang dapat di-resolve. Target mungkin tidak aktif."
                    ),
                    cname_chain=dns_result.cname_chain,
                    dangling=True,
                ))

        if dns_result.servfail:
            findings.append(TakeoverResult(
                subdomain=dns_result.subdomain,
                risk_level="MEDIUM",
                service="DNS",
                description=(
                    "SERVFAIL: Server DNS tidak merespons. "
                    "Mungkin delegasi NS yang rusak (dangling NS)."
                ),
                dangling=True,
            ))

        if not findings:
            findings.append(TakeoverResult(
                subdomain=dns_result.subdomain,
                risk_level="SAFE",
                service="-",
                description="Tidak ada indikasi subdomain takeover.",
                cname_chain=dns_result.cname_chain,
            ))

        return findings

    def _match_cname_fingerprints(
        self, dns_result: DNSResult
    ) -> list[Fingerprint]:
        matched = []
        for fp in self.fingerprints:
            for pattern in fp.cname:
                pattern_lower = pattern.lower()
                for cname in dns_result.cname_chain:
                    if pattern_lower in cname.lower():
                        matched.append(fp)
                        break
                else:
                    continue
                break
        return matched

    @staticmethod
    def _check_fingerprint_body(fingerprint: str, body: str) -> bool:
        if not fingerprint or not body:
            return False
        if fingerprint == "NXDOMAIN":
            return False
        try:
            return bool(re.search(re.escape(fingerprint), body, re.IGNORECASE))
        except re.error:
            return fingerprint.lower() in body.lower()


class ReportGenerator:
    RISK_COLORS = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[31m",
        "MEDIUM":   "\033[33m",
        "LOW":      "\033[36m",
        "INFO":     "\033[34m",
        "SAFE":     "\033[32m",
    }
    RESET = "\033[0m"

    def __init__(
        self,
        results: list[TakeoverResult],
        dns_results: list[DNSResult],
        resolver_info: dict | None = None,
    ):
        self.results = results
        self.dns_results = dns_results
        self.resolver_info = resolver_info or {}

    def print_console(self):
        print("\n" + "=" * 80)
        print("  HASIL SUBDOMAIN TAKEOVER & DANGLING DNS DETECTOR ")
        print(
            f"  Waktu: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Total subdomain diperiksa: {len(self.dns_results)}")
        if self.resolver_info:
            print(f"  Resolver mode : {self.resolver_info.get('mode', 'N/A')}")
            print(
                f"  Resolver aktif: {self.resolver_info.get('healthy_count', 'N/A')}")
        print("=" * 80)

        stats: dict[str, int] = {}
        for r in self.results:
            stats[r.risk_level] = stats.get(r.risk_level, 0) + 1

        print("\n┌─ RINGKASAN ─────────────────────────────────────┐")
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"):
            count = stats.get(level, 0)
            color = self.RISK_COLORS.get(level, "")
            if count > 0:
                print(f"│  {color}{level:10s}{self.RESET} : {count:4d} temuan")
        print("└─────────────────────────────────────────────────┘\n")

        actionable = [r for r in self.results if r.risk_level != "SAFE"]
        actionable.sort(
            key=lambda r: ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").index(
                r.risk_level
            )
            if r.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            else 99
        )

        if not actionable:
            print("  ✅ Tidak ada potensi risiko yang ditemukan.\n")
            return

        print("┌─ DETAIL TEMUAN ─────────────────────────────────┐\n")
        for idx, r in enumerate(actionable, 1):
            color = self.RISK_COLORS.get(r.risk_level, "")
            print(f"  [{idx}] {color}[{r.risk_level}]{self.RESET} {r.subdomain}")
            print(f"      Layanan  : {r.service}")
            print(f"      Deskripsi: {r.description}")
            if r.cname_chain:
                chain = " → ".join(r.cname_chain)
                print(f"      CNAME    : {r.subdomain} → {chain}")
            if r.evidence:
                print(f"      Evidence : {r.evidence[:120]}")
            if r.dangling:
                print(f"      ⚠  Dangling DNS Entry Terdeteksi")
            print()

        print("└─────────────────────────────────────────────────┘\n")

    def export_json(self, path: str):
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_checked": len(self.dns_results),
            "resolver_info": self.resolver_info,
            "summary": {},
            "findings": [],
        }
        for r in self.results:
            report["summary"][r.risk_level] = (
                report["summary"].get(r.risk_level, 0) + 1
            )
        for r in self.results:
            if r.risk_level != "SAFE":
                report["findings"].append(asdict(r))

        Path(path).write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        log.info("Laporan JSON disimpan ke: %s", path)

    def export_csv(self, path: str):
        fieldnames = [
            "subdomain", "risk_level", "service", "description",
            "cname_chain", "evidence", "dangling", "vulnerable_service",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in self.results:
                row = asdict(r)
                row["cname_chain"] = " → ".join(row["cname_chain"])
                writer.writerow(row)
        log.info("Laporan CSV disimpan ke: %s", path)


def generate_subdomains(
    domain: str,
    wordlist_path: str | None = None,
) -> list[str]:

    DEFAULT_PREFIXES = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
        "blog", "dev", "staging", "api", "app", "admin", "portal",
        "test", "demo", "beta", "cdn", "assets", "static", "media",
        "shop", "store", "docs", "wiki", "git", "ci", "jenkins",
        "jira", "confluence", "vpn", "remote", "mx", "imap",
        "autodiscover", "sip", "lyncdiscover", "enterprise",
        "cloud", "aws", "azure", "gcp", "s3", "heroku",
        "status", "monitor", "grafana", "kibana", "elastic",
        "staging2", "uat", "preprod", "sandbox", "internal",
    ]

    subdomains = []
    if wordlist_path:
        wl = Path(wordlist_path)
        if not wl.exists():
            log.error("Wordlist tidak ditemukan: %s", wordlist_path)
            sys.exit(1)
        with open(wl, encoding="utf-8", errors="ignore") as f:
            for line in f:
                prefix = line.strip().lower()
                if prefix and not prefix.startswith("#"):
                    subdomains.append(f"{prefix}.{domain}")
        log.info("Dimuat %d subdomain dari wordlist: %s", len(subdomains), wl)
    else:
        subdomains = [f"{p}.{domain}" for p in DEFAULT_PREFIXES]
        log.info(
            "Menggunakan %d prefix subdomain bawaan untuk %s",
            len(subdomains), domain,
        )

    return subdomains


def load_targets_file(filepath: str) -> list[str]:
    targets = []
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                targets.append(line)
    log.info("Dimuat %d target dari file: %s", len(targets), filepath)
    return targets


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Takeover & Dangling DNS Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  %(prog)s -d example.com
  %(prog)s -d example.com -w wordlist.txt
  %(prog)s -l subdomains.txt -o report.json
  %(prog)s -d example.com --resolver-mode static  

  %(prog)s -d example.com --resolver-file my_resolvers.txt
        """,
    )
    parser.add_argument(
        "-d", "--domain",
        help="Single Domain target (mis: example.com)",
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Path file wordlist subdomain prefix",
    )
    parser.add_argument(
        "-l", "--list",
        help="Path file berisi daftar subdomain (satu per baris)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Path output JSON",
    )
    parser.add_argument(
        "--csv",
        help="Path output CSV",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=MAX_WORKERS,
        help=f"Jumlah thread paralel (default: {MAX_WORKERS})",
    )
    parser.add_argument(
        "--resolver-mode",
        choices=["fresh", "static", "custom"],
        default="fresh",
        help=(
            "Mode resolver DNS: "
            "'fresh' = proabiral Fresh-Resolvers (default), "
            "'static' = Google/Cloudflare/Quad9, "
            "'custom' = dari file sendiri"
        ),
    )
    parser.add_argument(
        "--resolver-file",
        help="Path ke file resolver costum (satu IP per baris, butuh --resolver-mode custom)",
    )
    parser.add_argument(
        "--max-resolvers",
        type=int,
        default=MAX_RESOLVERS_TO_USE,
        help=f"Maks resolver yang digunakan setelah validasi (default: {MAX_RESOLVERS_TO_USE})",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Lewati validasi resolver (lebih cepat, kurang akurat)",
    )
    parser.add_argument(
        "--no-http",
        action="store_true",
        help="Lewati pemeriksaan HTTP (hanya DNS)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Tampilkan log detail (DEBUG level)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.domain and not args.list:
        parser.error("Harus menyediakan -d/--domain atau -l/--list")

    if args.resolver_mode == "custom" and not args.resolver_file:
        parser.error("--resolver-mode custom memerlukan --resolver-file")

    log.info("=" * 60)
    log.info("SUBDOMAIN TAKEOVER & DANGLING DNS DETECTOR ")
    log.info("=" * 60)

    resolver_mgr = ResolverManager(
        mode=args.resolver_mode,
        custom_file=args.resolver_file,
        max_resolvers=args.max_resolvers,
    )
    resolver_mgr.load()

    if not args.skip_validation:
        resolver_mgr.validate()
    else:
        log.info("Validasi resolver dilewati (--skip-validation)")

    healthy_resolvers = resolver_mgr.get_healthy()
    resolver_info = {
        "mode": args.resolver_mode,
        "source": (
            FRESH_RESOLVERS_URL if args.resolver_mode == "fresh"
            else ("static" if args.resolver_mode == "static" else args.resolver_file)
        ),
        "total_loaded": len(resolver_mgr.resolvers),
        "healthy_count": len(healthy_resolvers),
        "sample": healthy_resolvers[:5],
    }
    log.info("Resolver siap: %d aktif, mode=%s", len(
        healthy_resolvers), args.resolver_mode)

    fp_db = FingerprintDB()
    fingerprints = fp_db.load()

    targets: list[str] = []
    if args.list:
        targets = load_targets_file(args.list)
    if args.domain:
        targets.extend(generate_subdomains(args.domain, args.wordlist))

    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    targets = unique_targets

    if not targets:
        log.error("Tidak ada target subdomain untuk diperiksa.")
        sys.exit(1)

    log.info("Total target unik: %d", len(targets))

    dns_checker = DNSChecker(resolver_manager=resolver_mgr, rotate=True)
    dns_results: list[DNSResult] = []

    log.info("Memulai pemeriksaan DNS dengan %d thread...", args.threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_map = {
            executor.submit(dns_checker.check, target): target
            for target in targets
        }
        for i, future in enumerate(
            concurrent.futures.as_completed(future_map), 1
        ):
            subdomain = future_map[future]
            try:
                result = future.result()
                dns_results.append(result)
                status = "CNAME" if result.has_cname else (
                    "NXDOMAIN" if result.nxdomain else "OK"
                )
                log.debug(
                    "[%d/%d] %s → %s (via %s)",
                    i, len(targets), subdomain, status, result.resolver_used,
                )
            except Exception as exc:
                log.error("Error memeriksa %s: %s", subdomain, exc)
                dns_results.append(DNSResult(
                    subdomain=subdomain, error=str(exc)
                ))

    log.info(
        "Pemeriksaan DNS selesai. Ditemukan %d dengan CNAME.",
        sum(1 for r in dns_results if r.has_cname),
    )

    log.info("Menganalisis potensi subdomain takeover...")
    analyzer = TakeoverAnalyzer(fingerprints)

    if args.no_http:
        analyzer.prober = None

    all_findings: list[TakeoverResult] = []
    for dns_result in dns_results:
        findings = analyzer.analyze(dns_result)
        all_findings.extend(findings)

    reporter = ReportGenerator(all_findings, dns_results, resolver_info)
    reporter.print_console()

    if args.output:
        reporter.export_json(args.output)
    if args.csv:
        reporter.export_csv(args.csv)

    critical_count = sum(1 for r in all_findings if r.risk_level == "CRITICAL")
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
