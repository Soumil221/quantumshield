# services/asset_discovery.py
#
# Asset Discovery pipeline for Quantum Shield.
#
# Pipeline (per domain):
#   1. Subfinder  → raw subdomain list
#   2. DNS        → resolve each subdomain to an IPv4 address
#   3. Nmap       → scan common ports per unique IP
#   4. Assemble   → merge into a list of DiscoveredAsset objects
#
# Async note:
#   subprocess.run() is inherently blocking.  For a production deployment
#   with many concurrent scan requests, replace run_command() calls with
#   asyncio.create_subprocess_exec() and await the coroutines, or offload
#   to a ThreadPoolExecutor / Celery worker queue.  The interface of this
#   module (discover_assets) stays identical — only the I/O strategy changes.

import asyncio
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address

from models import DiscoveredAsset
from utils.subprocess_runner import SubprocessResult, run_command

logger = logging.getLogger(__name__)

# ── Tuneable constants ────────────────────────────────────────────────────── #

# Ports forwarded to nmap.  Extend this list as new phases are added.
SCAN_PORTS: list[int] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
SCAN_PORTS_STR: str = ",".join(map(str, SCAN_PORTS))

SUBFINDER_TIMEOUT: int = 120   # seconds — large domains may take a while
DNS_TIMEOUT: float = 5.0       # seconds per individual resolution
NMAP_TIMEOUT: int = 60         # seconds per host
DNS_WORKERS: int = 20          # concurrent DNS threads
NMAP_WORKERS: int = 10         # concurrent nmap threads


# ─────────────────────────────────────────────────────────────────────────── #
# Step 1 — Subdomain discovery via Subfinder                                  #
# ─────────────────────────────────────────────────────────────────────────── #

def run_subfinder(domain: str) -> list[str]:
    """
    Invoke Subfinder and return a deduplicated, sorted list of subdomains.

    Subfinder's -silent flag suppresses banners so stdout contains only
    one subdomain per line — making parsing trivial.

    Returns an empty list on any failure (logged, not raised).
    """
    logger.info("[subfinder] Starting subdomain enumeration for: %s", domain)

    result: SubprocessResult = run_command(
        ["subfinder", "-d", domain, "-silent"],
        timeout=SUBFINDER_TIMEOUT,
    )

    if result.tool_missing:
        logger.error(
            "[subfinder] Tool not installed. "
            "Install via: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )
        return []

    if result.timed_out:
        logger.warning("[subfinder] Timed out after %ds for domain: %s", SUBFINDER_TIMEOUT, domain)
        return []

    if not result.success and result.returncode != 0:
        # subfinder may exit non-zero but still produce valid output
        logger.warning("[subfinder] Exited with code %d, attempting to parse output anyway.", result.returncode)

    subdomains: list[str] = result.stdout_lines

    # Sanitise: keep only valid-looking hostnames, strip accidental whitespace
    subdomains = [s.strip().lower() for s in subdomains if _looks_like_hostname(s)]

    # Deduplicate while preserving discovered order
    seen: set[str] = set()
    unique: list[str] = []
    for s in subdomains:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    logger.info("[subfinder] Discovered %d unique subdomains for %s", len(unique), domain)
    return unique


def _looks_like_hostname(value: str) -> bool:
    """Cheap guard to reject obviously garbage lines in subfinder output."""
    value = value.strip()
    if not value or " " in value or value.startswith(("#", "//", "http")):
        return False
    # Must contain at least one dot (rules out bare labels and error messages)
    return "." in value


# ─────────────────────────────────────────────────────────────────────────── #
# Step 2 — DNS resolution                                                     #
# ─────────────────────────────────────────────────────────────────────────── #

def resolve_subdomain(subdomain: str) -> str | None:
    """
    Resolve *subdomain* to its first IPv4 address.

    Returns None if resolution fails for any reason so callers can skip
    unresolvable hosts without crashing the pipeline.
    """
    try:
        # getaddrinfo returns a list of 5-tuples; take the first IPv4 result.
        infos = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        if infos:
            # Ensure we always return a string (some platforms/types may be
            # interpreted as non-str by static analyzers); cast explicitly.
            ip = str(infos[0][4][0])
            logger.debug("[dns] %s → %s", subdomain, ip)
            return ip
    except socket.gaierror as exc:
        logger.debug("[dns] Could not resolve %s: %s", subdomain, exc)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[dns] Unexpected error resolving %s: %s", subdomain, exc)
    return None


def resolve_all(subdomains: list[str]) -> dict[str, str]:
    """
    Resolve a list of subdomains concurrently using a thread pool.

    Returns:
        Mapping of subdomain → ip_address for every successfully resolved host.
    """
    if not subdomains:
        return {}

    logger.info("[dns] Resolving %d subdomains (workers=%d) …", len(subdomains), DNS_WORKERS)

    # socket.getaddrinfo() releases the GIL, so threading gives real speedup here.
    resolved: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        future_to_host = {pool.submit(resolve_subdomain, host): host for host in subdomains}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            try:
                ip = future.result(timeout=DNS_TIMEOUT + 1)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[dns] Worker exception for %s: %s", host, exc)
                ip = None
            if ip:
                resolved[host] = ip

    logger.info("[dns] Resolved %d / %d subdomains.", len(resolved), len(subdomains))
    return resolved


# ─────────────────────────────────────────────────────────────────────────── #
# Step 3 — Port scanning via Nmap                                              #
# ─────────────────────────────────────────────────────────────────────────── #

# Regex to extract open ports from nmap's grepable (-oG) output.
# Example line: Host: 1.2.3.4 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
_NMAP_PORT_RE = re.compile(r"(\d+)/open/tcp")


def scan_ports(ip: str) -> list[int]:
    """
    Run nmap against *ip* and return a list of open TCP port numbers.

    Uses grepable output (-oG -) for reliable line-by-line parsing.
    -T4 speeds up the scan; adjust to -T3 for stealthier behaviour.
    --open limits output to confirmed-open ports only.
    """
    logger.info("[nmap] Scanning %s on ports %s", ip, SCAN_PORTS_STR)

    # Validate ip before passing to subprocess to prevent command injection.
    try:
        ip_address(ip)  # raises ValueError for invalid addresses
    except ValueError:
        logger.error("[nmap] Invalid IP address, skipping: %r", ip)
        return []

    result: SubprocessResult = run_command(
        [
            "nmap",
            "-p", SCAN_PORTS_STR,
            "-T4",           # Aggressive timing — adjust for stealth
            "--open",        # Only show open ports in output
            "-oG", "-",      # Grepable format to stdout
            "--host-timeout", f"{NMAP_TIMEOUT}s",
            ip,
        ],
        timeout=NMAP_TIMEOUT + 10,  # outer wall-clock > inner host-timeout
    )

    if result.tool_missing:
        logger.error(
            "[nmap] Tool not installed. "
            "Install via: sudo apt install nmap  OR  brew install nmap"
        )
        return []

    if result.timed_out:
        logger.warning("[nmap] Timed out scanning %s", ip)
        return []

    open_ports = _parse_nmap_output(result.stdout)
    logger.info("[nmap] %s — open ports: %s", ip, open_ports or "none")
    return open_ports


def _parse_nmap_output(raw: str) -> list[int]:
    """
    Extract open port numbers from nmap's grepable (-oG) output.

    The grepable format contains lines like:
        Host: 93.184.216.34 ()  Ports: 80/open/tcp//http///, 443/open/tcp//https///
    Comment lines start with '#' and are skipped.
    """
    ports: list[int] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Match every occurrence of "<port>/open/tcp" on this line
        for match in _NMAP_PORT_RE.finditer(line):
            try:
                ports.append(int(match.group(1)))
            except ValueError:
                pass
    return sorted(set(ports))  # deduplicate and sort numerically


# ─────────────────────────────────────────────────────────────────────────── #
# Step 4 — Parallel port scanning across all unique IPs                       #
# ─────────────────────────────────────────────────────────────────────────── #

def scan_all_ports(ip_to_hosts: dict[str, list[str]]) -> dict[str, list[int]]:
    """
    Run nmap concurrently across all unique IPs.

    Args:
        ip_to_hosts: Mapping of ip → [list of hostnames resolving to that ip].

    Returns:
        Mapping of ip → [open port numbers].
    """
    if not ip_to_hosts:
        return {}

    logger.info("[nmap] Scanning %d unique IPs (workers=%d) …", len(ip_to_hosts), NMAP_WORKERS)

    results: dict[str, list[int]] = {}

    with ThreadPoolExecutor(max_workers=NMAP_WORKERS) as pool:
        future_to_ip = {pool.submit(scan_ports, ip): ip for ip in ip_to_hosts}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
            except Exception as exc:  # noqa: BLE001
                logger.warning("[nmap] Worker exception for %s: %s", ip, exc)
                results[ip] = []

    return results


# ─────────────────────────────────────────────────────────────────────────── #
# Public entry point                                                           #
# ─────────────────────────────────────────────────────────────────────────── #

def discover_assets(domain: str) -> list[DiscoveredAsset]:
    """
    Full asset-discovery pipeline for *domain*.

    1. Enumerate subdomains with Subfinder
    2. Resolve each subdomain to an IPv4 address (concurrent DNS)
    3. Port-scan every unique IP with Nmap (concurrent)
    4. Assemble and return a list of DiscoveredAsset objects

    This function is synchronous (blocking).  To call it from an async
    FastAPI route without stalling the event loop, wrap it like:

        assets = await asyncio.get_event_loop().run_in_executor(
            None, discover_assets, domain
        )

    Returns:
        List of DiscoveredAsset — one entry per subdomain that resolved
        successfully.  Empty list if no assets were found or all tools failed.
    """
    logger.info("=== Asset discovery started for: %s ===", domain)

    # ── Step 1: Subdomains ──────────────────────────────────────────────── #
    subdomains: list[str] = run_subfinder(domain)
    if not subdomains:
        logger.warning("No subdomains found for %s — pipeline complete (empty result).", domain)
        return []

    # ── Step 2: DNS resolution ──────────────────────────────────────────── #
    host_to_ip: dict[str, str] = resolve_all(subdomains)
    if not host_to_ip:
        logger.warning("No subdomains resolved to an IP for %s.", domain)
        return []

    # Invert: ip → [hostnames] so we scan each IP exactly once
    ip_to_hosts: dict[str, list[str]] = {}
    for host, ip in host_to_ip.items():
        ip_to_hosts.setdefault(ip, []).append(host)

    # ── Step 3: Port scanning ───────────────────────────────────────────── #
    ip_to_ports: dict[str, list[int]] = scan_all_ports(ip_to_hosts)

    # ── Step 4: Assemble result ─────────────────────────────────────────── #
    assets: list[DiscoveredAsset] = []
    for host, ip in sorted(host_to_ip.items()):  # sort for deterministic output
        ports = ip_to_ports.get(ip, [])
        assets.append(
            DiscoveredAsset(
                host=host,
                ip=ip,
                ports=ports,
            )
        )

    logger.info(
        "=== Asset discovery complete for %s — %d assets, %d unique IPs ===",
        domain,
        len(assets),
        len(ip_to_hosts),
    )
    return assets