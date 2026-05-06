"""Reconnaissance engine — network and web discovery."""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

import requests


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5432, 5900, 5985, 5986, 8080, 8443, 9200, 9300,
]


@dataclass
class PortResult:
    host: str
    port: int
    state: str
    banner: str | None = None
    service: str | None = None


@dataclass
class WebInfo:
    url: str
    status_code: int | None = None
    server: str | None = None
    technologies: list[str] | None = None
    title: str | None = None


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Attempt to grab a service banner."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            probes = [b"HEAD / HTTP/1.0\r\n\r\n", b"\r\n", b"\x00" * 8]
            for probe in probes:
                try:
                    s.send(probe)
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        return banner[:200]
                except Exception:
                    continue
    except Exception:
        pass
    return None


def _identify_service(port: int, banner: str | None) -> str | None:
    """Guess service name from port and banner."""
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
        3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
        8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    }
    if banner:
        banner_lower = banner.lower()
        for keyword, svc in [("ssh", "ssh"), ("smtp", "smtp"), ("ftp", "ftp"),
                              ("http", "http"), ("nginx", "nginx"), ("apache", "apache")]:
            if keyword in banner_lower:
                return svc
    return services.get(port)


def scan_port(host: str, port: int, timeout: float = 1.0, grab: bool = True) -> PortResult | None:
    """Scan a single TCP port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            banner = grab_banner(host, port, timeout=timeout) if grab else None
            service = _identify_service(port, banner)
            return PortResult(host=host, port=port, state="open", banner=banner, service=service)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def port_scan(
    hosts: list[str],
    ports: list[int] | None = None,
    threads: int = 100,
    timeout: float = 1.0,
) -> list[PortResult]:
    """Multi-threaded TCP port scan."""
    if ports is None:
        ports = COMMON_PORTS

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): (host, port)
            for host in hosts
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return sorted(results, key=lambda r: (r.host, r.port))


def enum_subdomains(domain: str) -> list[str]:
    """Enumerate subdomains via crt.sh."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        subs = set()
        for entry in r.json():
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub.endswith(domain) and sub != domain:
                    subs.add(sub)
        return sorted(subs)
    except Exception:
        return []


def fingerprint_web(url: str) -> WebInfo:
    """Fingerprint technologies on a web application."""
    info = WebInfo(url=url)
    try:
        r = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        info.status_code = r.status_code
        headers = r.headers
        text = r.text.lower()

        info.server = headers.get("Server") or headers.get("X-Powered-By")
        info.technologies = []

        if "wp-content" in text or "wp-includes" in text:
            info.technologies.append("WordPress")
        if "django" in text:
            info.technologies.append("Django")
        if "next.js" in text or "__next" in text:
            info.technologies.append("Next.js")
        if "react" in text:
            info.technologies.append("React")
        if "laravel" in text:
            info.technologies.append("Laravel")
        if "express" in text:
            info.technologies.append("Express.js")
        if "fastapi" in text:
            info.technologies.append("FastAPI")
        if "nginx" in (info.server or "").lower():
            info.technologies.append("nginx")
        if "apache" in (info.server or "").lower():
            info.technologies.append("Apache")

        title_match = text.find("<title>")
        if title_match != -1:
            end = text.find("</title>", title_match)
            if end != -1:
                info.title = r.text[title_match + 7:end].strip()

    except Exception:
        pass
    return info


def discover_api_endpoints(base_url: str, wordlist: list[str] | None = None) -> list[dict[str, Any]]:
    """Discover API endpoints via brute-forcing."""
    if wordlist is None:
        wordlist = [
            "users", "admin", "api", "v1", "v2", "auth", "login", "register",
            "health", "status", "metrics", "debug", "config", "env", "backup",
            "graphql", "search", "items", "orders", "payments", "swagger.json",
            "openapi.json", "api-docs", "docs",
        ]

    endpoints = []
    prefixes = ["/", "/api/", "/api/v1/", "/api/v2/", "/rest/", "/graphql", "/internal/"]

    for word in wordlist:
        for prefix in prefixes:
            url = base_url.rstrip("/") + prefix + word
            try:
                r = requests.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 401, 403, 405, 500]:
                    endpoints.append({"url": url, "status": r.status_code, "length": len(r.content)})
            except Exception:
                pass
    return endpoints
