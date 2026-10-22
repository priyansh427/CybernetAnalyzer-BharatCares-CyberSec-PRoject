"""
cyber_net_analyzer.py
═════════════════════
CyberNetAnalyzer — Python Cybersecurity Network Analysis Tool
Single-file edition (all modules inlined).

LEGAL NOTICE
  Use ONLY on networks and devices you own or have explicit written
  authorization to scan.  Unauthorized network scanning is illegal
  in most jurisdictions.

USAGE
  python cyber_net_analyzer.py

DEPENDENCIES
  Required : Python 3.10+  (socket, ipaddress, subprocess,
             concurrent.futures, csv, tkinter — all stdlib)
  Optional : scapy>=2.5.0  →  pip install scapy
             Windows live capture also needs Npcap: https://npcap.com
             Linux live capture: run as root or grant cap_net_raw
"""

from __future__ import annotations

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — Service & Risk Database
# ═══════════════════════════════════════════════════════════════════════════

COMMON_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    67:    "DHCP (server)",
    69:    "TFTP",
    80:    "HTTP",
    88:    "Kerberos",
    110:   "POP3",
    111:   "RPC/portmapper",
    119:   "NNTP",
    123:   "NTP",
    135:   "MS-RPC",
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS-SSN",
    143:   "IMAP",
    161:   "SNMP",
    162:   "SNMP-trap",
    389:   "LDAP",
    443:   "HTTPS",
    445:   "SMB/CIFS",
    465:   "SMTPS",
    500:   "IKE/IPsec",
    514:   "Syslog",
    587:   "SMTP submission",
    631:   "IPP (printing)",
    636:   "LDAPS",
    873:   "rsync",
    993:   "IMAPS",
    995:   "POP3S",
    1080:  "SOCKS proxy",
    1194:  "OpenVPN",
    1433:  "MS SQL Server",
    1521:  "Oracle DB",
    1723:  "PPTP VPN",
    2049:  "NFS",
    2375:  "Docker daemon",
    2376:  "Docker TLS",
    3000:  "Dev web server",
    3306:  "MySQL/MariaDB",
    3389:  "RDP",
    4369:  "Erlang Port Mapper",
    5000:  "Dev web server",
    5432:  "PostgreSQL",
    5672:  "RabbitMQ AMQP",
    5900:  "VNC",
    5985:  "WinRM HTTP",
    5986:  "WinRM HTTPS",
    6379:  "Redis",
    6443:  "Kubernetes API",
    8080:  "HTTP alt",
    8443:  "HTTPS alt",
    8888:  "Jupyter Notebook",
    9000:  "SonarQube / PHP-FPM",
    9090:  "Prometheus",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch cluster",
    10250: "Kubernetes kubelet",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB shard",
    50070: "Hadoop NameNode",
}

# Risk data: port → (level, label, explanation, remediation)
RISK_DB: dict[int, tuple[str, str, str, str]] = {
    21: (
        "HIGH",
        "Unencrypted FTP",
        "FTP transmits credentials and data in plaintext, trivially interceptable on "
        "the same network segment.",
        "Replace FTP with SFTP (port 22) or FTPS. If FTP must be kept, restrict "
        "to specific source IPs via firewall.",
    ),
    23: (
        "HIGH",
        "Telnet (unencrypted remote shell)",
        "Telnet sends all traffic including passwords in cleartext. It should not "
        "exist on any production or corporate network.",
        "Disable the Telnet service and replace it with SSH.",
    ),
    69: (
        "MEDIUM",
        "TFTP (unauthenticated file transfer)",
        "TFTP has no authentication. An open listener may allow anyone to read "
        "or write files.",
        "Restrict TFTP to trusted subnets or disable if unused.",
    ),
    111: (
        "MEDIUM",
        "RPC portmapper",
        "Exposes a map of all registered RPC services, potentially aiding "
        "reconnaissance.",
        "Block port 111 at the perimeter firewall unless NFS/NIS is required.",
    ),
    135: (
        "MEDIUM",
        "MS-RPC endpoint mapper",
        "Used by many Windows services. Historically a vector for worm propagation "
        "(e.g. Blaster). Should not be Internet-facing.",
        "Block at the network perimeter. Restrict internally where possible.",
    ),
    139: (
        "MEDIUM",
        "NetBIOS session service",
        "Legacy Windows file sharing. Can leak hostnames and share information "
        "to unauthenticated requestors.",
        "Disable NetBIOS over TCP/IP where SMBv2/v3 (port 445) is sufficient.",
    ),
    161: (
        "MEDIUM",
        "SNMP",
        "SNMPv1/v2c use community strings sent in plaintext, often left at "
        "defaults ('public'/'private').",
        "Upgrade to SNMPv3 with authentication and encryption, or disable SNMP "
        "if not required. Restrict to management VLANs.",
    ),
    445: (
        "HIGH",
        "SMB/CIFS (Windows file sharing)",
        "SMB has been the target of high-impact exploits (EternalBlue / WannaCry). "
        "An open SMB port warrants immediate attention.",
        "Block SMB at the perimeter. Ensure the host is fully patched. "
        "Disable SMBv1 on all systems.",
    ),
    873: (
        "MEDIUM",
        "rsync (unauthenticated possible)",
        "An open rsync daemon may allow anonymous read/write access to filesystem "
        "paths if not configured with secrets.",
        "Require rsync secrets-file authentication. Restrict via IP ACL.",
    ),
    1080: (
        "MEDIUM",
        "SOCKS proxy",
        "An open SOCKS proxy can be abused for traffic pivoting and anonymization.",
        "Restrict to authorised clients via firewall or remove if unused.",
    ),
    2049: (
        "MEDIUM",
        "NFS",
        "Misconfigured NFS exports can allow unauthenticated file access.",
        "Restrict NFS exports to specific trusted hosts. Block port 2049 at "
        "the network perimeter.",
    ),
    2375: (
        "HIGH",
        "Docker daemon (unauthenticated)",
        "An unauthenticated Docker API grants root-equivalent control of the host. "
        "This is a critical misconfiguration.",
        "Never expose Docker socket without TLS client auth. Use port 2376 with "
        "certificates, or a Unix socket only.",
    ),
    3306: (
        "MEDIUM",
        "MySQL/MariaDB",
        "Database ports should not be reachable from untrusted networks.",
        "Bind the database to localhost or a management interface. Use firewall "
        "rules to restrict access.",
    ),
    3389: (
        "HIGH",
        "RDP (Remote Desktop)",
        "RDP exposed to the internet is a frequent ransomware entry point "
        "(BlueKeep, DejaBlue). Even internally it increases attack surface.",
        "Place RDP behind a VPN or jump host. Enable NLA. Restrict source IPs "
        "via firewall. Keep Windows fully patched.",
    ),
    5432: (
        "MEDIUM",
        "PostgreSQL",
        "Database ports should not be reachable from untrusted networks.",
        "Restrict pg_hba.conf and add firewall rules to limit source IPs.",
    ),
    5900: (
        "HIGH",
        "VNC (remote desktop)",
        "VNC often lacks strong authentication and may transmit data without "
        "encryption.",
        "Tunnel VNC through SSH or a VPN. Disable if unused. Apply strong "
        "password and IP restrictions.",
    ),
    5985: (
        "MEDIUM",
        "WinRM over HTTP",
        "Windows Remote Management over HTTP uses NTLM (potentially "
        "downgradeable).",
        "Use WinRM over HTTPS (port 5986) with a valid certificate.",
    ),
    6379: (
        "HIGH",
        "Redis (no auth by default)",
        "Redis historically shipped with no authentication and binds to all "
        "interfaces. An open Redis port can expose all stored data and allow "
        "arbitrary file writes.",
        "Bind Redis to localhost. Set a strong requirepass. Block port 6379 "
        "at the firewall.",
    ),
    8888: (
        "MEDIUM",
        "Jupyter Notebook",
        "A publicly accessible Jupyter instance may allow arbitrary code "
        "execution on the server.",
        "Protect with a strong password/token. Do not expose to the internet.",
    ),
    9200: (
        "HIGH",
        "Elasticsearch (no auth by default)",
        "Older Elasticsearch versions have no authentication by default. "
        "An open port may expose all indexed data.",
        "Enable Elasticsearch security features. Restrict port 9200/9300 "
        "to trusted IPs via firewall.",
    ),
    11211: (
        "HIGH",
        "Memcached (no auth by default)",
        "Memcached has no built-in authentication. Also abused as a UDP "
        "amplification DDoS reflector.",
        "Bind to localhost or restrict via firewall. Disable UDP if not needed.",
    ),
    27017: (
        "HIGH",
        "MongoDB (no auth by default in older versions)",
        "Early MongoDB installations allowed unauthenticated access by default, "
        "leading to mass data breaches.",
        "Enable MongoDB authentication. Restrict port 27017 via firewall.",
    ),
}

DEFAULT_PORTS: list[int] = sorted(COMMON_PORTS.keys())


def svc_name(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")


def svc_risk(port: int) -> tuple[str, str, str, str] | None:
    """Return (level, label, explanation, remediation) or None."""
    return RISK_DB.get(port)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — Scanner (host discovery + TCP port scan)
# ═══════════════════════════════════════════════════════════════════════════

import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

MAX_HOSTS       = 1024
MAX_WORKERS     = 50
CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT  = 2.0


@dataclass
class PortResult:
    port:        int
    state:       str        # "open" | "closed" | "filtered"
    service:     str = ""
    banner:      str = ""
    risk_level:  str = ""
    risk_label:  str = ""
    explanation: str = ""
    remediation: str = ""


@dataclass
class HostResult:
    ip:        str
    hostname:  str              = ""
    alive:     bool             = False
    ports:     list[PortResult] = field(default_factory=list)
    scan_time: float            = 0.0

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def risk_summary(self) -> dict[str, int]:
        c: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for p in self.open_ports:
            if p.risk_level in c:
                c[p.risk_level] += 1
        return c


def resolve_targets(raw: str) -> list[str]:
    """Parse IP / CIDR string(s) into a flat list of IP strings."""
    targets: list[str] = []
    parts = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            if len(targets) + len(hosts) > MAX_HOSTS:
                raise ValueError(
                    f"Target range would exceed the {MAX_HOSTS}-host safety limit "
                    f"({len(targets) + len(hosts)} hosts requested). Use a smaller range."
                )
            targets.extend(str(h) for h in hosts)
        except ValueError as exc:
            msg = str(exc)
            if "does not appear" in msg or "is not a valid" in msg:
                raise ValueError(f"'{part}' is not a valid IP address or CIDR range.") from exc
            raise
    if not targets:
        raise ValueError("No valid targets provided.")
    return targets


def _ping(ip: str) -> bool:
    system = platform.system().lower()
    try:
        cmd = (
            ["ping", "-n", "1", "-w", "500", ip]
            if system == "windows"
            else ["ping", "-c", "1", "-W", "1", ip]
        )
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def _tcp_probe(ip: str) -> bool:
    for port in [22, 80, 443, 445, 3389, 8080]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(CONNECT_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _grab_banner(ip: str, port: int) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))
            s.sendall(b"\r\n")
            data = s.recv(256).decode("utf-8", errors="replace").strip()
            lines = data.splitlines()
            return lines[0][:120] if lines else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, grab_banner: bool = False) -> PortResult:
    pr = PortResult(port=port, state="closed", service=svc_name(port))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONNECT_TIMEOUT)
            err = s.connect_ex((ip, port))
        if err == 0:
            pr.state = "open"
            if grab_banner:
                pr.banner = _grab_banner(ip, port)
            risk = svc_risk(port)
            if risk:
                pr.risk_level, pr.risk_label, pr.explanation, pr.remediation = risk
    except socket.timeout:
        pr.state = "filtered"
    except Exception:
        pr.state = "closed"
    return pr


def scan_network(
    target_str:  str,
    ports:       list[int] | None = None,
    grab_banner: bool             = False,
    progress_cb: Callable[[str], None] | None = None,
    cancelled:   Callable[[], bool] | None    = None,
) -> list[HostResult]:
    """Discover live hosts then scan TCP ports.  Returns list[HostResult]."""
    ips     = resolve_targets(target_str)
    results: list[HostResult] = []
    scan_ports = ports or DEFAULT_PORTS

    def _cb(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    _cb(f"Resolved {len(ips)} target(s). Starting discovery…")

    # Phase 1 — parallel host discovery
    alive_ips: list[str] = []
    discovered: set[str] = set()

    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(ips))) as ex:
        ping_futs = {ex.submit(_ping,      ip): ip for ip in ips}
        tcp_futs  = {ex.submit(_tcp_probe, ip): ip for ip in ips}
        all_futs  = {**ping_futs, **tcp_futs}
        for fut in as_completed(all_futs):
            if cancelled and cancelled():
                _cb("Discovery cancelled.")
                return results
            ip = all_futs[fut]
            try:
                if fut.result() and ip not in discovered:
                    discovered.add(ip)
                    alive_ips.append(ip)
                    _cb(f"  ↳ {ip} is reachable.")
            except Exception:
                pass

    alive_ips.sort(key=lambda x: ipaddress.ip_address(x))
    _cb(f"Discovery: {len(alive_ips)}/{len(ips)} host(s) reachable.")

    if not alive_ips:
        _cb("No reachable hosts found. Check target range and network connectivity.")
        return results

    # Phase 2 — port scan each alive host
    for ip in alive_ips:
        if cancelled and cancelled():
            _cb("Scan cancelled by user.")
            break
        host = HostResult(ip=ip, alive=True, hostname=_rdns(ip))
        label = f"{ip} ({host.hostname})" if host.hostname else ip
        _cb(f"[{label}] Scanning {len(scan_ports)} ports…")
        t0 = time.monotonic()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(scan_port, ip, p, grab_banner): p for p in scan_ports}
            done = 0
            for fut in as_completed(futs):
                if cancelled and cancelled():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    pr = fut.result()
                    if pr.state == "open":
                        host.ports.append(pr)
                except Exception:
                    pass
                done += 1
                if done % 30 == 0 or done == len(scan_ports):
                    pct = int(done / len(scan_ports) * 100)
                    _cb(f"[{label}] {pct}% ({done}/{len(scan_ports)} ports)…")

        host.ports.sort(key=lambda p: p.port)
        host.scan_time = time.monotonic() - t0
        results.append(host)
        _cb(f"[{label}] ✓ {len(host.open_ports)} open port(s) in {host.scan_time:.1f}s.")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — Traffic Analyzer (Scapy, optional)
# ═══════════════════════════════════════════════════════════════════════════

from collections import Counter

try:
    from scapy.all import (          # type: ignore[import]
        AsyncSniffer, IP, TCP, UDP, ICMP, ARP, DNS, rdpcap,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class TrafficSummary:
    source:            str             = ""
    duration_seconds:  float           = 0.0
    total_packets:     int             = 0
    total_bytes:       int             = 0
    protocol_counts:   dict[str, int]  = field(default_factory=dict)
    top_sources:       list            = field(default_factory=list)
    top_destinations:  list            = field(default_factory=list)
    top_ports:         list            = field(default_factory=list)
    observations:      list[str]       = field(default_factory=list)
    error:             str             = ""

    @property
    def success(self) -> bool:
        return not self.error


def _proto_label(pkt) -> str:
    # Guard against Scapy symbols being undefined (no-scapy path never calls this,
    # but the function must parse without NameError at definition time if scapy missing)
    try:
        if pkt.haslayer(ARP):  return "ARP"   # type: ignore[name-defined]
        if pkt.haslayer(ICMP): return "ICMP"  # type: ignore[name-defined]
        if pkt.haslayer(DNS):  return "DNS"   # type: ignore[name-defined]
        if pkt.haslayer(TCP):  return "TCP"   # type: ignore[name-defined]
        if pkt.haslayer(UDP):  return "UDP"   # type: ignore[name-defined]
        if pkt.haslayer(IP):   return "IP (other)"  # type: ignore[name-defined]
    except Exception:
        pass
    return "Other"


def _analyse_packets(packets, source: str, duration: float) -> TrafficSummary:
    s = TrafficSummary(source=source, duration_seconds=duration,
                       total_packets=len(packets))
    proto_c: Counter[str] = Counter()
    src_c:   Counter[str] = Counter()
    dst_c:   Counter[str] = Counter()
    port_c:  Counter[int] = Counter()
    total_b  = 0

    for pkt in packets:
        total_b += len(pkt)
        proto_c[_proto_label(pkt)] += 1
        if pkt.haslayer(IP):
            src_c[pkt[IP].src] += 1
            dst_c[pkt[IP].dst] += 1
        if pkt.haslayer(TCP):
            port_c[pkt[TCP].dport] += 1
        elif pkt.haslayer(UDP):
            port_c[pkt[UDP].dport] += 1

    s.total_bytes      = total_b
    s.protocol_counts  = dict(proto_c.most_common())
    s.top_sources      = src_c.most_common(10)
    s.top_destinations = dst_c.most_common(10)
    s.top_ports        = port_c.most_common(10)

    obs: list[str] = []
    if not packets:
        obs.append("No packets captured.")
    else:
        pps = len(packets) / max(duration, 0.001)
        obs.append(f"Captured {len(packets):,} packets ({total_b/1024:.1f} KB) "
                   f"in {duration:.1f}s — avg {pps:.1f} pkt/s.")
    bcast = sum(v for k, v in dst_c.items()
                if k in ("255.255.255.255", "224.0.0.1", "224.0.0.251"))
    if bcast > 50:
        obs.append(f"High broadcast/multicast traffic ({bcast} pkts).")
    arp_n = proto_c.get("ARP", 0)
    if len(packets) and arp_n / len(packets) > 0.3:
        obs.append(f"High ARP ratio ({arp_n}/{len(packets)}) — possible ARP scan.")
    if proto_c.get("DNS", 0):
        obs.append(f"{proto_c['DNS']} DNS packet(s) observed.")
    if s.top_sources:
        obs.append(f"Top source: {s.top_sources[0][0]} ({s.top_sources[0][1]} pkts).")
    s.observations = obs
    return s


def analyse_pcap(path: str) -> TrafficSummary:
    if not SCAPY_AVAILABLE:
        return TrafficSummary(source=path,
                              error="Scapy not installed.  Run: pip install scapy")
    import os
    if not os.path.isfile(path):
        return TrafficSummary(source=path, error=f"File not found: {path}")
    try:
        t0 = time.monotonic()
        pkts = rdpcap(path)
        return _analyse_packets(pkts, path, time.monotonic() - t0)
    except Exception as exc:
        return TrafficSummary(source=path, error=f"Failed to read pcap: {exc}")


def capture_live(
    interface:   str,
    duration_s:  int = 30,
    pkt_limit:   int = 5000,
    progress_cb: Callable[[str], None] | None = None,
    cancelled:   Callable[[], bool] | None    = None,
) -> TrafficSummary:
    if not SCAPY_AVAILABLE:
        return TrafficSummary(source=interface,
                              error="Scapy not installed.  Run: pip install scapy")
    duration_s = min(max(1, duration_s), 300)
    pkt_limit  = min(max(1, pkt_limit), 50_000)

    def _cb(m: str) -> None:
        if progress_cb: progress_cb(m)

    _cb(f"Starting live capture on '{interface}' (max {duration_s}s / {pkt_limit} pkts)…")
    try:
        sniffer = AsyncSniffer(iface=interface, count=pkt_limit,
                               timeout=duration_s, store=True)
        t0 = time.monotonic()
        sniffer.start()
        while sniffer.running:
            time.sleep(0.5)
            n = len(sniffer.results) if sniffer.results else 0
            _cb(f"Capturing… {time.monotonic()-t0:.0f}s / {n} pkts…")
            if cancelled and cancelled():
                sniffer.stop()
                break
        sniffer.join()
        pkts     = list(sniffer.results) if sniffer.results else []
        duration = time.monotonic() - t0
    except PermissionError:
        return TrafficSummary(
            source=interface,
            error=(
                "Permission denied. Live capture requires elevated privileges.\n"
                "  Windows: Run as Administrator.\n"
                "  Linux:   sudo python3 cyber_net_analyzer.py"
            ),
        )
    except Exception as exc:
        return TrafficSummary(source=interface, error=f"Capture error: {exc}")

    _cb(f"Capture complete — {len(pkts)} packets.  Analysing…")
    return _analyse_packets(pkts, interface, duration)


def get_interfaces() -> list[str]:
    if not SCAPY_AVAILABLE:
        return []
    try:
        from scapy.arch import get_if_list  # type: ignore[import]
        return get_if_list()
    except Exception:
        return []


def format_traffic_summary(s: TrafficSummary) -> str:
    if not s.success:
        return f"[ERROR] {s.error}"
    lines = [
        "=" * 60, "NETWORK TRAFFIC ANALYSIS", "=" * 60,
        f"Source        : {s.source}",
        f"Duration      : {s.duration_seconds:.1f}s",
        f"Total packets : {s.total_packets:,}",
        f"Total bytes   : {s.total_bytes / 1024:.1f} KB",
        "", "--- Protocol Breakdown ---",
    ]
    for proto, cnt in sorted(s.protocol_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {proto:<15} {cnt:>6} packets")
    lines += ["", "--- Top Source IPs ---"]
    for ip, cnt in s.top_sources[:10]:
        lines.append(f"  {ip:<18} {cnt:>6} packets")
    lines += ["", "--- Top Destination IPs ---"]
    for ip, cnt in s.top_destinations[:10]:
        lines.append(f"  {ip:<18} {cnt:>6} packets")
    lines += ["", "--- Top Destination Ports ---"]
    for port, cnt in s.top_ports[:10]:
        lines.append(f"  {port:<6} {svc_name(port):<18} {cnt:>6} packets")
    lines += ["", "--- Observations ---"]
    for obs in s.observations:
        lines.append(f"  • {obs}")
    lines.append("=" * 60)
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — Reporter (CSV + text)
# ═══════════════════════════════════════════════════════════════════════════

import csv
import datetime
import os


def _ts() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def export_csv(hosts: list[HostResult], directory: str = ".", filename: str = "") -> str:
    if not filename:
        filename = f"scan_results_{_ts()}.csv"
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    fields = ["ip", "hostname", "port", "service", "banner",
              "risk_level", "risk_label", "explanation", "remediation"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for host in hosts:
            for p in host.open_ports:
                w.writerow({
                    "ip": host.ip, "hostname": host.hostname,
                    "port": p.port, "service": p.service, "banner": p.banner,
                    "risk_level": p.risk_level, "risk_label": p.risk_label,
                    "explanation": p.explanation, "remediation": p.remediation,
                })
    return path


def _sev(level: str) -> int:
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(level, 3)


def generate_report(
    hosts:     list[HostResult],
    target:    str,
    directory: str = ".",
    filename:  str = "",
) -> str:
    if not filename:
        filename = f"security_report_{_ts()}.txt"
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alive = [h for h in hosts if h.alive]

    lines = [
        "=" * 70,
        "  CYBERSECURITY NETWORK ANALYSIS — SECURITY REPORT",
        "=" * 70,
        f"  Generated  : {now}",
        f"  Target     : {target}",
        f"  Hosts up   : {len(alive)} / {len(hosts)}",
        f"  Open ports : {sum(len(h.open_ports) for h in alive)}",
        f"  HIGH risks : {sum(h.risk_summary['HIGH']   for h in alive)}",
        f"  MED risks  : {sum(h.risk_summary['MEDIUM'] for h in alive)}",
        "",
        "  DISCLAIMER: Risk flags are based solely on observed open ports.",
        "  They do NOT confirm exploitation. Human analysis is required.",
        "=" * 70, "",
    ]

    for host in alive:
        label = host.ip + (f"  ({host.hostname})" if host.hostname else "")
        lines += [f"HOST: {label}", "-" * 60]
        if not host.open_ports:
            lines += ["  No open ports found on scanned range.", ""]
            continue
        flagged   = [p for p in host.open_ports if p.risk_level]
        unflagged = [p for p in host.open_ports if not p.risk_level]
        if flagged:
            lines.append("  ▸ Ports with security notes:")
            for p in sorted(flagged, key=lambda x: (_sev(x.risk_level), x.port)):
                icon = {"HIGH": "⚠ HIGH", "MEDIUM": "⚡ MEDIUM"}.get(p.risk_level, p.risk_level)
                lines += [
                    f"    [{icon}]  Port {p.port}/TCP — {p.service}",
                    f"      Why    : {p.explanation}",
                    f"      Action : {p.remediation}",
                    "",
                ]
        if unflagged:
            lines.append("  ▸ Other open ports (no specific risk note):")
            for p in unflagged:
                lines.append(f"    {p.port}/TCP  {p.service}"
                             + (f"  [{p.banner}]" if p.banner else ""))
            lines.append("")
        lines.append("")

    dead = [h for h in hosts if not h.alive]
    if dead:
        lines += ["UNREACHABLE HOSTS:", "-" * 40]
        for h in dead:
            lines.append(f"  {h.ip}")
        lines.append("")

    # Consolidated recommendations
    all_risks = sorted(
        [p for h in alive for p in h.open_ports if p.risk_level],
        key=lambda x: (_sev(x.risk_level), x.port),
    )
    if all_risks:
        lines += ["=" * 70, "  CONSOLIDATED RECOMMENDATIONS", "=" * 70, ""]
        seen: set[int] = set()
        for p in all_risks:
            if p.port in seen:
                continue
            seen.add(p.port)
            icon = {"HIGH": "⚠ HIGH", "MEDIUM": "⚡ MEDIUM"}.get(p.risk_level, p.risk_level)
            lines += [f"  [{icon}]  Port {p.port} — {p.service}", f"    {p.remediation}", ""]

    lines += ["=" * 70, "  END OF REPORT", "=" * 70]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def save_all_reports(
    hosts:     list[HostResult],
    target:    str,
    directory: str = "reports",
    traffic:   TrafficSummary | None = None,
) -> dict[str, str]:
    paths = {
        "csv":    export_csv(hosts, directory),
        "report": generate_report(hosts, target, directory),
    }
    if traffic and traffic.success:
        tf = os.path.join(directory, f"traffic_report_{_ts()}.txt")
        os.makedirs(directory, exist_ok=True)
        with open(tf, "w", encoding="utf-8") as fh:
            fh.write(format_traffic_summary(traffic) + "\n")
        paths["traffic"] = tf
    return paths


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — Tkinter GUI
# ═══════════════════════════════════════════════════════════════════════════

import sys
import threading
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox, scrolledtext
from typing import Optional

_HERE = os.path.dirname(os.path.abspath(__file__))

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 — Sample / Demo Data
# ═══════════════════════════════════════════════════════════════════════════
#
# A realistic small-office LAN scenario with six hosts.
# Each host exposes a mix of HIGH / MEDIUM / LOW risk ports so that every
# threat category is demonstrated in the UI.
#
# Threat summary
# ──────────────
# 192.168.1.1  – Border router: Telnet admin interface still open (HIGH),
#                SNMP v1 community string exposed (HIGH), HTTP management
#                page without TLS (MEDIUM).
# 192.168.1.10 – File server: SMB port open on a Windows host that also
#                runs an outdated RDP listener (HIGH), plus MS-RPC (HIGH).
# 192.168.1.20 – Database server: MySQL and PostgreSQL both listening on
#                their default ports with no host firewall (HIGH).  Redis
#                and MongoDB are also exposed with no auth (HIGH).
# 192.168.1.30 – Dev workstation: Docker daemon on 2375 (unauthenticated,
#                HIGH), Jupyter Notebook on 8888 (HIGH), a dev HTTP server
#                on 3000 (MEDIUM).
# 192.168.1.40 – Internal web server: HTTP plain-text (MEDIUM) plus
#                HTTPS (LOW, healthy); Prometheus metrics endpoint
#                world-accessible on 9090 (MEDIUM).
# 192.168.1.50 – Legacy printer/IoT: FTP with anonymous access (HIGH),
#                an old Telnet management port (HIGH), and IPP printing
#                service (LOW).

def _make_port(port: int, banner: str = "") -> PortResult:
    """Build a PortResult with risk data looked up from RISK_DB."""
    risk = svc_risk(port)
    return PortResult(
        port        = port,
        state       = "open",
        service     = svc_name(port),
        banner      = banner,
        risk_level  = risk[0] if risk else "",
        risk_label  = risk[1] if risk else "",
        explanation = risk[2] if risk else "",
        remediation = risk[3] if risk else "",
    )


def _make_host(ip: str, hostname: str, ports_data: list) -> HostResult:
    """Build a HostResult that is alive with a list of open PortResults."""
    h = HostResult(ip=ip, hostname=hostname, alive=True, scan_time=0.12)
    h.ports = [_make_port(p, b) for p, b in ports_data]
    return h


SAMPLE_HOSTS: list[HostResult] = [
    _make_host("192.168.1.1",  "router.local", [
        (23,  "Cisco IOS 15.x telnetd"),       # HIGH  – Telnet
        (161, "net-snmp 5.7 (community=public)"),  # HIGH  – SNMP
        (80,  "Cisco HTTP Management/1.1"),     # MEDIUM – HTTP
        (443, "Cisco HTTPS Management/1.1"),    # LOW   – HTTPS
    ]),
    _make_host("192.168.1.10", "fileserver.local", [
        (445, "Windows Server 2012 SMB"),       # HIGH  – SMB
        (3389,"Microsoft RDP 8.0"),             # HIGH  – RDP
        (135, "Microsoft MSRPC"),               # HIGH  – MS-RPC
        (139, "NetBIOS-SSN"),                   # HIGH  – NetBIOS
        (443, "IIS/10.0 (HTTPS)"),              # LOW   – HTTPS
    ]),
    _make_host("192.168.1.20", "dbserver.local", [
        (3306, "MySQL 5.7.38 Community"),       # HIGH  – MySQL
        (5432, "PostgreSQL 13.4"),              # HIGH  – PostgreSQL
        (6379, "Redis 6.2.6 (no auth)"),        # HIGH  – Redis
        (27017,"MongoDB 4.4.6"),                # HIGH  – MongoDB
        (22,   "OpenSSH 8.4 Ubuntu"),           # MEDIUM – SSH
    ]),
    _make_host("192.168.1.30", "devbox.local", [
        (2375, "Docker Engine API/1.41 (plain HTTP)"),  # HIGH – Docker
        (8888, "Jupyter Notebook 6.4.12"),      # HIGH  – Jupyter
        (3000, "Node.js Express dev server"),   # MEDIUM – Dev web
        (22,   "OpenSSH 9.0"),                  # MEDIUM – SSH
        (5432, "PostgreSQL 14 (dev instance)"), # HIGH  – PostgreSQL
    ]),
    _make_host("192.168.1.40", "webserver.local", [
        (80,   "nginx/1.24 HTTP"),              # MEDIUM – HTTP
        (443,  "nginx/1.24 HTTPS"),             # LOW    – HTTPS
        (8080, "Tomcat/9.0 HTTP alt"),          # MEDIUM – HTTP alt
        (9090, "Prometheus/2.45 metrics"),      # MEDIUM – Prometheus
        (9200, "Elasticsearch 8.6.0"),          # HIGH   – Elasticsearch
    ]),
    _make_host("192.168.1.50", "printer-iot.local", [
        (21,   "ftpd 2.0.10 (anonymous login enabled)"),  # HIGH – FTP
        (23,   "BusyBox telnetd"),              # HIGH  – Telnet
        (631,  "CUPS 2.3 IPP"),                 # LOW   – IPP
        (80,   "Embedded HTTP admin"),          # MEDIUM – HTTP
        (161,  "AgentX SNMP v1"),               # HIGH  – SNMP
    ]),
]

# ── Colour palette ────────────────────────────────────────────────────────
BG       = "#1e1e2e"
BG2      = "#2a2a3e"
ACCENT   = "#7c3aed"
ACCENT2  = "#6d28d9"
FG       = "#e2e8f0"
FG_MUTED = "#94a3b8"
GREEN    = "#16a34a"
YELLOW   = "#f59e0b"
RED      = "#ef4444"
BLUE     = "#3b82f6"
BORDER   = "#3f3f5f"

FONT_BODY   = ("Segoe UI", 10)
FONT_BOLD   = ("Segoe UI", 10, "bold")
FONT_TITLE  = ("Segoe UI", 15, "bold")
FONT_HDR    = ("Segoe UI", 11, "bold")
FONT_MONO   = ("Consolas", 9)


# ── Small widget helpers ──────────────────────────────────────────────────
def _lbl(parent, text, **kw) -> tk.Label:
    kw.setdefault("bg", BG2); kw.setdefault("fg", FG); kw.setdefault("font", FONT_BODY)
    return tk.Label(parent, text=text, **kw)

def _btn(parent, text, cmd, color=ACCENT, **kw) -> tk.Button:
    return tk.Button(parent, text=text, command=cmd, bg=color, fg="white",
                     activebackground=ACCENT2, activeforeground="white",
                     relief="flat", cursor="hand2", font=FONT_BOLD,
                     padx=14, pady=6, **kw)

def _ent(parent, textvariable=None, **kw) -> tk.Entry:
    kw.setdefault("bg", "#16213e"); kw.setdefault("fg", FG)
    kw.setdefault("insertbackground", FG); kw.setdefault("relief", "flat")
    kw.setdefault("font", FONT_BODY)
    return tk.Entry(parent, textvariable=textvariable, **kw)

def _frm(parent, **kw) -> tk.Frame:
    kw.setdefault("bg", BG2)
    return tk.Frame(parent, **kw)


# ── Authorization gate dialog ──────────────────────────────────────────────
class AuthDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, target: str):
        super().__init__(parent)
        self.title("⚠ Authorization Required")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.confirmed = False
        self.geometry("530x320")
        self._centre(parent)

        tk.Label(self, text="⚠  AUTHORIZATION REQUIRED",
                 font=FONT_TITLE, bg=BG, fg=YELLOW).pack(pady=(22, 6))
        msg = (
            f"You are about to scan:\n\n    {target}\n\n"
            "Scanning networks without explicit permission from the owner\n"
            "is illegal in most jurisdictions.\n\n"
            "By clicking CONFIRM you declare that you have written or\n"
            "clearly established authorization to scan this target."
        )
        tk.Label(self, text=msg, font=FONT_BODY, bg=BG, fg=FG,
                 justify="center", wraplength=460).pack(padx=24, pady=6)
        bf = _frm(self, bg=BG)
        bf.pack(pady=14)
        _btn(bf, "✓  I Have Authorization — Confirm",
             self._ok, color="#16a34a").pack(side="left", padx=8)
        _btn(bf, "✗  Cancel",
             self._cancel, color="#6b7280").pack(side="left", padx=8)

    def _centre(self, p: tk.Tk) -> None:
        self.update_idletasks()
        x = p.winfo_x() + (p.winfo_width()  - self.winfo_width())  // 2
        y = p.winfo_y() + (p.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def _ok(self)     -> None: self.confirmed = True;  self.destroy()
    def _cancel(self) -> None: self.confirmed = False; self.destroy()


# ── Main application ───────────────────────────────────────────────────────
class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("CyberNetAnalyzer — Network Security Analysis Tool")
        self.configure(bg=BG)
        self.minsize(1100, 680)
        self.geometry("1220x760")

        self._results: list[HostResult]           = []
        self._traffic: Optional[TrafficSummary]   = None
        self._scanning  = False
        self._cancel_ev = threading.Event()
        self._rdir      = os.path.join(_HERE, "reports")

        self._build_ui()
        self._log("CyberNetAnalyzer ready.  Enter a target and click ▶ Start Scan.")
        self._log(f"Scapy: {'available ✓' if SCAPY_AVAILABLE else 'NOT installed — Traffic tab disabled (pip install scapy)'}")

    # ── Build UI ─────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_header()
        main = _frm(self, bg=BG)
        main.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)
        self._build_left(main)
        self._build_right(main)

    def _build_header(self) -> None:
        hdr = _frm(self, bg=ACCENT)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔍  CyberNetAnalyzer",
                 font=FONT_TITLE, bg=ACCENT, fg="white").pack(side="left", padx=20, pady=10)
        tk.Label(hdr,
                 text="Authorized Network Security Analysis Tool  |  Educational use only",
                 font=FONT_BODY, bg=ACCENT, fg="#ddd6fe").pack(side="right", padx=20)

    def _sec_hdr(self, parent, text: str) -> None:
        tk.Label(parent, text=text, bg=BG2, fg=ACCENT,
                 font=FONT_HDR, anchor="w").pack(fill="x", padx=10, pady=(10, 2))
        _frm(parent, bg=BORDER, height=1).pack(fill="x", padx=10, pady=(0, 4))

    def _chk(self, parent, text, var, cmd=None) -> tk.Checkbutton:
        cb = tk.Checkbutton(parent, text=text, variable=var, bg=BG2, fg=FG,
                            activebackground=BG2, activeforeground=FG,
                            selectcolor="#16213e", font=FONT_BODY, command=cmd)
        cb.pack(anchor="w", pady=1)
        return cb

    # ── Left panel ───────────────────────────────────────────────────────

    def _build_left(self, parent: tk.Frame) -> None:
        left = _frm(parent, bg=BG2, width=284)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=4)
        left.pack_propagate(False)

        # Target
        self._sec_hdr(left, "🎯  Target")
        tf = _frm(left); tf.pack(fill="x", padx=10, pady=(0, 6))
        _lbl(tf, "IP / CIDR range:").pack(anchor="w")
        self._tgt_var = tk.StringVar(value="192.168.1.1")
        _ent(tf, textvariable=self._tgt_var).pack(fill="x", ipady=4)
        _lbl(tf, "e.g.  192.168.1.1  or  192.168.1.0/24",
             fg=FG_MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

        # Options
        self._sec_hdr(left, "⚙  Scan Options")
        of = _frm(left); of.pack(fill="x", padx=10, pady=(0, 6))
        self._banner_var = tk.BooleanVar(value=False)
        self._chk(of, "Grab service banners", self._banner_var)
        self._custom_var = tk.BooleanVar(value=False)
        self._chk(of, "Custom port list", self._custom_var,
                  cmd=self._toggle_ports)
        self._port_frame = _frm(of); self._port_frame.pack(fill="x")
        _lbl(self._port_frame, "Ports (comma-sep):",
             fg=FG_MUTED, font=("Segoe UI", 8)).pack(anchor="w")
        self._ports_var = tk.StringVar(value="22,80,443,445,3389,3306")
        self._port_ent = _ent(self._port_frame, textvariable=self._ports_var)
        self._port_ent.pack(fill="x", ipady=3)
        self._port_frame.pack_forget()

        # Controls
        self._sec_hdr(left, "▶  Controls")
        cf = _frm(left); cf.pack(fill="x", padx=10, pady=(0, 6))
        self._start_btn  = _btn(cf, "▶  Start Scan",    self._start,  color=GREEN)
        self._cancel_btn = _btn(cf, "■  Cancel Scan",   self._cancel, color="#6b7280")
        self._export_btn = _btn(cf, "💾  Export Reports", self._export, color=BLUE)
        self._sample_btn = _btn(cf, "🧪  Load Sample Data", self._load_sample,
                                color="#0e7490")
        for b in (self._start_btn, self._cancel_btn, self._export_btn,
                  self._sample_btn):
            b.pack(fill="x", pady=3)
        self._cancel_btn.configure(state="disabled")
        self._export_btn.configure(state="disabled")

        # Progress
        self._sec_hdr(left, "📊  Progress")
        pf = _frm(left); pf.pack(fill="x", padx=10, pady=(0, 6))
        self._prog = ttk.Progressbar(pf, mode="indeterminate")
        self._prog.pack(fill="x", pady=4)
        self._stat_var = tk.StringVar(value="Idle")
        tk.Label(pf, textvariable=self._stat_var, bg=BG2, fg=FG_MUTED,
                 font=("Segoe UI", 8), wraplength=240, justify="left").pack(anchor="w")

        # Log
        self._sec_hdr(left, "📋  Activity Log")
        lf = _frm(left); lf.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._log_box = scrolledtext.ScrolledText(
            lf, bg="#0f0f1a", fg=FG_MUTED, font=FONT_MONO,
            relief="flat", height=8, state="disabled", wrap="word")
        self._log_box.pack(fill="both", expand=True)

    # ── Right panel ───────────────────────────────────────────────────────

    def _build_right(self, parent: tk.Frame) -> None:
        right = _frm(parent, bg=BG)
        right.grid(row=0, column=1, sticky="nsew", pady=4)
        right.rowconfigure(0, weight=1); right.columnconfigure(0, weight=1)

        sty = ttk.Style()
        sty.theme_use("default")
        sty.configure("TNotebook",      background=BG)
        sty.configure("TNotebook.Tab",  background=BG2, foreground=FG_MUTED,
                      padding=[12, 6],  font=FONT_BODY)
        sty.map("TNotebook.Tab",
                background=[("selected", BG)],
                foreground=[("selected", FG)])

        self._nb = ttk.Notebook(right)
        self._nb.grid(row=0, column=0, sticky="nsew")
        self._build_scan_tab()
        self._build_report_tab()
        self._build_traffic_tab()
        self._build_about_tab()

    # ── Scan Results tab ──────────────────────────────────────────────────

    def _build_scan_tab(self) -> None:
        tab = _frm(self._nb, bg=BG)
        self._nb.add(tab, text="  🔍 Scan Results  ")
        tab.rowconfigure(1, weight=1); tab.columnconfigure(0, weight=1)

        sf = _frm(tab); sf.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        self._sum_var = tk.StringVar(value="No scan run yet.")
        tk.Label(sf, textvariable=self._sum_var, bg=BG2, fg=FG,
                 font=FONT_BOLD, anchor="w", padx=10, pady=6).pack(fill="x")

        cols = ("ip", "hostname", "port", "service", "risk", "banner")
        tf = _frm(tab); tf.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
        tf.rowconfigure(0, weight=1); tf.columnconfigure(0, weight=1)

        sty = ttk.Style()
        sty.configure("Treeview",
                      background="#16213e", fieldbackground="#16213e",
                      foreground=FG, rowheight=22, font=FONT_BODY)
        sty.configure("Treeview.Heading",
                      background=BG2, foreground=ACCENT, font=FONT_BOLD)
        sty.map("Treeview", background=[("selected", ACCENT)])

        self._tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  selectmode="browse")
        for col, head, w in [
            ("ip",       "IP Address",  110),
            ("hostname", "Hostname",    140),
            ("port",     "Port",         60),
            ("service",  "Service",     130),
            ("risk",     "Risk",         90),
            ("banner",   "Banner",      300),
        ]:
            self._tree.heading(col, text=head)
            self._tree.column(col, width=w, minwidth=40)

        self._tree.tag_configure("HIGH",   foreground=RED)
        self._tree.tag_configure("MEDIUM", foreground=YELLOW)
        self._tree.tag_configure("LOW",    foreground=BLUE)
        self._tree.tag_configure("none",   foreground=FG)

        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        dp = _frm(tab); dp.grid(row=2, column=0, sticky="ew", padx=8, pady=4)
        _lbl(dp, "Selected port detail:", fg=FG_MUTED,
             font=("Segoe UI", 8)).pack(anchor="w", padx=4)
        self._detail = scrolledtext.ScrolledText(
            dp, bg="#0f0f1a", fg=FG, font=FONT_MONO,
            height=5, relief="flat", state="disabled")
        self._detail.pack(fill="x", padx=4)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

    # ── Security Report tab ────────────────────────────────────────────────

    def _build_report_tab(self) -> None:
        tab = _frm(self._nb, bg=BG)
        self._nb.add(tab, text="  📄 Security Report  ")
        tab.rowconfigure(0, weight=1); tab.columnconfigure(0, weight=1)
        self._report_box = scrolledtext.ScrolledText(
            tab, bg="#0f0f1a", fg=FG, font=FONT_MONO,
            relief="flat", state="disabled", wrap="none")
        self._report_box.pack(fill="both", expand=True, padx=8, pady=8)
        self._set_report("Run a scan to generate the security report.")

    # ── Traffic Analysis tab ───────────────────────────────────────────────

    def _build_traffic_tab(self) -> None:
        tab = _frm(self._nb, bg=BG)
        self._nb.add(tab, text="  📡 Traffic Analysis  ")
        tab.rowconfigure(2, weight=1); tab.columnconfigure(0, weight=1)

        col = GREEN if SCAPY_AVAILABLE else YELLOW
        msg = ("Scapy ✓ available — live capture and pcap analysis enabled."
               if SCAPY_AVAILABLE else
               "Scapy not installed.  pip install scapy  "
               "(Windows also needs Npcap: https://npcap.com)")
        tk.Label(tab, text=msg, bg=BG2, fg=col, font=FONT_BODY,
                 justify="left", wraplength=800, padx=10,
                 pady=8).grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))

        ctrl = _frm(tab); ctrl.grid(row=1, column=0, sticky="ew", padx=8, pady=4)

        # pcap row
        pr = _frm(ctrl); pr.pack(fill="x", pady=2)
        _lbl(pr, "Pcap file:").pack(side="left", padx=(0, 4))
        self._pcap_var = tk.StringVar()
        _ent(pr, textvariable=self._pcap_var, width=48).pack(side="left", padx=2)
        _btn(pr, "Browse…", self._browse_pcap,  color="#334155").pack(side="left", padx=4)
        _btn(pr, "Analyse File", self._do_pcap,  color=BLUE).pack(side="left", padx=4)

        # live capture row
        lr = _frm(ctrl); lr.pack(fill="x", pady=2)
        _lbl(lr, "Interface:").pack(side="left", padx=(0, 4))
        self._iface_var = tk.StringVar()
        ifaces = get_interfaces() or ["(none found)"]
        self._iface_var.set(ifaces[0])
        om = tk.OptionMenu(lr, self._iface_var, *ifaces)
        om.configure(bg=BG2, fg=FG, activebackground=ACCENT,
                     activeforeground="white", relief="flat",
                     font=FONT_BODY, highlightthickness=0)
        om["menu"].configure(bg=BG2, fg=FG)
        om.pack(side="left", padx=2)
        _lbl(lr, "Duration (s):").pack(side="left", padx=(10, 4))
        self._dur_var = tk.StringVar(value="30")
        _ent(lr, textvariable=self._dur_var, width=6).pack(side="left", padx=2)
        self._live_btn = _btn(lr, "▶ Start Live Capture",
                              self._do_live, color=GREEN)
        self._live_btn.pack(side="left", padx=8)
        self._stop_btn = _btn(lr, "■ Stop", self._stop_live, color="#6b7280")
        self._stop_btn.pack(side="left")
        self._stop_btn.configure(state="disabled")

        self._traffic_box = scrolledtext.ScrolledText(
            tab, bg="#0f0f1a", fg=FG, font=FONT_MONO,
            relief="flat", state="disabled", wrap="none")
        self._traffic_box.grid(row=2, column=0, sticky="nsew", padx=8, pady=(4, 8))
        self._set_traffic("Analyse a pcap file or start a live capture.\n"
                          "(Live capture requires Administrator / root privileges.)")

    # ── About tab ─────────────────────────────────────────────────────────

    def _build_about_tab(self) -> None:
        tab = _frm(self._nb, bg=BG)
        self._nb.add(tab, text="  ℹ About  ")
        about = (
            "CyberNetAnalyzer  —  v1.0\n"
            "─" * 74 + "\n\n"
            "PURPOSE\n"
            "  Authorized network security analysis and education tool.\n"
            "  Use only on networks you own or have explicit permission to scan.\n\n"
            "FEATURES\n"
            "  • Network host discovery (ICMP ping + TCP probe fallback)\n"
            "  • TCP port scanning with concurrent execution (50 threads)\n"
            "  • Service identification for 65+ well-known ports\n"
            "  • Security risk assessment with remediation guidance\n"
            "  • Optional service banner grabbing\n"
            "  • Scapy-powered packet capture and pcap file analysis\n"
            "  • CSV and plain-text report export\n\n"
            "LEGAL NOTICE\n"
            "  Scanning a network without authorisation is illegal in most\n"
            "  countries. The tool includes an authorization confirmation step\n"
            "  and enforces a 1 024-host scan limit per session.\n\n"
            "DEPENDENCIES\n"
            "  Required : Python 3.10+  (all stdlib)\n"
            "  Optional : scapy>=2.5.0  →  pip install scapy\n"
            "             Windows live capture also needs Npcap: https://npcap.com\n\n"
            "SECURITY DESIGN\n"
            "  • No stealth techniques — standard TCP connect only\n"
            "  • No exploitation or credential theft\n"
            "  • Risk labels are advisory, not confirmed vulnerabilities\n"
            "  • 1-second connect timeout, 50-thread concurrency cap\n"
            "─" * 74
        )
        txt = scrolledtext.ScrolledText(
            tab, bg="#0f0f1a", fg=FG, font=FONT_MONO, relief="flat", state="normal")
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", about)
        txt.configure(state="disabled")

    # ── Event handlers ────────────────────────────────────────────────────

    def _toggle_ports(self) -> None:
        if self._custom_var.get():
            self._port_frame.pack(fill="x")
        else:
            self._port_frame.pack_forget()

    def _load_sample(self) -> None:
        """Populate the UI with built-in sample data to demonstrate threat highlighting."""
        if self._scanning:
            return
        self._log("Loading sample data — 6-host small-office LAN threat scenario…")
        self._tgt_var.set("192.168.1.0/24  [SAMPLE]")
        self._clear_tree()
        self._set_report("Loading sample data…")
        self._sum_var.set("Loading sample data…")
        # Re-use the same _scan_done path so summary, tree, and report are
        # all populated with colour-coded threat highlighting.
        self._scan_done(list(SAMPLE_HOSTS))
        self._log(
            "Sample data loaded.  RED = HIGH risk  ·  YELLOW = MEDIUM  ·  BLUE = LOW.\n"
            "Scroll through the Scan Results tab and click any row for threat detail."
        )

    def _start(self) -> None:
        if self._scanning:
            return
        target = self._tgt_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or CIDR range.")
            return
        try:
            ips = resolve_targets(target)
        except ValueError as exc:
            messagebox.showerror("Invalid Target", str(exc))
            return

        dlg = AuthDialog(self, target)
        self.wait_window(dlg)
        if not dlg.confirmed:
            self._log("Scan cancelled — authorization not confirmed.")
            return

        ports = None
        if self._custom_var.get():
            raw = self._ports_var.get().strip()
            try:
                ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
                if not ports:
                    raise ValueError("Empty port list.")
                bad = [p for p in ports if not (1 <= p <= 65535)]
                if bad:
                    raise ValueError(f"Invalid port number(s): {bad}")
            except ValueError as exc:
                messagebox.showerror("Invalid Ports", str(exc))
                return

        grab = self._banner_var.get()
        self._scanning = True
        self._cancel_ev.clear()
        self._start_btn.configure(state="disabled")
        self._cancel_btn.configure(state="normal")
        self._export_btn.configure(state="disabled")
        self._prog.start(12)
        self._clear_tree()
        self._set_report("Scanning… please wait.")
        self._sum_var.set(f"Scanning {target} ({len(ips)} host(s))…")
        self._log(f"Scan started: {target} — {len(ips)} host(s), "
                  f"{'custom ports' if ports else 'default port list'}.")
        threading.Thread(target=self._run_scan, args=(target, ports, grab),
                         daemon=True).start()

    def _cancel(self) -> None:
        if self._scanning:
            self._cancel_ev.set()
            self._log("Cancellation requested…")

    def _export(self) -> None:
        if not self._results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        directory = filedialog.askdirectory(title="Choose output directory",
                                            initialdir=self._rdir)
        if not directory:
            return
        try:
            paths = save_all_reports(
                hosts=self._results,
                target=self._tgt_var.get().strip(),
                directory=directory,
                traffic=self._traffic,
            )
            self._rdir = directory
            msg = "Reports saved:\n\n" + "\n".join(
                f"  {k.upper()}: {os.path.basename(v)}" for k, v in paths.items()
            )
            messagebox.showinfo("Export complete", msg)
            self._log(f"Reports exported → {directory}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def _on_select(self, _=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], "values")
        if not vals:
            return
        ip, hostname, port, service, risk, banner = vals
        host = next((h for h in self._results if h.ip == ip), None)
        if not host:
            return
        pr = next((p for p in host.open_ports if str(p.port) == port), None)
        if not pr:
            return
        lines = [
            f"Host     : {ip}" + (f"  ({hostname})" if hostname and hostname != "—" else ""),
            f"Port     : {pr.port}/TCP",
            f"Service  : {pr.service}",
        ]
        if pr.banner:
            lines.append(f"Banner   : {pr.banner}")
        if pr.risk_level:
            lines += [
                f"Risk     : {pr.risk_level}  —  {pr.risk_label}",
                f"Why      : {pr.explanation}",
                f"Action   : {pr.remediation}",
            ]
        else:
            lines.append("Risk     : No specific risk note for this port.")
        self._detail.configure(state="normal")
        self._detail.delete("1.0", "end")
        self._detail.insert("1.0", "\n".join(lines))
        self._detail.configure(state="disabled")

    # ── Traffic handlers ──────────────────────────────────────────────────

    def _browse_pcap(self) -> None:
        p = filedialog.askopenfilename(
            title="Open pcap file",
            filetypes=[("Pcap files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if p:
            self._pcap_var.set(p)

    def _do_pcap(self) -> None:
        path = self._pcap_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Please select a pcap file first.")
            return
        self._set_traffic("Analysing pcap file…")
        threading.Thread(target=self._run_pcap, args=(path,), daemon=True).start()

    def _run_pcap(self, path: str) -> None:
        result = analyse_pcap(path)
        self._traffic = result
        text = format_traffic_summary(result)
        self.after(0, lambda: self._set_traffic(text))
        self.after(0, lambda: self._log(f"Pcap analysis done: {path}"))

    def _do_live(self) -> None:
        if not SCAPY_AVAILABLE:
            messagebox.showerror(
                "Scapy not installed",
                "Live capture requires Scapy.\n\n"
                "  pip install scapy\n\n"
                "Windows also needs Npcap: https://npcap.com")
            return
        try:
            dur = int(self._dur_var.get())
            if not (1 <= dur <= 300):
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Duration must be 1–300 seconds.")
            return
        iface = self._iface_var.get()
        self._cancel_ev.clear()
        self._live_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._set_traffic(f"Starting live capture on '{iface}'…")
        threading.Thread(target=self._run_live, args=(iface, dur), daemon=True).start()

    def _run_live(self, iface: str, dur: int) -> None:
        def _cb(m: str):
            self.after(0, lambda msg=m: self._log(msg))
        result = capture_live(iface, duration_s=dur,
                              progress_cb=_cb, cancelled=self._cancel_ev.is_set)
        self._traffic = result
        text = format_traffic_summary(result)
        self.after(0, lambda: self._set_traffic(text))
        self.after(0, lambda: self._live_btn.configure(state="normal"))
        self.after(0, lambda: self._stop_btn.configure(state="disabled"))

    def _stop_live(self) -> None:
        self._cancel_ev.set()

    # ── Scan worker ───────────────────────────────────────────────────────

    def _run_scan(self, target: str, ports, grab: bool) -> None:
        try:
            results = scan_network(
                target_str=target, ports=ports, grab_banner=grab,
                progress_cb=lambda m: self.after(0, lambda msg=m: self._log(msg)),
                cancelled=self._cancel_ev.is_set,
            )
            self.after(0, lambda r=results: self._scan_done(r))
        except Exception as exc:
            self.after(0, lambda e=exc: self._scan_error(str(e)))

    def _scan_done(self, results: list[HostResult]) -> None:
        self._scanning = False
        self._prog.stop()
        self._start_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._results = results
        alive = [h for h in results if h.alive]
        tot   = sum(len(h.open_ports) for h in alive)
        high  = sum(h.risk_summary["HIGH"]   for h in alive)
        med   = sum(h.risk_summary["MEDIUM"] for h in alive)
        summ  = (f"✓ Scan complete  ·  {len(alive)}/{len(results)} host(s) up  ·  "
                 f"{tot} open port(s)  ·  {high} HIGH  ·  {med} MEDIUM risk")
        self._sum_var.set(summ)
        self._log(summ)
        self._populate_tree(results)
        self._build_report(results)
        if alive:
            self._export_btn.configure(state="normal")
            self._nb.select(0)

    def _scan_error(self, msg: str) -> None:
        self._scanning = False
        self._prog.stop()
        self._start_btn.configure(state="normal")
        self._cancel_btn.configure(state="disabled")
        self._log(f"ERROR: {msg}")
        messagebox.showerror("Scan Error", msg)

    # ── Tree & report helpers ─────────────────────────────────────────────

    def _clear_tree(self) -> None:
        for i in self._tree.get_children():
            self._tree.delete(i)

    def _populate_tree(self, hosts: list[HostResult]) -> None:
        self._clear_tree()
        for h in hosts:
            if not h.alive:
                continue
            for p in h.open_ports:
                risk_txt = p.risk_level if p.risk_level else "—"
                tag      = p.risk_level if p.risk_level else "none"
                self._tree.insert("", "end", tags=(tag,), values=(
                    h.ip, h.hostname or "—", p.port,
                    p.service, risk_txt, p.banner or "—",
                ))

    def _build_report(self, hosts: list[HostResult]) -> None:
        target = self._tgt_var.get().strip()
        alive  = [h for h in hosts if h.alive]
        now    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines  = [
            "=" * 70,
            "  CYBERSECURITY NETWORK ANALYSIS — SECURITY REPORT",
            "=" * 70,
            f"  Generated  : {now}",
            f"  Target     : {target}",
            f"  Hosts up   : {len(alive)} / {len(hosts)}",
            f"  Open ports : {sum(len(h.open_ports) for h in alive)}",
            "",
            "  DISCLAIMER: Findings are based solely on observed open ports.",
            "  They do NOT confirm exploitation. Human review required.",
            "=" * 70, "",
        ]
        for h in alive:
            label = h.ip + (f"  ({h.hostname})" if h.hostname else "")
            lines += [f"HOST: {label}", "-" * 60]
            if not h.open_ports:
                lines += ["  No open ports found.", ""]
                continue
            flagged   = [p for p in h.open_ports if p.risk_level]
            unflagged = [p for p in h.open_ports if not p.risk_level]
            for p in sorted(flagged, key=lambda x: (_sev(x.risk_level), x.port)):
                icon = {"HIGH": "⚠ HIGH", "MEDIUM": "⚡ MEDIUM"}.get(p.risk_level, p.risk_level)
                lines += [
                    f"  [{icon}]  Port {p.port}/TCP — {p.service}",
                    f"    Why    : {p.explanation}",
                    f"    Action : {p.remediation}", "",
                ]
            if unflagged:
                lines.append("  Other open ports (no specific risk note):")
                for p in unflagged:
                    lines.append(f"    {p.port}/TCP  {p.service}"
                                 + (f"  [{p.banner}]" if p.banner else ""))
                lines.append("")
            lines.append("")
        lines += ["=" * 70, "  END OF REPORT", "=" * 70]
        self._set_report("\n".join(lines))

    # ── Utility ───────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        self._log_box.configure(state="normal")
        self._log_box.insert("end", msg.rstrip() + "\n")
        self._log_box.see("end")
        self._log_box.configure(state="disabled")
        self._stat_var.set(msg[:80])

    def _set_report(self, text: str) -> None:
        self._report_box.configure(state="normal")
        self._report_box.delete("1.0", "end")
        self._report_box.insert("1.0", text)
        self._report_box.configure(state="disabled")

    def _set_traffic(self, text: str) -> None:
        self._traffic_box.configure(state="normal")
        self._traffic_box.delete("1.0", "end")
        self._traffic_box.insert("1.0", text)
        self._traffic_box.configure(state="disabled")


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    App().mainloop()
