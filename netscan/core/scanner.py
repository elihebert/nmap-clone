"""
NetScan Core Scanner Engine
High-performance async network scanner with adaptive timing
"""

import asyncio
import time
import socket
import struct
import random
import logging
from typing import List, Dict, Optional, Union, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import netifaces
import re

# Configure scapy before importing to suppress warnings
import scapy.config
scapy.config.conf.verb = 0  # Suppress scapy verbosity

from scapy.all import *
from collections import defaultdict
import numpy as np

# Suppress specific scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Supported scan types"""
    TCP_SYN = "syn"
    TCP_CONNECT = "connect"
    TCP_ACK = "ack"
    TCP_WINDOW = "window"
    TCP_MAIMON = "maimon"
    TCP_NULL = "null"
    TCP_FIN = "fin"
    TCP_XMAS = "xmas"
    UDP = "udp"
    SCTP_INIT = "sctp-init"
    SCTP_COOKIE = "sctp-cookie"
    IP_PROTO = "ip-proto"
    PING = "ping"
    TIMESTAMP = "timestamp"
    NETMASK = "netmask"


class TimingTemplate(Enum):
    """Timing templates for scan speed"""
    PARANOID = 0  # 5 min between packets
    SNEAKY = 1    # 15 sec between packets
    POLITE = 2    # 0.4 sec between packets
    NORMAL = 3    # Default timing
    AGGRESSIVE = 4 # Fast timing
    INSANE = 5    # Fastest timing


@dataclass
class ScanOptions:
    """Configuration options for scanning"""
    scan_type: ScanType = ScanType.TCP_SYN
    ports: Union[str, List[int]] = "1-1000"
    timing: TimingTemplate = TimingTemplate.NORMAL
    max_retries: int = 2
    timeout: float = 1.0
    parallelism: int = 100
    min_rtt_timeout: float = 0.1
    max_rtt_timeout: float = 10.0
    initial_rtt_timeout: float = 1.0
    host_timeout: Optional[float] = None
    scan_delay: float = 0
    max_scan_delay: float = 1.0
    min_rate: Optional[int] = None
    max_rate: Optional[int] = None
    defeat_rst_ratelimit: bool = False
    defeat_icmp_ratelimit: bool = False
    version_detection: bool = False
    full_version_detection: bool = False  # Flag for banner grabbing
    os_detection: bool = False
    traceroute: bool = False
    script_scan: bool = False
    ipv6: bool = False
    fragment_packets: bool = False
    mtu: Optional[int] = None
    decoy_hosts: List[str] = field(default_factory=list)
    source_port: Optional[int] = None
    interface: Optional[str] = None
    spoof_mac: Optional[str] = None


@dataclass
class PortResult:
    """Result for a single port scan"""
    port: int
    state: str  # open, closed, filtered, open|filtered, closed|filtered
    service: Optional[str] = None
    version: Optional[str] = None
    reason: str = ""
    ttl: Optional[int] = None
    window: Optional[int] = None
    script_results: Dict[str, str] = field(default_factory=dict)


@dataclass
class HostResult:
    """Result for a single host scan"""
    ip: str
    hostname: Optional[str] = None
    state: str = "up"  # up, down, unknown
    ports: Dict[int, PortResult] = field(default_factory=dict)
    os_matches: List[Dict[str, Union[str, int]]] = field(default_factory=list)
    traceroute: List[Dict[str, str]] = field(default_factory=list)
    latency: Optional[float] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    scripts: Dict[str, str] = field(default_factory=dict)
    scan_time: float = 0


class AdaptiveTiming:
    """Adaptive timing algorithm for network conditions"""
    
    def __init__(self, options: ScanOptions):
        self.options = options
        self.rtt_history: List[float] = []
        self.current_rtt_timeout = options.initial_rtt_timeout
        self.congestion_window = options.parallelism
        self.packet_loss_rate = 0.0
        self.last_update = time.time()
        
    def update_rtt(self, rtt: float):
        """Update RTT statistics"""
        self.rtt_history.append(rtt)
        if len(self.rtt_history) > 100:
            self.rtt_history.pop(0)
            
        # Calculate adaptive timeout (similar to TCP's algorithm)
        if len(self.rtt_history) >= 3:
            avg_rtt = np.mean(self.rtt_history[-10:])
            std_rtt = np.std(self.rtt_history[-10:])
            self.current_rtt_timeout = min(
                max(avg_rtt + 4 * std_rtt, self.options.min_rtt_timeout),
                self.options.max_rtt_timeout
            )
    
    def update_loss(self, lost: bool):
        """Update packet loss statistics"""
        alpha = 0.875  # Smoothing factor
        self.packet_loss_rate = alpha * self.packet_loss_rate + (1 - alpha) * (1 if lost else 0)
        
        # Adjust congestion window based on loss
        if lost and self.congestion_window > 10:
            self.congestion_window = int(self.congestion_window * 0.8)
        elif not lost and self.congestion_window < self.options.parallelism:
            self.congestion_window = min(self.congestion_window + 1, self.options.parallelism)
    
    def get_timeout(self) -> float:
        """Get current timeout value"""
        return self.current_rtt_timeout
    
    def get_parallelism(self) -> int:
        """Get current parallelism level"""
        return self.congestion_window


class Scanner:
    """Main scanner class with async support"""
    
    def __init__(self, options: Optional[ScanOptions] = None):
        self.options = options or ScanOptions()
        self.timing = AdaptiveTiming(self.options)
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.semaphore = asyncio.Semaphore(self.options.parallelism)
        self.results: Dict[str, HostResult] = {}
        self.start_time = None
        self.packet_count = 0
        self.rate_limiter = None
        
        # Initialize rate limiting if specified
        if self.options.min_rate or self.options.max_rate:
            self._init_rate_limiter()
    
    def _init_rate_limiter(self):
        """Initialize rate limiting"""
        self.rate_limiter = {
            'last_sent': time.time(),
            'tokens': self.options.max_rate or float('inf'),
            'refill_rate': self.options.max_rate or float('inf'),
            'min_interval': 1.0 / self.options.min_rate if self.options.min_rate else 0
        }
    
    async def _rate_limit(self):
        """Apply rate limiting"""
        if not self.rate_limiter:
            return
            
        now = time.time()
        
        # Token bucket for max rate
        if self.options.max_rate:
            elapsed = now - self.rate_limiter['last_sent']
            self.rate_limiter['tokens'] = min(
                self.rate_limiter['tokens'] + elapsed * self.rate_limiter['refill_rate'],
                self.rate_limiter['refill_rate']
            )
            
            if self.rate_limiter['tokens'] < 1:
                await asyncio.sleep((1 - self.rate_limiter['tokens']) / self.rate_limiter['refill_rate'])
                self.rate_limiter['tokens'] = 0
            else:
                self.rate_limiter['tokens'] -= 1
        
        # Minimum interval for min rate
        if self.options.min_rate:
            elapsed = now - self.rate_limiter['last_sent']
            if elapsed < self.rate_limiter['min_interval']:
                await asyncio.sleep(self.rate_limiter['min_interval'] - elapsed)
        
        self.rate_limiter['last_sent'] = time.time()
    
    def _parse_ports(self, ports: Union[str, List[int]]) -> List[int]:
        """Parse port specification"""
        if isinstance(ports, list):
            return ports
        
        # Handle special case: "-" means all ports (1-65535)
        if ports == "-":
            return list(range(1, 65536))
            
        port_list = []
        for part in ports.split(','):
            if '-' in part:
                # Split on '-' and handle empty strings
                parts = part.split('-')
                if len(parts) == 2 and parts[0] and parts[1]:
                    start, end = map(int, parts)
                    port_list.extend(range(start, end + 1))
                elif len(parts) == 2 and parts[0] and not parts[1]:
                    # Handle "80-" (from port 80 to 65535)
                    start = int(parts[0])
                    port_list.extend(range(start, 65536))
                elif len(parts) == 2 and not parts[0] and parts[1]:
                    # Handle "-80" (from port 1 to 80)
                    end = int(parts[1])
                    port_list.extend(range(1, end + 1))
            else:
                port_list.append(int(part))
        
        return port_list
    
    def _get_interface_info(self) -> Tuple[str, str]:
        """Get default interface and IP"""
        if self.options.interface:
            iface = self.options.interface
        else:
            # Get default gateway interface
            gws = netifaces.gateways()
            iface = gws['default'][netifaces.AF_INET][1]
        
        addrs = netifaces.ifaddresses(iface)
        ip = addrs[netifaces.AF_INET][0]['addr']
        
        return iface, ip
    
    async def scan(self, targets: Union[str, List[str]], 
                   ports: Optional[Union[str, List[int]]] = None) -> Dict[str, HostResult]:
        """Main scan method"""
        self.start_time = time.time()
        
        # Parse targets
        if isinstance(targets, str):
            targets = [targets]
        
        all_hosts = []
        for target in targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                all_hosts.extend(str(host) for host in network.hosts())
            except ValueError:
                # Single host
                all_hosts.append(target)
        
        # Parse ports
        if ports:
            port_list = self._parse_ports(ports)
        else:
            port_list = self._parse_ports(self.options.ports)
        
        # Warn about large scans
        total_probes = len(all_hosts) * len(port_list)
        if total_probes > 100000:
            logger.warning(f"Large scan detected: {len(all_hosts)} hosts × {len(port_list)} ports = {total_probes:,} probes")
            logger.warning("Consider using -F for fast scan or --top-ports for common ports")
        
        # Perform host discovery
        logger.info(f"Starting scan of {len(all_hosts)} hosts on {len(port_list)} ports")
        live_hosts = await self._discover_hosts(all_hosts)
        
        # If no live hosts found, return empty results
        if not live_hosts:
            logger.warning("No live hosts found during discovery phase")
            return self.results
        
        # Scan live hosts
        tasks = []
        for host in live_hosts:
            task = self._scan_host(host, port_list)
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        # Perform additional scans if requested
        if self.options.version_detection:
            await self._version_detection()
        
        # Aggressive scanning includes enhanced version detection
        if self.options.timing == TimingTemplate.AGGRESSIVE or self.options.full_version_detection:
            logger.info("Performing aggressive version detection")
            for host_ip, host_result in self.results.items():
                for port, port_result in host_result.ports.items():
                    if port_result.state == "open":
                        await self._aggressive_version_detection(host_ip, port, port_result)
        
        if self.options.os_detection:
            # Use enhanced OS detection for aggressive scanning
            if self.options.timing == TimingTemplate.AGGRESSIVE:
                await self._enhanced_os_detection()
            else:
                await self._os_detection()
        
        if self.options.script_scan:
            await self._script_scanning()
        
        if self.options.traceroute:
            await self._traceroute()
        
        return self.results
    
    async def _discover_hosts(self, hosts: List[str]) -> List[str]:
        """Discover live hosts using various methods"""
        live_hosts = []
        
        # Use ICMP echo, TCP SYN to port 80/443, and TCP ACK to port 80/443
        discovery_methods = [
            self._icmp_ping,
            lambda h: self._tcp_ping(h, 80),
            lambda h: self._tcp_ping(h, 443),
        ]
        
        tasks = []
        for host in hosts:
            for method in discovery_methods:
                task = method(host)
                tasks.append((host, task))
        
        results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
        
        # Collect live hosts
        host_results = defaultdict(list)
        for (host, _), result in zip(tasks, results):
            if not isinstance(result, Exception):
                host_results[host].append(result)
        
        # A host is considered live if any method succeeds
        for host, results in host_results.items():
            if any(results):
                live_hosts.append(host)
                self.results[host] = HostResult(ip=host, state="up")
        
        logger.info(f"Discovered {len(live_hosts)} live hosts")
        return live_hosts
    
    async def _icmp_ping(self, host: str) -> bool:
        """ICMP echo request"""
        async with self.semaphore:
            await self._rate_limit()
            
            try:
                # Create ICMP packet
                pkt = IP(dst=host)/ICMP()
                
                # Send packet and wait for reply
                start_time = time.time()
                reply = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: sr1(pkt, timeout=self.timing.get_timeout(), verbose=0)
                )
                
                if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
                    rtt = time.time() - start_time
                    self.timing.update_rtt(rtt)
                    return True
                else:
                    self.timing.update_loss(True)
                    return False
                    
            except Exception as e:
                logger.debug(f"ICMP ping failed for {host}: {e}")
                return False
    
    async def _tcp_ping(self, host: str, port: int) -> bool:
        """TCP SYN/ACK ping"""
        async with self.semaphore:
            await self._rate_limit()
            
            try:
                sport = random.randint(1024, 65535)
                pkt = IP(dst=host)/TCP(sport=sport, dport=port, flags="S")
                
                start_time = time.time()
                reply = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: sr1(pkt, timeout=self.timing.get_timeout(), verbose=0)
                )
                
                if reply and reply.haslayer(TCP):
                    rtt = time.time() - start_time
                    self.timing.update_rtt(rtt)
                    return True
                else:
                    self.timing.update_loss(True)
                    return False
                    
            except Exception as e:
                logger.debug(f"TCP ping failed for {host}:{port}: {e}")
                return False
    
    async def _scan_host(self, host: str, ports: List[int]):
        """Scan all ports on a host"""
        logger.debug(f"Scanning host {host}")
        
        # Get scan method
        scan_method = self._get_scan_method()
        
        # Scan ports in batches
        tasks = []
        for port in ports:
            task = scan_method(host, port)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Store results
        for port, result in zip(ports, results):
            if isinstance(result, PortResult):
                self.results[host].ports[port] = result
    
    def _get_scan_method(self):
        """Get the appropriate scan method based on scan type"""
        scan_methods = {
            ScanType.TCP_SYN: self._tcp_syn_scan,
            ScanType.TCP_CONNECT: self._tcp_connect_scan,
            ScanType.TCP_ACK: self._tcp_ack_scan,
            ScanType.TCP_WINDOW: self._tcp_window_scan,
            ScanType.TCP_NULL: self._tcp_null_scan,
            ScanType.TCP_FIN: self._tcp_fin_scan,
            ScanType.TCP_XMAS: self._tcp_xmas_scan,
            ScanType.UDP: self._udp_scan,
        }
        
        return scan_methods.get(self.options.scan_type, self._tcp_syn_scan)
    
    async def _tcp_syn_scan(self, host: str, port: int) -> PortResult:
        """TCP SYN scan (half-open scan)"""
        async with self.semaphore:
            await self._rate_limit()
            
            for retry in range(self.options.max_retries + 1):
                try:
                    sport = self.options.source_port or random.randint(1024, 65535)
                    
                    # Build packet with options
                    pkt = IP(dst=host)
                    
                    if self.options.fragment_packets:
                        pkt.flags = "MF"
                    
                    tcp = TCP(sport=sport, dport=port, flags="S", seq=random.randint(0, 2**32-1))
                    pkt = pkt/tcp
                    
                    # Add decoys if specified
                    if self.options.decoy_hosts:
                        # Implementation for decoy hosts
                        pass
                    
                    start_time = time.time()
                    reply = await asyncio.get_event_loop().run_in_executor(
                        self.executor,
                        lambda: sr1(pkt, timeout=self.timing.get_timeout(), verbose=0)
                    )
                    
                    if reply:
                        rtt = time.time() - start_time
                        self.timing.update_rtt(rtt)
                        
                        if reply.haslayer(TCP):
                            tcp_layer = reply[TCP]
                            
                            if tcp_layer.flags & 0x12:  # SYN-ACK
                                # Send RST to close connection
                                rst = IP(dst=host)/TCP(sport=sport, dport=port, flags="R", seq=tcp_layer.ack)
                                send(rst, verbose=0)
                                
                                return PortResult(
                                    port=port,
                                    state="open",
                                    reason="syn-ack",
                                    ttl=reply[IP].ttl if reply.haslayer(IP) else None,
                                    window=tcp_layer.window
                                )
                            
                            elif tcp_layer.flags & 0x04:  # RST
                                if not self.options.defeat_rst_ratelimit or retry == self.options.max_retries:
                                    return PortResult(port=port, state="closed", reason="reset")
                            
                    else:
                        self.timing.update_loss(True)
                        
                        if retry == self.options.max_retries:
                            return PortResult(port=port, state="filtered", reason="no-response")
                    
                    # Add scan delay
                    if self.options.scan_delay > 0:
                        await asyncio.sleep(self.options.scan_delay)
                        
                except Exception as e:
                    logger.debug(f"TCP SYN scan error for {host}:{port}: {e}")
                    if retry == self.options.max_retries:
                        return PortResult(port=port, state="filtered", reason=f"error: {str(e)}")
            
            return PortResult(port=port, state="filtered", reason="max-retries")
    
    async def _tcp_connect_scan(self, host: str, port: int) -> PortResult:
        """Full TCP connect scan"""
        async with self.semaphore:
            await self._rate_limit()
            
            for retry in range(self.options.max_retries + 1):
                try:
                    start_time = time.time()
                    
                    # Create socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    sock.settimeout(self.timing.get_timeout())
                    
                    # Attempt connection
                    try:
                        await asyncio.wait_for(
                            asyncio.get_event_loop().sock_connect(sock, (host, port)),
                            timeout=self.timing.get_timeout()
                        )
                        
                        rtt = time.time() - start_time
                        self.timing.update_rtt(rtt)
                        
                        sock.close()
                        return PortResult(port=port, state="open", reason="syn-ack")
                        
                    except (socket.timeout, asyncio.TimeoutError):
                        self.timing.update_loss(True)
                        if retry == self.options.max_retries:
                            return PortResult(port=port, state="filtered", reason="timeout")
                            
                    except ConnectionRefusedError:
                        return PortResult(port=port, state="closed", reason="conn-refused")
                        
                    finally:
                        sock.close()
                        
                except Exception as e:
                    logger.debug(f"TCP connect scan error for {host}:{port}: {e}")
                    if retry == self.options.max_retries:
                        return PortResult(port=port, state="filtered", reason=f"error: {str(e)}")
            
            return PortResult(port=port, state="filtered", reason="max-retries")
    
    async def _tcp_ack_scan(self, host: str, port: int) -> PortResult:
        """TCP ACK scan for firewall detection"""
        async with self.semaphore:
            await self._rate_limit()
            
            try:
                sport = random.randint(1024, 65535)
                pkt = IP(dst=host)/TCP(sport=sport, dport=port, flags="A", ack=random.randint(0, 2**32-1))
                
                reply = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: sr1(pkt, timeout=self.timing.get_timeout(), verbose=0)
                )
                
                if reply and reply.haslayer(TCP) and reply[TCP].flags & 0x04:  # RST
                    return PortResult(port=port, state="unfiltered", reason="reset")
                elif reply and reply.haslayer(ICMP):
                    return PortResult(port=port, state="filtered", reason="icmp-error")
                else:
                    return PortResult(port=port, state="filtered", reason="no-response")
                    
            except Exception as e:
                logger.debug(f"TCP ACK scan error for {host}:{port}: {e}")
                return PortResult(port=port, state="filtered", reason=f"error: {str(e)}")
    
    async def _tcp_window_scan(self, host: str, port: int) -> PortResult:
        """TCP Window scan"""
        async with self.semaphore:
            await self._rate_limit()
            
            try:
                sport = random.randint(1024, 65535)
                pkt = IP(dst=host)/TCP(sport=sport, dport=port, flags="A", ack=random.randint(0, 2**32-1))
                
                reply = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: sr1(pkt, timeout=self.timing.get_timeout(), verbose=0)
                )
                
                if reply and reply.haslayer(TCP):
                    tcp_layer = reply[TCP]
                    if tcp_layer.flags & 0x04:  # RST
                        if tcp_layer.window > 0:
                            return PortResult(port=port, state="open", reason="window", window=tcp_layer.window)
                        else:
                            return PortResult(port=port, state="closed", reason="window", window=tcp_layer.window)
                
                return PortResult(port=port, state="filtered", reason="no-response")
                
            except Exception as e:
                logger.debug(f"TCP Window scan error for {host}:{port}: {e}")
                return PortResult(port=port, state="filtered", reason=f"error: {str(e)}")
    
    async def _tcp_null_scan(self, host: str, port: int) -> PortResult:
        """TCP NULL scan (no flags)"""
        return await self._tcp_flags_scan(host, port, "", "null")
    
    async def _tcp_fin_scan(self, host: str, port: int) -> PortResult:
        """TCP FIN scan"""
        return await self._tcp_flags_scan(host, port, "F", "fin")
    
    async def _tcp_xmas_scan(self, host: str, port: int) -> PortResult:
        """TCP XMAS scan (FIN, PSH, URG flags)"""
        return await self._tcp_flags_scan(host, port, "FPU", "xmas")
    
    async def _tcp_flags_scan(self, host: str, port: int, flags: str, scan_name: str) -> PortResult:
        """Generic TCP flags scan"""
        async with self.semaphore:
            await self._rate_limit()
            
            try:
                sport = random.randint(1024, 65535)
                pkt = IP(dst=host)/TCP(sport=sport, dport=port, flags=flags)
                
                reply = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    lambda: sr1(pkt, timeout=self.timing.get_timeout(), verbose=0)
                )
                
                if reply and reply.haslayer(TCP) and reply[TCP].flags & 0x04:  # RST
                    return PortResult(port=port, state="closed", reason=f"{scan_name}-reset")
                elif reply and reply.haslayer(ICMP):
                    icmp_type = reply[ICMP].type
                    icmp_code = reply[ICMP].code
                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        return PortResult(port=port, state="filtered", reason=f"{scan_name}-icmp-{icmp_code}")
                elif not reply:
                    return PortResult(port=port, state="open|filtered", reason=f"{scan_name}-no-response")
                
                return PortResult(port=port, state="filtered", reason=f"{scan_name}-unknown")
                
            except Exception as e:
                logger.debug(f"TCP {scan_name} scan error for {host}:{port}: {e}")
                return PortResult(port=port, state="filtered", reason=f"error: {str(e)}")
    
    async def _udp_scan(self, host: str, port: int) -> PortResult:
        """UDP scan"""
        async with self.semaphore:
            await self._rate_limit()
            
            for retry in range(self.options.max_retries + 1):
                try:
                    sport = random.randint(1024, 65535)
                    
                    # Create UDP packet with port-specific payload
                    payload = self._get_udp_payload(port)
                    pkt = IP(dst=host)/UDP(sport=sport, dport=port)/Raw(load=payload)
                    
                    start_time = time.time()
                    reply = await asyncio.get_event_loop().run_in_executor(
                        self.executor,
                        lambda: sr1(pkt, timeout=self.timing.get_timeout() * 2, verbose=0)  # UDP needs longer timeout
                    )
                    
                    if reply:
                        rtt = time.time() - start_time
                        self.timing.update_rtt(rtt)
                        
                        if reply.haslayer(UDP):
                            return PortResult(port=port, state="open", reason="udp-response")
                        elif reply.haslayer(ICMP):
                            icmp_type = reply[ICMP].type
                            icmp_code = reply[ICMP].code
                            
                            if icmp_type == 3 and icmp_code == 3:  # Port unreachable
                                if not self.options.defeat_icmp_ratelimit or retry == self.options.max_retries:
                                    return PortResult(port=port, state="closed", reason="port-unreach")
                            elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
                                return PortResult(port=port, state="filtered", reason=f"icmp-{icmp_code}")
                    else:
                        self.timing.update_loss(True)
                        if retry == self.options.max_retries:
                            return PortResult(port=port, state="open|filtered", reason="no-response")
                    
                except Exception as e:
                    logger.debug(f"UDP scan error for {host}:{port}: {e}")
                    if retry == self.options.max_retries:
                        return PortResult(port=port, state="filtered", reason=f"error: {str(e)}")
            
            return PortResult(port=port, state="open|filtered", reason="max-retries")
    
    def _get_udp_payload(self, port: int) -> bytes:
        """Get port-specific UDP payload for better detection"""
        # Common UDP service payloads
        payloads = {
            53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
            123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00",  # NTP
            161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04",  # SNMP
            500: b"\x00" * 8,  # IKE
            1434: b"\x02",  # MS-SQL
        }
        
        return payloads.get(port, b"")
    
    async def _version_detection(self):
        """Perform service version detection on open ports"""
        logger.info("Starting version detection")
        
        tasks = []
        for host_ip, host_result in self.results.items():
            if host_result.state == "up":
                for port_num, port_result in host_result.ports.items():
                    if port_result.state == "open":
                        # Use full detection if explicitly requested, otherwise basic
                        if self.options.full_version_detection:
                            task = self._detect_service_version(host_ip, port_num, port_result)
                        else:
                            task = self._basic_service_detection(host_ip, port_num, port_result)
                        tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _basic_service_detection(self, host: str, port: int, port_result: PortResult):
        """Basic service detection using port numbers only (fast)"""
        try:
            service_info = self._identify_by_port(port)
            
            if service_info['service']:
                port_result.service = service_info['service']
            if service_info['version']:
                port_result.version = service_info['version']
                
        except Exception as e:
            logger.debug(f"Basic service detection failed for {host}:{port}: {e}")
    
    async def _detect_service_version(self, host: str, port: int, port_result: PortResult):
        """Detect service version for a specific port"""
        try:
            # Try different detection methods
            service_info = await self._banner_grab(host, port)
            
            if not service_info['service']:
                service_info = await self._probe_service(host, port)
            
            # Update port result with detected information
            if service_info['service']:
                port_result.service = service_info['service']
            if service_info['version']:
                port_result.version = service_info['version']
                
        except Exception as e:
            logger.debug(f"Version detection failed for {host}:{port}: {e}")
    
    async def _banner_grab(self, host: str, port: int) -> dict:
        """Grab banner from service"""
        service_info = {'service': None, 'version': None}
        
        try:
            # Try TCP connection first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            await asyncio.wait_for(
                asyncio.get_event_loop().sock_connect(sock, (host, port)),
                timeout=3
            )
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000, 8008, 8888, 3000, 5000]:
                request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
                await asyncio.get_event_loop().sock_sendall(sock, request)
            elif port in [443, 8443]:
                # For HTTPS, just identify it as https
                service_info['service'] = 'https'
                service_info['version'] = 'ssl/tls'
                sock.close()
                return service_info
            elif port == 22:
                # SSH usually sends banner immediately
                pass
            elif port in [21]:
                # FTP usually sends banner immediately
                pass
            elif port in [25, 587]:
                # SMTP usually sends banner immediately
                pass
            else:
                # For other services, try to trigger a response
                await asyncio.get_event_loop().sock_sendall(sock, b"\r\n")
            
            # Read response
            try:
                sock.settimeout(2)
                data = await asyncio.wait_for(
                    asyncio.get_event_loop().sock_recv(sock, 1024),
                    timeout=2
                )
                banner = data.decode('utf-8', errors='ignore').strip()
                
                # Parse banner for service information
                service_info = self._parse_banner(banner, port)
                
            except (asyncio.TimeoutError, socket.timeout):
                # No banner received, try to identify by port
                service_info = self._identify_by_port(port)
            
            sock.close()
            
        except Exception as e:
            logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            # Fall back to port-based identification
            service_info = self._identify_by_port(port)
        
        return service_info
    
    def _parse_banner(self, banner: str, port: int) -> dict:
        """Parse service banner to extract service and version info"""
        service_info = {'service': None, 'version': None}
        
        if not banner:
            return self._identify_by_port(port)
        
        banner_lower = banner.lower()
        
        # HTTP services
        if 'http' in banner_lower and 'server:' in banner_lower:
            service_info['service'] = 'http'
            # Extract server header
            lines = banner.split('\n')
            for line in lines:
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
                    service_info['version'] = server
                    break
        
        # SSH
        elif banner.startswith('SSH-'):
            service_info['service'] = 'ssh'
            # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
            parts = banner.split()
            if len(parts) > 0:
                ssh_version = parts[0]  # SSH-2.0-OpenSSH_8.9p1
                if 'OpenSSH' in ssh_version:
                    version_part = ssh_version.split('OpenSSH_')[1] if 'OpenSSH_' in ssh_version else ''
                    service_info['version'] = f"OpenSSH {version_part}"
                else:
                    service_info['version'] = ssh_version
        
        # FTP
        elif banner.startswith('220'):
            service_info['service'] = 'ftp'
            # Extract FTP server info
            if 'vsftpd' in banner_lower:
                service_info['version'] = 'vsftpd'
            elif 'proftpd' in banner_lower:
                service_info['version'] = 'ProFTPD'
            elif 'filezilla' in banner_lower:
                service_info['version'] = 'FileZilla'
            else:
                service_info['version'] = banner.strip()
        
        # SMTP
        elif banner.startswith('220') and ('smtp' in banner_lower or 'mail' in banner_lower):
            service_info['service'] = 'smtp'
            if 'postfix' in banner_lower:
                service_info['version'] = 'Postfix'
            elif 'sendmail' in banner_lower:
                service_info['version'] = 'Sendmail'
            elif 'exim' in banner_lower:
                service_info['version'] = 'Exim'
            else:
                service_info['version'] = banner.strip()
        
        # Telnet
        elif 'telnet' in banner_lower or banner.startswith('\xff'):
            service_info['service'] = 'telnet'
            service_info['version'] = 'telnet'
        
        # MySQL
        elif port == 3306 and len(banner) > 4:
            service_info['service'] = 'mysql'
            # MySQL sends a specific packet format
            if 'mysql' in banner_lower:
                service_info['version'] = 'MySQL'
        
        # PostgreSQL
        elif port == 5432:
            service_info['service'] = 'postgresql'
            service_info['version'] = 'PostgreSQL'
        
        # If we couldn't parse the banner, fall back to port identification
        if not service_info['service']:
            service_info = self._identify_by_port(port)
            if banner and not service_info['version']:
                service_info['version'] = banner[:50]  # First 50 chars of banner
        
        return service_info
    
    def _identify_by_port(self, port: int) -> dict:
        """Identify service by well-known port numbers"""
        port_services = {
            7: {'service': 'echo', 'version': None},
            9: {'service': 'discard', 'version': None},
            13: {'service': 'daytime', 'version': None},
            21: {'service': 'ftp', 'version': None},
            22: {'service': 'ssh', 'version': None},
            23: {'service': 'telnet', 'version': None},
            25: {'service': 'smtp', 'version': None},
            37: {'service': 'time', 'version': None},
            53: {'service': 'domain', 'version': 'DNS'},
            79: {'service': 'finger', 'version': None},
            80: {'service': 'http', 'version': None},
            88: {'service': 'kerberos', 'version': None},
            110: {'service': 'pop3', 'version': None},
            111: {'service': 'rpcbind', 'version': None},
            113: {'service': 'ident', 'version': None},
            119: {'service': 'nntp', 'version': None},
            135: {'service': 'msrpc', 'version': 'Microsoft RPC'},
            139: {'service': 'netbios-ssn', 'version': 'NetBIOS'},
            143: {'service': 'imap', 'version': None},
            179: {'service': 'bgp', 'version': None},
            389: {'service': 'ldap', 'version': None},
            443: {'service': 'https', 'version': 'ssl/tls'},
            445: {'service': 'microsoft-ds', 'version': 'SMB'},
            465: {'service': 'smtps', 'version': 'ssl/tls'},
            513: {'service': 'rlogin', 'version': None},
            514: {'service': 'rsh', 'version': None},
            515: {'service': 'printer', 'version': 'LPD'},
            543: {'service': 'klogin', 'version': None},
            544: {'service': 'kshell', 'version': None},
            548: {'service': 'afp', 'version': 'Apple Filing'},
            587: {'service': 'submission', 'version': 'SMTP'},
            631: {'service': 'ipp', 'version': 'CUPS'},
            993: {'service': 'imaps', 'version': 'ssl/tls'},
            995: {'service': 'pop3s', 'version': 'ssl/tls'},
            1433: {'service': 'ms-sql-s', 'version': 'Microsoft SQL'},
            1723: {'service': 'pptp', 'version': None},
            3306: {'service': 'mysql', 'version': None},
            3389: {'service': 'ms-wbt-server', 'version': 'RDP'},
            5432: {'service': 'postgresql', 'version': None},
            5900: {'service': 'vnc', 'version': None},
            8080: {'service': 'http-proxy', 'version': None},
            8443: {'service': 'https-alt', 'version': 'ssl/tls'},
        }
        
        return port_services.get(port, {'service': 'unknown', 'version': None})
    
    async def _probe_service(self, host: str, port: int) -> dict:
        """Send specific probes to identify services"""
        service_info = {'service': None, 'version': None}
        
        # This would contain specific service probes similar to nmap's nmap-service-probes
        # For now, we'll use basic probes for common services
        
        probes = []
        
        # HTTP probe
        if port in [80, 8080, 8000, 8008, 8888, 3000, 5000]:
            probes.append({
                'data': b"GET / HTTP/1.0\r\n\r\n",
                'expect': b'HTTP',
                'service': 'http'
            })
        
        # HTTPS probe
        elif port in [443, 8443]:
            service_info = {'service': 'https', 'version': 'ssl/tls'}
            return service_info
        
        # Try probes
        for probe in probes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                await asyncio.wait_for(
                    asyncio.get_event_loop().sock_connect(sock, (host, port)),
                    timeout=2
                )
                
                await asyncio.get_event_loop().sock_sendall(sock, probe['data'])
                
                response = await asyncio.wait_for(
                    asyncio.get_event_loop().sock_recv(sock, 1024),
                    timeout=2
                )
                
                if probe['expect'] in response:
                    service_info['service'] = probe['service']
                    # Try to extract version from response
                    response_str = response.decode('utf-8', errors='ignore')
                    service_info = self._parse_banner(response_str, port)
                    break
                
                sock.close()
                
            except Exception as e:
                logger.debug(f"Service probe failed for {host}:{port}: {e}")
                continue
        
        # If no probes worked, fall back to port identification
        if not service_info['service']:
            service_info = self._identify_by_port(port)
        
        return service_info
    
    async def _os_detection(self):
        """Perform OS detection using TCP/IP stack fingerprinting"""
        logger.info("Starting OS detection")
        
        # Implementation would include:
        # - TCP/IP fingerprinting
        # - TTL analysis
        # - Window size analysis
        # - TCP options analysis
        pass
    
    async def _traceroute(self):
        """Perform traceroute to targets"""
        logger.info("Starting traceroute")
        
        # Implementation would include:
        # - ICMP TTL-based traceroute
        # - TCP SYN traceroute
        # - UDP traceroute
        pass

    async def _aggressive_version_detection(self, host: str, port: int, port_result: PortResult):
        """Perform aggressive version detection with multiple probes"""
        # Enhanced banner grabbing with multiple probe strings
        probes = [
            # Generic probes
            b"",  # Empty probe
            b"\r\n\r\n",  # Double CRLF
            b"HELP\r\n",
            b"QUIT\r\n",
            b"GET / HTTP/1.0\r\n\r\n",
            b"HEAD / HTTP/1.0\r\n\r\n",
            b"OPTIONS * HTTP/1.0\r\n\r\n",
            
            # Service-specific probes
            b"USER anonymous\r\n",  # FTP
            b"EHLO test\r\n",  # SMTP
            b"SSH-2.0-OpenSSH_7.4\r\n",  # SSH
            b"\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00",  # MySQL
            b"STATS\r\n",  # Memcached
            b"INFO\r\n",  # Redis
            b"*1\r\n$4\r\nping\r\n",  # Redis PING
            b"CAP LS\r\n",  # IRC
            b"<policy-file-request/>\x00",  # Flash policy
        ]
        
        best_result = None
        best_confidence = 0
        
        for probe in probes:
            try:
                result = await self._send_probe_and_analyze(host, port, probe)
                if result and result.get('confidence', 0) > best_confidence:
                    best_result = result
                    best_confidence = result['confidence']
                    
                    # Stop if we have high confidence
                    if best_confidence > 0.8:
                        break
                        
            except Exception:
                continue
        
        if best_result:
            port_result.service = best_result.get('service', port_result.service)
            port_result.version = best_result.get('version', port_result.version)
            
            # Add any detected vulnerabilities
            if 'vulnerabilities' in best_result:
                port_result.script_results['vulns'] = best_result['vulnerabilities']
    
    async def _send_probe_and_analyze(self, host: str, port: int, probe: bytes) -> Optional[Dict]:
        """Send a probe and analyze the response"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3.0
            )
            
            # Send probe
            if probe:
                writer.write(probe)
                await writer.drain()
            
            # Read response
            response = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            
            writer.close()
            await writer.wait_closed()
            
            if response:
                return self._analyze_aggressive_banner(response.decode('utf-8', errors='ignore'), port)
                
        except Exception:
            pass
        
        return None
    
    def _analyze_aggressive_banner(self, banner: str, port: int) -> Dict[str, any]:
        """Enhanced banner analysis for aggressive scanning"""
        result = {
            'confidence': 0.0
        }
        
        # Enhanced service fingerprints with vulnerability detection
        fingerprints = [
            # SSH with vulnerability detection
            (r'SSH-(\d+\.\d+)-(.+)', 'ssh', 
             lambda m: f"SSH {m.group(1)} ({m.group(2)})", 0.95,
             lambda m: ['SSH Protocol 1 (vulnerable)'] if 'SSH-1.' in m.group(0) else []),
            
            # HTTP/Web servers with version extraction
            (r'Server:\s*Apache/(\S+)', 'http', 
             lambda m: f"Apache {m.group(1)}", 0.9,
             lambda m: ['Apache 2.2.x (EOL)'] if 'Apache/2.2.' in m.group(0) else []),
            (r'Server:\s*nginx/(\S+)', 'http', 
             lambda m: f"nginx {m.group(1)}", 0.9,
             lambda m: ['nginx 1.0.x (outdated)'] if 'nginx/1.0.' in m.group(0) else []),
            (r'Server:\s*Microsoft-IIS/(\S+)', 'http', 
             lambda m: f"Microsoft IIS {m.group(1)}", 0.9,
             lambda m: ['IIS 6.0 (severely outdated)'] if 'IIS/6.0' in m.group(0) else []),
            
            # Database servers
            (r'MySQL.*\s+(\d+\.\d+\.\d+)', 'mysql', 
             lambda m: f"MySQL {m.group(1)}", 0.9,
             lambda m: []),
            (r'PostgreSQL\s+(\d+\.\d+)', 'postgresql', 
             lambda m: f"PostgreSQL {m.group(1)}", 0.9,
             lambda m: []),
            (r'\$.*redis_version:(\d+\.\d+\.\d+)', 'redis', 
             lambda m: f"Redis {m.group(1)}", 0.9,
             lambda m: ['Redis unprotected'] if 'requirepass' not in banner else []),
            
            # FTP servers
            (r'220.*ProFTPD\s+(\S+)', 'ftp', 
             lambda m: f"ProFTPD {m.group(1)}", 0.9,
             lambda m: []),
            (r'220.*vsftpd\s+(\S+)', 'ftp', 
             lambda m: f"vsftpd {m.group(1)}", 0.9,
             lambda m: []),
            
            # SMTP servers
            (r'220.*Postfix', 'smtp', 
             lambda m: "Postfix", 0.9,
             lambda m: []),
            (r'220.*Exim\s+(\S+)', 'smtp', 
             lambda m: f"Exim {m.group(1)}", 0.9,
             lambda m: []),
            
            # Other services
            (r'RFB\s+(\d{3}\.\d{3})', 'vnc', 
             lambda m: f"VNC (RFB {m.group(1)})", 0.95,
             lambda m: []),
        ]
        
        for pattern, service, version_func, confidence, vuln_func in fingerprints:
            match = re.search(pattern, banner, re.IGNORECASE | re.MULTILINE)
            if match:
                result['service'] = service
                result['version'] = version_func(match)
                result['confidence'] = confidence
                vulnerabilities = vuln_func(match)
                if vulnerabilities:
                    result['vulnerabilities'] = vulnerabilities
                break
        
        return result
    
    async def _enhanced_os_detection(self):
        """Enhanced OS detection with TCP/IP stack fingerprinting"""
        logger.info("Performing enhanced OS detection")
        
        for host_ip, host_result in self.results.items():
            # Find an open port for OS detection
            open_port = None
            for port, port_result in host_result.ports.items():
                if port_result.state == "open":
                    open_port = port
                    break
            
            if not open_port:
                continue
            
            # Perform TCP/IP stack fingerprinting
            os_fingerprint = await self._tcp_stack_fingerprinting(host_ip, open_port)
            
            # Match against OS database
            os_matches = self._match_os_fingerprint(os_fingerprint)
            
            # Store top matches
            host_result.os_matches = os_matches[:3]  # Top 3 matches
    
    async def _tcp_stack_fingerprinting(self, host: str, port: int) -> Dict:
        """Perform TCP/IP stack fingerprinting"""
        fingerprint = {
            'ttl': None,
            'window_size': None,
            'tcp_options': None,
            'df_bit': None,
            'tcp_timestamp': None,
        }
        
        try:
            # Send SYN packet with specific options
            ip = IP(dst=host)
            tcp = TCP(
                sport=random.randint(1024, 65535),
                dport=port,
                flags='S',
                seq=random.randint(0, 2**32-1),
                window=5840,
                options=[
                    ('MSS', 1460),
                    ('SAckOK', b''),
                    ('Timestamp', (0, 0)),
                    ('NOP', None),
                    ('WScale', 7)
                ]
            )
            
            packet = ip/tcp
            
            # Send and receive response
            response = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                lambda: sr1(packet, timeout=2, verbose=0)
            )
            
            if response and response.haslayer(TCP):
                # Extract fingerprint data
                fingerprint['ttl'] = response[IP].ttl if response.haslayer(IP) else None
                fingerprint['window_size'] = response[TCP].window
                fingerprint['df_bit'] = bool(response[IP].flags & 0x2) if response.haslayer(IP) else None
                
                # Extract TCP options
                tcp_options = []
                for opt in response[TCP].options:
                    if opt[0] == 'MSS':
                        tcp_options.append(f"MSS={opt[1]}")
                    elif opt[0] == 'WScale':
                        tcp_options.append(f"WS={opt[1]}")
                    elif opt[0] == 'Timestamp':
                        fingerprint['tcp_timestamp'] = True
                        tcp_options.append("TS")
                    elif opt[0] == 'SAckOK':
                        tcp_options.append("SACK")
                
                fingerprint['tcp_options'] = ','.join(tcp_options)
                
        except Exception as e:
            logger.debug(f"TCP fingerprinting failed: {e}")
        
        return fingerprint
    
    def _match_os_fingerprint(self, fingerprint: Dict) -> List[Dict]:
        """Match fingerprint against OS database"""
        os_database = {
            'Windows 10': {
                'ttl': [128, 127],
                'window': [8192, 65535],
                'df': True,
                'timestamp': True,
            },
            'Windows 7/8': {
                'ttl': [128, 127],
                'window': [8192],
                'df': True,
                'timestamp': True,
            },
            'Linux 5.x': {
                'ttl': [64, 63],
                'window': [65535, 29200],
                'df': True,
                'timestamp': True,
            },
            'Linux 4.x': {
                'ttl': [64, 63],
                'window': [29200, 14600],
                'df': True,
                'timestamp': True,
            },
            'macOS 11/12': {
                'ttl': [64, 63],
                'window': [65535],
                'df': True,
                'timestamp': True,
            },
            'FreeBSD': {
                'ttl': [64],
                'window': [65535],
                'df': True,
                'timestamp': True,
            },
        }
        
        matches = []
        
        for os_name, os_sig in os_database.items():
            score = 0
            
            # Check TTL
            if fingerprint.get('ttl') in os_sig.get('ttl', []):
                score += 30
            
            # Check window size
            if fingerprint.get('window_size') in os_sig.get('window', []):
                score += 25
            
            # Check DF bit
            if fingerprint.get('df_bit') == os_sig.get('df'):
                score += 20
            
            # Check timestamp
            if fingerprint.get('tcp_timestamp') == os_sig.get('timestamp'):
                score += 25
            
            if score > 0:
                matches.append({
                    'name': os_name,
                    'accuracy': score,
                    'cpe': self._generate_os_cpe(os_name),
                })
        
        # Sort by accuracy
        matches.sort(key=lambda x: x['accuracy'], reverse=True)
        
        return matches
    
    def _generate_os_cpe(self, os_name: str) -> str:
        """Generate CPE string for OS"""
        # Simplified CPE generation
        if 'Windows' in os_name:
            return f"cpe:/o:microsoft:windows"
        elif 'Linux' in os_name:
            return f"cpe:/o:linux:linux_kernel"
        elif 'macOS' in os_name:
            return f"cpe:/o:apple:macos"
        elif 'FreeBSD' in os_name:
            return f"cpe:/o:freebsd:freebsd"
        else:
            return f"cpe:/o:unknown:unknown"
    
    async def _script_scanning(self):
        """Perform script scanning for vulnerability detection"""
        logger.info("Performing script scanning")
        
        for host_ip, host_result in self.results.items():
            for port, port_result in host_result.ports.items():
                if port_result.state == "open":
                    # Run vulnerability checks based on service
                    vulns = await self._check_service_vulnerabilities(
                        host_ip, port, port_result
                    )
                    
                    if vulns:
                        port_result.script_results['vulnerability-scan'] = vulns
    
    async def _check_service_vulnerabilities(self, host: str, port: int, 
                                           port_result: PortResult) -> List[str]:
        """Check for common vulnerabilities based on service"""
        vulnerabilities = []
        
        service = port_result.service
        version = port_result.version or ''
        
        # SSH vulnerabilities
        if service == 'ssh':
            if 'SSH 1.' in version or 'SSH-1.' in version:
                vulnerabilities.append('SSH Protocol 1 enabled (CVE-2001-0361)')
            if 'OpenSSH 7.2' in version:
                vulnerabilities.append('OpenSSH 7.2 username enumeration (CVE-2016-6210)')
        
        # HTTP vulnerabilities
        elif service == 'http':
            # Check for outdated web servers
            if 'Apache/2.2' in version:
                vulnerabilities.append('Apache 2.2.x is EOL and may have unpatched vulnerabilities')
            elif 'nginx/1.0' in version:
                vulnerabilities.append('nginx 1.0.x is outdated')
            elif 'IIS/6.0' in version:
                vulnerabilities.append('IIS 6.0 has multiple known vulnerabilities')
            
            # Check for common paths
            common_paths = ['/.git/', '/.env', '/wp-admin/', '/phpmyadmin/']
            for path in common_paths:
                if await self._check_http_path(host, port, path):
                    vulnerabilities.append(f'Sensitive path exposed: {path}')
        
        # FTP vulnerabilities
        elif service == 'ftp':
            # Check anonymous login
            if await self._check_ftp_anonymous(host, port):
                vulnerabilities.append('FTP anonymous login allowed')
        
        # Database vulnerabilities
        elif service in ['mysql', 'postgresql', 'mongodb', 'redis']:
            vulnerabilities.append(f'{service} may be using default credentials')
        
        return vulnerabilities
    
    async def _check_http_path(self, host: str, port: int, path: str) -> bool:
        """Check if HTTP path exists"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2.0
            )
            
            request = f"HEAD {path} HTTP/1.0\r\nHost: {host}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            
            # Check if path exists (2xx, 3xx, or 403 response)
            response_str = response.decode('utf-8', errors='ignore')
            if 'HTTP/1.' in response_str:
                status_code = int(response_str.split()[1])
                return status_code in range(200, 400) or status_code == 403
                
        except Exception:
            pass
        
        return False
    
    async def _check_ftp_anonymous(self, host: str, port: int) -> bool:
        """Check if FTP allows anonymous login"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3.0
            )
            
            # Read banner
            await asyncio.wait_for(reader.readline(), timeout=2.0)
            
            # Try anonymous login
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            
            response = await asyncio.wait_for(reader.readline(), timeout=2.0)
            
            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            
            # Check if anonymous login is allowed (331 response)
            return b'331' in response
            
        except Exception:
            pass
        
        return False


def timing_template_args(template: TimingTemplate) -> Dict[str, any]:
    """Get timing arguments for a template"""
    templates = {
        TimingTemplate.PARANOID: {
            'scan_delay': 300,
            'max_retries': 0,
            'parallelism': 1,
            'max_rtt_timeout': 300,
        },
        TimingTemplate.SNEAKY: {
            'scan_delay': 15,
            'max_retries': 1,
            'parallelism': 1,
            'max_rtt_timeout': 150,
        },
        TimingTemplate.POLITE: {
            'scan_delay': 0.4,
            'max_retries': 1,
            'parallelism': 10,
            'max_rtt_timeout': 100,
        },
        TimingTemplate.NORMAL: {
            'scan_delay': 0,
            'max_retries': 2,
            'parallelism': 100,
            'initial_rtt_timeout': 1.0,
        },
        TimingTemplate.AGGRESSIVE: {
            'scan_delay': 0,
            'max_scan_delay': 0.01,
            'max_retries': 6,
            'parallelism': 300,
            'min_rtt_timeout': 0.1,
            'max_rtt_timeout': 1.25,
            'initial_rtt_timeout': 0.5,
        },
        TimingTemplate.INSANE: {
            'scan_delay': 0,
            'max_scan_delay': 0.005,
            'max_retries': 2,
            'parallelism': 500,
            'min_rtt_timeout': 0.05,
            'max_rtt_timeout': 0.3,
            'initial_rtt_timeout': 0.25,
            'host_timeout': 900,  # 15 minutes
        },
    }
    
    return templates.get(template, {}) 