#!/usr/bin/env python3
"""
NetScan CLI - Command Line Interface
Provides nmap-compatible command line options
"""

import click
import asyncio
import sys
import json
import logging
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint
import time
from datetime import datetime
from typing import List, Optional
import ipaddress

from netscan.core.scanner import Scanner, ScanOptions, ScanType, TimingTemplate, timing_template_args
from netscan.utils.output import OutputFormatter
from netscan.ui.web import start_web_server

console = Console()
logger = logging.getLogger(__name__)


def setup_logging(verbose: int):
    """Setup logging based on verbosity level"""
    if verbose == 0:
        level = logging.WARNING
    elif verbose == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_scan_type(options: dict) -> ScanType:
    """Parse scan type from command options"""
    if options.get('syn_scan'):
        return ScanType.TCP_SYN
    elif options.get('connect_scan'):
        return ScanType.TCP_CONNECT
    elif options.get('ack_scan'):
        return ScanType.TCP_ACK
    elif options.get('window_scan'):
        return ScanType.TCP_WINDOW
    elif options.get('maimon_scan'):
        return ScanType.TCP_MAIMON
    elif options.get('null_scan'):
        return ScanType.TCP_NULL
    elif options.get('fin_scan'):
        return ScanType.TCP_FIN
    elif options.get('xmas_scan'):
        return ScanType.TCP_XMAS
    elif options.get('udp_scan'):
        return ScanType.UDP
    elif options.get('ping_scan'):
        return ScanType.PING
    else:
        return ScanType.TCP_SYN  # Default


def parse_timing_template(timing: str) -> TimingTemplate:
    """Parse timing template"""
    templates = {
        '0': TimingTemplate.PARANOID,
        '1': TimingTemplate.SNEAKY,
        '2': TimingTemplate.POLITE,
        '3': TimingTemplate.NORMAL,
        '4': TimingTemplate.AGGRESSIVE,
        '5': TimingTemplate.INSANE,
        'paranoid': TimingTemplate.PARANOID,
        'sneaky': TimingTemplate.SNEAKY,
        'polite': TimingTemplate.POLITE,
        'normal': TimingTemplate.NORMAL,
        'aggressive': TimingTemplate.AGGRESSIVE,
        'insane': TimingTemplate.INSANE,
    }
    
    return templates.get(timing.lower(), TimingTemplate.NORMAL)


def create_scan_options(ctx_params: dict) -> ScanOptions:
    """Create ScanOptions from click context parameters"""
    options = ScanOptions()
    
    # Set scan type
    options.scan_type = parse_scan_type(ctx_params)
    
    # Set ports
    if ctx_params.get('ports'):
        options.ports = ctx_params['ports']
    elif ctx_params.get('top_ports'):
        # Get top N ports from common ports list
        options.ports = get_top_ports(ctx_params['top_ports'])
    elif ctx_params.get('fast_scan'):
        options.ports = get_top_ports(100)
    
    # Set timing
    if ctx_params.get('timing'):
        template = parse_timing_template(ctx_params['timing'])
        options.timing = template
        # Apply template settings
        template_args = timing_template_args(template)
        for key, value in template_args.items():
            setattr(options, key, value)
    
    # Enable basic service detection by default (port-based identification)
    # This provides service names without the performance cost of banner grabbing
    options.version_detection = True
    
    # Set other options
    if ctx_params.get('max_retries') is not None:
        options.max_retries = ctx_params['max_retries']
    
    if ctx_params.get('host_timeout'):
        options.host_timeout = parse_time(ctx_params['host_timeout'])
    
    if ctx_params.get('scan_delay'):
        options.scan_delay = parse_time(ctx_params['scan_delay'])
    
    if ctx_params.get('max_scan_delay'):
        options.max_scan_delay = parse_time(ctx_params['max_scan_delay'])
    
    if ctx_params.get('min_rate'):
        options.min_rate = ctx_params['min_rate']
    
    if ctx_params.get('max_rate'):
        options.max_rate = ctx_params['max_rate']
    
    if ctx_params.get('min_rtt_timeout'):
        options.min_rtt_timeout = parse_time(ctx_params['min_rtt_timeout'])
    
    if ctx_params.get('max_rtt_timeout'):
        options.max_rtt_timeout = parse_time(ctx_params['max_rtt_timeout'])
    
    if ctx_params.get('initial_rtt_timeout'):
        options.initial_rtt_timeout = parse_time(ctx_params['initial_rtt_timeout'])
    
    if ctx_params.get('parallelism'):
        options.parallelism = ctx_params['parallelism']
    
    if ctx_params.get('defeat_rst_ratelimit'):
        options.defeat_rst_ratelimit = True
    
    if ctx_params.get('defeat_icmp_ratelimit'):
        options.defeat_icmp_ratelimit = True
    
    # The -sV flag explicitly enables full version detection with banner grabbing
    if ctx_params.get('version_detection'):
        options.version_detection = True
        options.full_version_detection = True  # Enable banner grabbing for -sV
    
    if ctx_params.get('os_detection'):
        options.os_detection = True
    
    if ctx_params.get('traceroute'):
        options.traceroute = True
    
    if ctx_params.get('aggressive'):
        options.version_detection = True
        options.full_version_detection = True  # Enable full version detection for aggressive
        options.os_detection = True
        options.traceroute = True
        options.script_scan = True
        # Set aggressive timing if not already specified
        if not ctx_params.get('timing'):
            options.timing = TimingTemplate.AGGRESSIVE
            template_args = timing_template_args(TimingTemplate.AGGRESSIVE)
            for key, value in template_args.items():
                setattr(options, key, value)
    
    if ctx_params.get('ipv6'):
        options.ipv6 = True
    
    if ctx_params.get('fragment'):
        options.fragment_packets = True
    
    if ctx_params.get('mtu'):
        options.mtu = ctx_params['mtu']
    
    if ctx_params.get('decoy'):
        options.decoy_hosts = ctx_params['decoy'].split(',')
    
    if ctx_params.get('source_port'):
        options.source_port = ctx_params['source_port']
    
    if ctx_params.get('interface'):
        options.interface = ctx_params['interface']
    
    if ctx_params.get('spoof_mac'):
        options.spoof_mac = ctx_params['spoof_mac']
    
    return options


def parse_time(time_str: str) -> float:
    """Parse time string with units (ms, s, m, h)"""
    if not time_str:
        return 0
    
    time_str = time_str.strip()
    
    # Check for units
    if time_str.endswith('ms'):
        return float(time_str[:-2]) / 1000
    elif time_str.endswith('s'):
        return float(time_str[:-1])
    elif time_str.endswith('m'):
        return float(time_str[:-1]) * 60
    elif time_str.endswith('h'):
        return float(time_str[:-1]) * 3600
    else:
        # Default to seconds
        return float(time_str)


def get_top_ports(n: int) -> str:
    """Get top N most common ports"""
    # Top ports based on nmap's frequency data
    top_ports = [
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
        143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
        10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
        26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
        5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
        2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
        544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
        7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
        6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
    ]
    
    return ','.join(str(p) for p in top_ports[:n])


def display_banner():
    """Display NetScan banner"""
    banner = """
    ╔═╗ ╦╔═╗╔╦╗╔═╗╔═╗╔═╗╔╗╔
    ║ ║ ║║╣  ║ ╚═╗║  ╠═╣║║║
    ╝ ╩ ╩╚═╝ ╩ ╚═╝╚═╝╩ ╩╝╚╝
    High-Performance Network Scanner
    """
    console.print(Panel(banner, style="bold blue"))


def display_results(results: dict, options: dict):
    """Display scan results in a formatted table"""
    # Create summary
    total_hosts = len(results)
    up_hosts = sum(1 for h in results.values() if h.state == "up")
    total_ports = sum(len(h.ports) for h in results.values())
    open_ports = sum(1 for h in results.values() for p in h.ports.values() if p.state == "open")
    
    # Display summary
    summary = f"""
Scan Summary:
├─ Hosts: {up_hosts}/{total_hosts} up
├─ Ports: {open_ports}/{total_ports} open
└─ Time: {time.time() - options['start_time']:.2f}s
    """
    console.print(Panel(summary, title="[bold]Scan Complete[/bold]", style="green"))
    
    # Display detailed results
    for host_ip, host_result in results.items():
        if host_result.state != "up":
            continue
        
        # Create host table
        table = Table(title=f"[bold]{host_ip}[/bold] ({host_result.hostname or 'unknown'})")
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="magenta")
        table.add_column("Reason", style="dim")
        
        # Sort ports
        sorted_ports = sorted(host_result.ports.items())
        
        for port, port_result in sorted_ports:
            state_style = "green" if port_result.state == "open" else "red" if port_result.state == "closed" else "yellow"
            table.add_row(
                f"{port}/tcp",
                f"[{state_style}]{port_result.state}[/{state_style}]",
                port_result.service or "",
                port_result.version or "",
                port_result.reason
            )
        
        if host_result.ports:
            console.print(table)
            
            # Display vulnerability information for each port
            for port, port_result in sorted_ports:
                if port_result.script_results:
                    # Check for vulnerability scan results
                    if 'vulnerability-scan' in port_result.script_results:
                        vulns = port_result.script_results['vulnerability-scan']
                        if vulns:
                            vuln_text = f"[bold red]Port {port} Vulnerabilities:[/bold red]\n"
                            for vuln in vulns:
                                vuln_text += f"  • {vuln}\n"
                            console.print(Panel(vuln_text.strip(), style="red"))
                    
                    # Check for service-specific vulnerabilities
                    if 'vulns' in port_result.script_results:
                        vulns = port_result.script_results['vulns']
                        if vulns:
                            issue_text = f"[bold yellow]Port {port} Service Issues:[/bold yellow]\n"
                            for vuln in vulns:
                                issue_text += f"  • {vuln}\n"
                            console.print(Panel(issue_text.strip(), style="yellow"))
        
        # Display OS detection results
        if host_result.os_matches:
            os_info = "\n".join([f"  • {os['name']} ({os['accuracy']}%)" for os in host_result.os_matches[:3]])
            console.print(Panel(os_info, title="OS Detection", style="blue"))
        
        # Display traceroute
        if host_result.traceroute:
            trace_info = "\n".join([f"  {hop['ttl']}. {hop['ip']} ({hop['rtt']}ms)" for hop in host_result.traceroute])
            console.print(Panel(trace_info, title="Traceroute", style="cyan"))
        
        console.print()


@click.command()
@click.argument('targets', nargs=-1, required=True)
# Scan type options
@click.option('-sS', '--syn-scan', is_flag=True, help='TCP SYN scan (default)')
@click.option('-sT', '--connect-scan', is_flag=True, help='TCP connect scan')
@click.option('-sA', '--ack-scan', is_flag=True, help='TCP ACK scan')
@click.option('-sW', '--window-scan', is_flag=True, help='TCP Window scan')
@click.option('-sM', '--maimon-scan', is_flag=True, help='TCP Maimon scan')
@click.option('-sN', '--null-scan', is_flag=True, help='TCP Null scan')
@click.option('-sF', '--fin-scan', is_flag=True, help='TCP FIN scan')
@click.option('-sX', '--xmas-scan', is_flag=True, help='TCP Xmas scan')
@click.option('-sU', '--udp-scan', is_flag=True, help='UDP scan')
@click.option('-sn', '--ping-scan', is_flag=True, help='Ping scan - disable port scan')
# Port specification
@click.option('-p', '--ports', help='Port ranges (e.g., 22, 1-65535, U:53,T:21-25)')
@click.option('--top-ports', type=int, help='Scan <number> most common ports')
@click.option('-F', '--fast-scan', is_flag=True, help='Fast mode - Scan top 100 ports')
# Timing and performance
@click.option('-T', '--timing', help='Set timing template (0-5 or paranoid/sneaky/polite/normal/aggressive/insane)')
@click.option('--min-hostgroup', type=int, help='Minimum parallel host scan group size')
@click.option('--max-hostgroup', type=int, help='Maximum parallel host scan group size')
@click.option('--min-parallelism', type=int, help='Minimum number of parallel probes')
@click.option('--max-parallelism', '--parallelism', type=int, help='Maximum number of parallel probes')
@click.option('--min-rtt-timeout', help='Minimum RTT timeout')
@click.option('--max-rtt-timeout', help='Maximum RTT timeout')
@click.option('--initial-rtt-timeout', help='Initial RTT timeout')
@click.option('--max-retries', type=int, help='Maximum number of port scan probe retransmissions')
@click.option('--host-timeout', help='Give up on target after this long')
@click.option('--scan-delay', help='Adjust delay between probes')
@click.option('--max-scan-delay', help='Maximum delay between probes')
@click.option('--min-rate', type=int, help='Send packets no slower than <number> per second')
@click.option('--max-rate', type=int, help='Send packets no faster than <number> per second')
@click.option('--defeat-rst-ratelimit', is_flag=True, help='Defeat RST rate limits')
@click.option('--defeat-icmp-ratelimit', is_flag=True, help='Defeat ICMP rate limits')
# Service/version detection
@click.option('-sV', '--version-detection', is_flag=True, help='Probe open ports to determine service/version info')
@click.option('--version-intensity', type=int, help='Set version scan intensity (0-9)')
@click.option('--version-light', is_flag=True, help='Limit to most likely probes (intensity 2)')
@click.option('--version-all', is_flag=True, help='Try every single probe (intensity 9)')
# OS detection
@click.option('-O', '--os-detection', is_flag=True, help='Enable OS detection')
@click.option('--osscan-limit', is_flag=True, help='Limit OS detection to promising targets')
@click.option('--osscan-guess', is_flag=True, help='Guess OS more aggressively')
# Script scan
@click.option('-sC', '--script-scan', is_flag=True, help='Script scan using default scripts')
@click.option('--script', help='Run specified scripts')
# Other options
@click.option('-A', '--aggressive', is_flag=True, help='Enable OS detection, version detection, script scanning, and traceroute')
@click.option('-6', '--ipv6', is_flag=True, help='Enable IPv6 scanning')
@click.option('-v', '--verbose', count=True, help='Increase verbosity level')
@click.option('--traceroute', is_flag=True, help='Trace hop path to each host')
@click.option('-n', '--no-dns', is_flag=True, help='Never do DNS resolution')
@click.option('-R', '--dns-always', is_flag=True, help='Always resolve DNS')
@click.option('--system-dns', is_flag=True, help='Use system DNS resolver')
@click.option('--dns-servers', help='Specify custom DNS servers')
# Firewall/IDS evasion
@click.option('-f', '--fragment', is_flag=True, help='Fragment packets')
@click.option('--mtu', type=int, help='Use specified MTU')
@click.option('-D', '--decoy', help='Cloak scan with decoys')
@click.option('-S', '--source-ip', help='Spoof source address')
@click.option('-e', '--interface', help='Use specified interface')
@click.option('-g', '--source-port', type=int, help='Use given port number')
@click.option('--proxies', help='Relay connections through HTTP/SOCKS4 proxies')
@click.option('--data', help='Append custom payload to sent packets')
@click.option('--data-string', help='Append custom ASCII string to sent packets')
@click.option('--data-length', type=int, help='Append random data to sent packets')
@click.option('--ip-options', help='Send packets with specified ip options')
@click.option('--ttl', type=int, help='Set IP time-to-live field')
@click.option('--spoof-mac', help='Spoof MAC address')
@click.option('--badsum', is_flag=True, help='Send packets with bogus checksums')
# Output options
@click.option('-oN', '--output-normal', help='Output scan in normal format')
@click.option('-oX', '--output-xml', help='Output scan in XML format')
@click.option('-oG', '--output-grepable', help='Output scan in grepable format')
@click.option('-oA', '--output-all', help='Output in all formats')
@click.option('--append-output', is_flag=True, help='Append to rather than clobber output files')
@click.option('--resume', help='Resume aborted scan')
@click.option('--stylesheet', help='XSL stylesheet to transform XML output')
@click.option('--webxml', is_flag=True, help='Reference stylesheet from Nmap.Org')
@click.option('--no-stylesheet', is_flag=True, help='Prevent associating of XSL stylesheet')
# Misc options
@click.option('--datadir', help='Specify custom data file location')
@click.option('--send-eth', is_flag=True, help='Send using raw ethernet frames')
@click.option('--send-ip', is_flag=True, help='Send using raw IP packets')
@click.option('--privileged', is_flag=True, help='Assume user is fully privileged')
@click.option('--unprivileged', is_flag=True, help='Assume user lacks raw socket privileges')
@click.option('--release-memory', is_flag=True, help='Release memory during scan')
@click.option('--web-ui', is_flag=True, help='Start web UI server')
@click.option('--interactive', is_flag=True, help='Start in interactive mode')
@click.pass_context
def main(ctx, **options):
    """
    NetScan - High-Performance Network Scanner
    
    Examples:
      netscan -sS -p- 192.168.1.0/24
      netscan -A -T4 scanme.nmap.org
      netscan -sU -sV --top-ports 1000 192.168.1.1
      netscan -sn 192.168.1.0/24
      netscan --web-ui
    """
    # Display banner
    if not options.get('quiet'):
        display_banner()
    
    # Setup logging
    setup_logging(options.get('verbose', 0))
    
    # Start web UI if requested
    if options.get('web_ui'):
        console.print("[bold green]Starting Web UI server...[/bold green]")
        start_web_server()
        return
    
    # Check if targets provided
    if not options['targets']:
        console.print("[bold red]Error:[/bold red] No targets specified")
        ctx.exit(1)
    
    # Create scan options
    scan_options = create_scan_options(options)
    
    # Record start time
    options['start_time'] = time.time()
    
    # Create scanner
    scanner = Scanner(scan_options)
    
    # Display scan info
    console.print(f"[bold]Starting NetScan[/bold] at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"Scan type: [cyan]{scan_options.scan_type.value}[/cyan]")
    console.print(f"Target(s): [cyan]{', '.join(options['targets'])}[/cyan]")
    console.print(f"Ports: [cyan]{scan_options.ports}[/cyan]")
    console.print()
    
    # Run scan with progress bar
    async def run_scan():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=100)
            
            # Update progress periodically
            async def update_progress():
                while not scan_complete:
                    await asyncio.sleep(0.1)
                    # Update based on scanner state
                    progress.update(task, advance=1)
            
            scan_complete = False
            progress_task = asyncio.create_task(update_progress())
            
            try:
                results = await scanner.scan(
                    targets=list(options['targets']),
                    ports=scan_options.ports if not options.get('ping_scan') else None
                )
                scan_complete = True
                await progress_task
                progress.update(task, completed=100)
                return results
            except Exception as e:
                scan_complete = True
                await progress_task
                raise e
    
    # Run async scan
    try:
        results = asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        logger.exception("Scan failed")
        sys.exit(1)
    
    # Display results
    display_results(results, options)
    
    # Save output if requested
    if options.get('output_normal') or options.get('output_xml') or options.get('output_grepable') or options.get('output_all'):
        formatter = OutputFormatter(results, scan_options)
        
        if options.get('output_normal') or options.get('output_all'):
            filename = options.get('output_normal') or options.get('output_all') + '.nmap'
            formatter.save_normal(filename)
            console.print(f"Normal output saved to: {filename}")
        
        if options.get('output_xml') or options.get('output_all'):
            filename = options.get('output_xml') or options.get('output_all') + '.xml'
            formatter.save_xml(filename)
            console.print(f"XML output saved to: {filename}")
        
        if options.get('output_grepable') or options.get('output_all'):
            filename = options.get('output_grepable') or options.get('output_all') + '.gnmap'
            formatter.save_grepable(filename)
            console.print(f"Grepable output saved to: {filename}")
    
    # Interactive mode
    if options.get('interactive'):
        console.print("\n[bold]Entering interactive mode...[/bold]")
        # Implementation for interactive mode
        pass


if __name__ == '__main__':
    main() 