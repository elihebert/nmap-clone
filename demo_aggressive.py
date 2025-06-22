#!/usr/bin/env python3
"""
Demo script to showcase aggressive scanning features
"""

import asyncio
from netscan.core.scanner import Scanner, ScanOptions, TimingTemplate, ScanType
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

async def demo_aggressive_scan():
    """Demonstrate aggressive scanning capabilities"""
    
    # Create aggressive scan options
    options = ScanOptions()
    options.scan_type = ScanType.TCP_SYN
    options.ports = "22,80,443"  # Known open ports on scanme.nmap.org
    options.timing = TimingTemplate.AGGRESSIVE
    options.version_detection = True
    options.full_version_detection = True  # Enable banner grabbing
    options.os_detection = True
    options.script_scan = True  # Enable vulnerability scanning
    options.max_retries = 2
    options.parallelism = 100
    options.interface = "en0"
    
    # Create scanner
    scanner = Scanner(options)
    
    # Target
    target = "45.33.32.156"  # scanme.nmap.org
    
    console.print(Panel.fit(
        f"[bold cyan]Aggressive Scan Demo[/bold cyan]\n"
        f"Target: {target} (scanme.nmap.org)\n"
        f"Features: Version Detection, OS Fingerprinting, Vulnerability Scanning",
        title="NetScan Enhanced"
    ))
    
    console.print("\n[bold]Starting aggressive scan...[/bold]\n")
    
    # Run scan
    results = await scanner.scan(targets=[target])
    
    # Display results
    for host_ip, host_result in results.items():
        # Create results table
        table = Table(title=f"[bold]Scan Results for {host_ip}[/bold]")
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="magenta")
        
        for port, port_result in sorted(host_result.ports.items()):
            state_style = "green" if port_result.state == "open" else "red"
            table.add_row(
                f"{port}/tcp",
                f"[{state_style}]{port_result.state}[/{state_style}]",
                port_result.service or "unknown",
                port_result.version or ""
            )
        
        console.print(table)
        
        # Show OS detection results
        if host_result.os_matches:
            console.print("\n[bold]OS Detection:[/bold]")
            for os_match in host_result.os_matches[:3]:
                console.print(f"  • {os_match['name']} ([cyan]{os_match['accuracy']}%[/cyan] confidence)")
        
        # Show vulnerabilities for each port
        console.print("\n[bold]Security Analysis:[/bold]")
        vuln_found = False
        
        for port, port_result in sorted(host_result.ports.items()):
            if port_result.state == "open" and port_result.script_results:
                # Check for vulnerability scan results
                if 'vulnerability-scan' in port_result.script_results:
                    vulns = port_result.script_results['vulnerability-scan']
                    if vulns:
                        console.print(f"\n[red]Port {port} - Vulnerabilities:[/red]")
                        for vuln in vulns:
                            console.print(f"  ⚠️  {vuln}")
                        vuln_found = True
                
                # Check for service issues
                if 'vulns' in port_result.script_results:
                    issues = port_result.script_results['vulns']
                    if issues:
                        console.print(f"\n[yellow]Port {port} - Service Issues:[/yellow]")
                        for issue in issues:
                            console.print(f"  ⚡ {issue}")
                        vuln_found = True
        
        if not vuln_found:
            console.print("  ✅ No major vulnerabilities detected")
        
        # Show enhanced service information
        console.print("\n[bold]Enhanced Service Detection:[/bold]")
        for port, port_result in sorted(host_result.ports.items()):
            if port_result.state == "open":
                info = f"  Port {port}: "
                if port_result.service:
                    info += f"{port_result.service}"
                    if port_result.version:
                        info += f" ({port_result.version})"
                else:
                    info += "unknown service"
                console.print(info)

if __name__ == "__main__":
    import sys
    import os
    if sys.platform != 'win32' and os.geteuid() != 0:
        console.print("[bold red]Error:[/bold red] This script requires root privileges for raw packet operations.")
        console.print("Please run with: [cyan]sudo python demo_aggressive.py[/cyan]")
        sys.exit(1)
    
    asyncio.run(demo_aggressive_scan()) 