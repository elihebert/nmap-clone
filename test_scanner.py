#!/usr/bin/env python3
"""
Test script for NetScan
Demonstrates basic functionality
"""

import asyncio
import sys
from netscan.core.scanner import Scanner, ScanOptions, ScanType, TimingTemplate
from netscan.utils.output import OutputFormatter
from rich.console import Console
from rich.table import Table

console = Console()


async def test_basic_scan():
    """Test basic TCP SYN scan"""
    console.print("\n[bold blue]Testing Basic TCP SYN Scan[/bold blue]")
    
    # Create scanner with default options
    options = ScanOptions(
        scan_type=ScanType.TCP_SYN,
        ports="80,443,22,21,25,3389",
        timing=TimingTemplate.NORMAL
    )
    
    scanner = Scanner(options)
    
    # Scan localhost
    console.print("Scanning localhost (127.0.0.1)...")
    results = await scanner.scan("127.0.0.1")
    
    # Display results
    if results:
        for host_ip, host_result in results.items():
            console.print(f"\nHost: [cyan]{host_ip}[/cyan] - State: [green]{host_result.state}[/green]")
            
            if host_result.ports:
                table = Table(title="Port Scan Results")
                table.add_column("Port", style="cyan")
                table.add_column("State", style="green")
                table.add_column("Reason", style="yellow")
                
                for port_num, port_result in host_result.ports.items():
                    table.add_row(
                        f"{port_num}/tcp",
                        port_result.state,
                        port_result.reason
                    )
                
                console.print(table)
    else:
        console.print("[red]No results found[/red]")


async def test_timing_templates():
    """Test different timing templates"""
    console.print("\n[bold blue]Testing Timing Templates[/bold blue]")
    
    templates = [
        (TimingTemplate.NORMAL, "Normal"),
        (TimingTemplate.AGGRESSIVE, "Aggressive"),
    ]
    
    for template, name in templates:
        console.print(f"\n[yellow]Testing {name} timing...[/yellow]")
        
        options = ScanOptions(
            scan_type=ScanType.TCP_SYN,
            ports="80",
            timing=template
        )
        
        scanner = Scanner(options)
        
        import time
        start = time.time()
        results = await scanner.scan("127.0.0.1")
        elapsed = time.time() - start
        
        console.print(f"Scan completed in [green]{elapsed:.2f}s[/green]")


async def test_output_formats():
    """Test output format generation"""
    console.print("\n[bold blue]Testing Output Formats[/bold blue]")
    
    # Run a scan
    options = ScanOptions(
        scan_type=ScanType.TCP_SYN,
        ports="80,443",
        timing=TimingTemplate.NORMAL
    )
    
    scanner = Scanner(options)
    results = await scanner.scan("127.0.0.1")
    
    if results:
        formatter = OutputFormatter(results, options)
        
        # Save in different formats
        console.print("Saving results in different formats...")
        
        formatter.save_normal("test_output.txt")
        console.print("✓ Normal format saved to test_output.txt")
        
        formatter.save_xml("test_output.xml")
        console.print("✓ XML format saved to test_output.xml")
        
        formatter.save_json("test_output.json")
        console.print("✓ JSON format saved to test_output.json")
        
        formatter.save_html("test_output.html")
        console.print("✓ HTML format saved to test_output.html")


async def main():
    """Run all tests"""
    console.print("[bold green]NetScan Test Suite[/bold green]")
    console.print("=" * 50)
    
    try:
        # Test basic scanning
        await test_basic_scan()
        
        # Test timing templates
        await test_timing_templates()
        
        # Test output formats
        await test_output_formats()
        
        console.print("\n[bold green]All tests completed successfully![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Tests interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Test failed: {str(e)}[/bold red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Check if running as root (required for raw socket operations)
    import os
    if os.geteuid() != 0:
        console.print("[bold red]Warning:[/bold red] This script requires root privileges for raw socket operations")
        console.print("Please run with: sudo python test_scanner.py")
        sys.exit(1)
    
    asyncio.run(main()) 