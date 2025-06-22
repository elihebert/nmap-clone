#!/usr/bin/env python3
"""
Test script for demonstrating aggressive scanning capabilities
"""

import asyncio
from netscan.core.scanner import Scanner, ScanOptions, TimingTemplate, ScanType

async def test_aggressive_scan():
    """Test aggressive scanning features"""
    
    # Create scan options with aggressive settings
    options = ScanOptions()
    options.scan_type = ScanType.TCP_SYN
    options.ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    options.timing = TimingTemplate.AGGRESSIVE
    options.version_detection = True
    options.full_version_detection = True  # Enable banner grabbing
    options.os_detection = True
    options.script_scan = True  # Enable vulnerability scanning
    options.max_retries = 2
    options.parallelism = 200  # Aggressive parallelism
    
    # Create scanner
    scanner = Scanner(options)
    
    # Target to scan (use scanme.nmap.org for testing)
    target = "scanme.nmap.org"
    
    print(f"Starting aggressive scan of {target}")
    print("Features enabled:")
    print("- Enhanced version detection with multiple probes")
    print("- OS fingerprinting")
    print("- Vulnerability scanning")
    print("- Script scanning")
    print()
    
    # Run scan
    results = await scanner.scan(targets=[target])
    
    # Display results
    for host_ip, host_result in results.items():
        print(f"\nHost: {host_ip} ({host_result.hostname or 'unknown'})")
        print(f"State: {host_result.state}")
        
        if host_result.os_matches:
            print("\nOS Detection:")
            for os_match in host_result.os_matches[:3]:
                print(f"  - {os_match['name']} ({os_match['accuracy']}%)")
        
        if host_result.ports:
            print("\nOpen Ports:")
            for port, port_result in sorted(host_result.ports.items()):
                if port_result.state == "open":
                    print(f"  {port}/tcp - {port_result.service or 'unknown'} {port_result.version or ''}")
                    
                    # Display vulnerabilities
                    if port_result.script_results:
                        if 'vulnerability-scan' in port_result.script_results:
                            print("    Vulnerabilities:")
                            for vuln in port_result.script_results['vulnerability-scan']:
                                print(f"      - {vuln}")
                        
                        if 'vulns' in port_result.script_results:
                            print("    Service Issues:")
                            for vuln in port_result.script_results['vulns']:
                                print(f"      - {vuln}")

if __name__ == "__main__":
    print("NetScan Aggressive Scanning Test")
    print("================================")
    asyncio.run(test_aggressive_scan()) 