#!/usr/bin/env python3
"""
Simple test to debug scanning issues
"""

import asyncio
from netscan.core.scanner import Scanner, ScanOptions, ScanType
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

async def test_scan():
    # Create simple scan options
    options = ScanOptions()
    options.scan_type = ScanType.TCP_CONNECT  # Try connect scan instead of SYN
    options.ports = "22,80,443"  # Just a few ports
    options.timing = 3  # Normal timing
    options.interface = "en0"  # Specify interface
    
    # Create scanner
    scanner = Scanner(options)
    
    # Test with IP address
    target = "45.33.32.156"
    
    print(f"Testing scan of {target} on ports {options.ports}")
    
    # Run scan
    results = await scanner.scan(targets=[target])
    
    # Display results
    print(f"\nResults: {len(results)} hosts")
    for host_ip, host_result in results.items():
        print(f"\nHost: {host_ip}")
        print(f"State: {host_result.state}")
        print(f"Ports found: {len(host_result.ports)}")
        
        for port, port_result in sorted(host_result.ports.items()):
            print(f"  Port {port}: {port_result.state} ({port_result.reason})")

if __name__ == "__main__":
    asyncio.run(test_scan()) 