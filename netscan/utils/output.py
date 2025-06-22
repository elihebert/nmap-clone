"""
Output formatting utilities for NetScan
Supports normal, XML, and grepable output formats
"""

import xml.etree.ElementTree as ET
from xml.dom import minidom
import json
import time
from datetime import datetime
from typing import Dict, List, Optional
import socket
import platform

from netscan.core.scanner import HostResult, PortResult, ScanOptions


class OutputFormatter:
    """Format scan results in various output formats"""
    
    def __init__(self, results: Dict[str, HostResult], options: ScanOptions):
        self.results = results
        self.options = options
        self.start_time = datetime.now()
        self.version = "1.0.0"
        
    def save_normal(self, filename: str):
        """Save results in normal (human-readable) format"""
        with open(filename, 'w') as f:
            # Write header
            f.write(f"# NetScan {self.version} scan initiated {self.start_time}\n")
            f.write(f"# Scan type: {self.options.scan_type.value}\n")
            f.write(f"# Ports: {self.options.ports}\n")
            f.write(f"# Timing: {self.options.timing.name}\n\n")
            
            # Write results for each host
            for host_ip, host_result in self.results.items():
                f.write(f"NetScan scan report for {host_ip}")
                if host_result.hostname:
                    f.write(f" ({host_result.hostname})")
                f.write(f"\n")
                
                if host_result.state == "down":
                    f.write(f"Host is down\n\n")
                    continue
                
                f.write(f"Host is up")
                if host_result.latency:
                    f.write(f" ({host_result.latency:.4f}s latency)")
                f.write(f"\n")
                
                if host_result.mac_address:
                    f.write(f"MAC Address: {host_result.mac_address}")
                    if host_result.vendor:
                        f.write(f" ({host_result.vendor})")
                    f.write(f"\n")
                
                # Port results
                if host_result.ports:
                    f.write(f"PORT      STATE     SERVICE     VERSION\n")
                    
                    for port_num in sorted(host_result.ports.keys()):
                        port = host_result.ports[port_num]
                        proto = "tcp"  # TODO: Detect protocol
                        
                        f.write(f"{port_num}/{proto:<5} {port.state:<9} ")
                        f.write(f"{port.service or '':<11} ")
                        f.write(f"{port.version or ''}\n")
                        
                        # Show script results if any
                        if port.script_results:
                            for script_name, script_output in port.script_results.items():
                                f.write(f"    |_{script_name}: ")
                                if isinstance(script_output, list):
                                    f.write("\n")
                                    for item in script_output:
                                        f.write(f"      - {item}\n")
                                else:
                                    f.write(f"{script_output}\n")
                
                # OS detection results
                if host_result.os_matches:
                    f.write(f"\nOS details:\n")
                    for os_match in host_result.os_matches[:3]:
                        f.write(f"  {os_match['name']} ({os_match['accuracy']}%)\n")
                
                # Traceroute results
                if host_result.traceroute:
                    f.write(f"\nTraceroute:\n")
                    f.write(f"HOP  RTT      ADDRESS\n")
                    for hop in host_result.traceroute:
                        f.write(f"{hop['ttl']:<4} {hop['rtt']:<8} {hop['ip']}\n")
                
                f.write(f"\n")
            
            # Write summary
            total_hosts = len(self.results)
            up_hosts = sum(1 for h in self.results.values() if h.state == "up")
            f.write(f"\n# NetScan done: {total_hosts} IP addresses ({up_hosts} hosts up) scanned\n")
    
    def save_xml(self, filename: str):
        """Save results in XML format"""
        # Create root element
        root = ET.Element('nmaprun')
        root.set('scanner', 'netscan')
        root.set('version', self.version)
        root.set('start', str(int(self.start_time.timestamp())))
        root.set('startstr', self.start_time.strftime('%a %b %d %H:%M:%S %Y'))
        
        # Add scan info
        scaninfo = ET.SubElement(root, 'scaninfo')
        scaninfo.set('type', self.options.scan_type.value)
        scaninfo.set('protocol', 'tcp')  # TODO: Detect protocol
        scaninfo.set('services', self.options.ports)
        
        # Add verbose info
        verbose = ET.SubElement(root, 'verbose')
        verbose.set('level', '0')
        
        # Add debugging info
        debugging = ET.SubElement(root, 'debugging')
        debugging.set('level', '0')
        
        # Add host results
        for host_ip, host_result in self.results.items():
            host_elem = ET.SubElement(root, 'host')
            
            # Status
            status = ET.SubElement(host_elem, 'status')
            status.set('state', host_result.state)
            status.set('reason', 'syn-ack' if host_result.state == 'up' else 'no-response')
            
            # Address
            address = ET.SubElement(host_elem, 'address')
            address.set('addr', host_ip)
            address.set('addrtype', 'ipv4')
            
            if host_result.mac_address:
                mac_address = ET.SubElement(host_elem, 'address')
                mac_address.set('addr', host_result.mac_address)
                mac_address.set('addrtype', 'mac')
                if host_result.vendor:
                    mac_address.set('vendor', host_result.vendor)
            
            # Hostnames
            if host_result.hostname:
                hostnames = ET.SubElement(host_elem, 'hostnames')
                hostname = ET.SubElement(hostnames, 'hostname')
                hostname.set('name', host_result.hostname)
                hostname.set('type', 'user')
            
            # Ports
            if host_result.ports:
                ports_elem = ET.SubElement(host_elem, 'ports')
                
                for port_num in sorted(host_result.ports.keys()):
                    port_result = host_result.ports[port_num]
                    port_elem = ET.SubElement(ports_elem, 'port')
                    port_elem.set('portid', str(port_num))
                    port_elem.set('protocol', 'tcp')  # TODO: Detect protocol
                    
                    state_elem = ET.SubElement(port_elem, 'state')
                    state_elem.set('state', port_result.state)
                    state_elem.set('reason', port_result.reason)
                    if port_result.ttl is not None:
                        state_elem.set('reason_ttl', str(port_result.ttl))
                    
                    if port_result.service:
                        service_elem = ET.SubElement(port_elem, 'service')
                        service_elem.set('name', port_result.service)
                        if port_result.version:
                            service_elem.set('version', port_result.version)
            
            # OS detection
            if host_result.os_matches:
                os_elem = ET.SubElement(host_elem, 'os')
                for os_match in host_result.os_matches:
                    osmatch = ET.SubElement(os_elem, 'osmatch')
                    osmatch.set('name', os_match['name'])
                    osmatch.set('accuracy', str(os_match['accuracy']))
            
            # Traceroute
            if host_result.traceroute:
                trace_elem = ET.SubElement(host_elem, 'trace')
                for hop in host_result.traceroute:
                    hop_elem = ET.SubElement(trace_elem, 'hop')
                    hop_elem.set('ttl', str(hop['ttl']))
                    hop_elem.set('ipaddr', hop['ip'])
                    hop_elem.set('rtt', str(hop['rtt']))
        
        # Add run statistics
        runstats = ET.SubElement(root, 'runstats')
        finished = ET.SubElement(runstats, 'finished')
        finished.set('time', str(int(time.time())))
        finished.set('timestr', datetime.now().strftime('%a %b %d %H:%M:%S %Y'))
        
        hosts_elem = ET.SubElement(runstats, 'hosts')
        total_hosts = len(self.results)
        up_hosts = sum(1 for h in self.results.values() if h.state == "up")
        down_hosts = total_hosts - up_hosts
        hosts_elem.set('up', str(up_hosts))
        hosts_elem.set('down', str(down_hosts))
        hosts_elem.set('total', str(total_hosts))
        
        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent='  ')
        
        with open(filename, 'w') as f:
            f.write(xml_str)
    
    def save_grepable(self, filename: str):
        """Save results in grepable format"""
        with open(filename, 'w') as f:
            # Write header
            f.write(f"# NetScan {self.version} scan initiated {self.start_time}\n")
            
            # Write host results
            for host_ip, host_result in self.results.items():
                if host_result.state == "down":
                    f.write(f"Host: {host_ip} () Status: Down\n")
                    continue
                
                # Build ports string
                ports_list = []
                if host_result.ports:
                    for port_num in sorted(host_result.ports.keys()):
                        port = host_result.ports[port_num]
                        if port.state == "open":
                            service_info = f"{port.service}" if port.service else ""
                            if port.version:
                                service_info += f"/{port.version}"
                            ports_list.append(f"{port_num}/open/tcp//{service_info}//")
                
                ports_str = ", ".join(ports_list) if ports_list else ""
                
                # Write host line
                hostname = f"({host_result.hostname})" if host_result.hostname else "()"
                f.write(f"Host: {host_ip} {hostname} Status: Up\n")
                if ports_str:
                    f.write(f"Host: {host_ip} {hostname} Ports: {ports_str}\n")
                
                # OS detection
                if host_result.os_matches:
                    os_str = host_result.os_matches[0]['name']
                    f.write(f"Host: {host_ip} {hostname} OS: {os_str}\n")
    
    def save_json(self, filename: str):
        """Save results in JSON format (bonus format)"""
        output = {
            'scanner': 'netscan',
            'version': self.version,
            'scan_time': self.start_time.isoformat(),
            'scan_type': self.options.scan_type.value,
            'timing': self.options.timing.name,
            'hosts': {}
        }
        
        for host_ip, host_result in self.results.items():
            host_data = {
                'state': host_result.state,
                'hostname': host_result.hostname,
                'mac_address': host_result.mac_address,
                'vendor': host_result.vendor,
                'latency': host_result.latency,
                'ports': {},
                'os_matches': host_result.os_matches,
                'traceroute': host_result.traceroute
            }
            
            for port_num, port_result in host_result.ports.items():
                host_data['ports'][str(port_num)] = {
                    'state': port_result.state,
                    'service': port_result.service,
                    'version': port_result.version,
                    'reason': port_result.reason,
                    'ttl': port_result.ttl,
                    'window': port_result.window
                }
            
            output['hosts'][host_ip] = host_data
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
    
    def save_html(self, filename: str):
        """Save results as HTML report"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>NetScan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background-color: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .open { color: #4CAF50; font-weight: bold; }
        .closed { color: #f44336; }
        .filtered { color: #ff9800; }
        .host-section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .os-info { background-color: #f0f0f0; padding: 10px; border-radius: 3px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>NetScan Scan Report</h1>
        <div class="summary">
            <p><strong>Scan Time:</strong> {scan_time}</p>
            <p><strong>Scan Type:</strong> {scan_type}</p>
            <p><strong>Timing:</strong> {timing}</p>
            <p><strong>Total Hosts:</strong> {total_hosts} ({up_hosts} up, {down_hosts} down)</p>
        </div>
        {hosts_html}
    </div>
</body>
</html>
        """
        
        hosts_html = ""
        total_hosts = len(self.results)
        up_hosts = sum(1 for h in self.results.values() if h.state == "up")
        down_hosts = total_hosts - up_hosts
        
        for host_ip, host_result in self.results.items():
            if host_result.state != "up":
                continue
                
            host_html = f'<div class="host-section">'
            host_html += f'<h2>{host_ip}'
            if host_result.hostname:
                host_html += f' ({host_result.hostname})'
            host_html += '</h2>'
            
            if host_result.mac_address:
                host_html += f'<p><strong>MAC Address:</strong> {host_result.mac_address}'
                if host_result.vendor:
                    host_html += f' ({host_result.vendor})'
                host_html += '</p>'
            
            if host_result.ports:
                host_html += '<table>'
                host_html += '<tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>'
                
                for port_num in sorted(host_result.ports.keys()):
                    port = host_result.ports[port_num]
                    state_class = port.state.replace('|', '-')
                    host_html += f'<tr>'
                    host_html += f'<td>{port_num}/tcp</td>'
                    host_html += f'<td class="{state_class}">{port.state}</td>'
                    host_html += f'<td>{port.service or "-"}</td>'
                    host_html += f'<td>{port.version or "-"}</td>'
                    host_html += f'</tr>'
                    
                    # Add vulnerability row if found
                    if port.script_results and 'vulnerability-scan' in port.script_results:
                        vulns = port.script_results['vulnerability-scan']
                        if vulns:
                            host_html += '<tr><td colspan="4" style="padding-left: 20px; background-color: #ffebee;">'
                            host_html += '<strong>Vulnerabilities:</strong><br>'
                            for vuln in vulns:
                                host_html += f'• {vuln}<br>'
                            host_html += '</td></tr>'
                    
                    # Add other script results
                    if port.script_results and 'vulns' in port.script_results:
                        vulns = port.script_results['vulns']
                        if vulns:
                            host_html += '<tr><td colspan="4" style="padding-left: 20px; background-color: #fff3e0;">'
                            host_html += '<strong>Service Issues:</strong><br>'
                            for vuln in vulns:
                                host_html += f'• {vuln}<br>'
                            host_html += '</td></tr>'
                
                host_html += '</table>'
            
            if host_result.os_matches:
                host_html += '<div class="os-info">'
                host_html += '<strong>OS Detection:</strong><br>'
                for os_match in host_result.os_matches[:3]:
                    host_html += f'{os_match["name"]} ({os_match["accuracy"]}%)<br>'
                host_html += '</div>'
            
            host_html += '</div>'
            hosts_html += host_html
        
        html_content = html_template.format(
            scan_time=self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            scan_type=self.options.scan_type.value,
            timing=self.options.timing.name,
            total_hosts=total_hosts,
            up_hosts=up_hosts,
            down_hosts=down_hosts,
            hosts_html=hosts_html
        )
        
        with open(filename, 'w') as f:
            f.write(html_content) 