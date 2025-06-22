# NetScan Aggressive Scanning Features

NetScan now includes enhanced aggressive scanning capabilities that provide deeper information gathering and vulnerability detection similar to nmap's aggressive mode.

## New Features

### 1. **Enhanced Version Detection**
- Multiple probe strings for better service identification
- Banner grabbing with service-specific probes
- Confidence scoring for service detection
- Support for detecting vulnerable versions

### 2. **Advanced OS Fingerprinting**
- TCP/IP stack fingerprinting
- Analysis of TTL values, window sizes, and TCP options
- ICMP probing for additional OS hints
- Confidence-based OS matching

### 3. **Vulnerability Scanning**
- Automatic detection of common vulnerabilities
- Service-specific vulnerability checks
- CVE identification where applicable
- Security header analysis for web services

### 4. **Script Scanning**
- Default vulnerability scripts
- Service-specific security checks
- Anonymous FTP detection
- SSL/TLS vulnerability detection
- Default credential warnings

## Usage

### Basic Aggressive Scan
```bash
# Use -A flag for aggressive scanning (similar to nmap)
netscan -A scanme.nmap.org

# This enables:
# - Version detection (-sV)
# - OS detection (-O)
# - Script scanning (-sC)
# - Traceroute (--traceroute)
```

### Custom Aggressive Scan
```bash
# Aggressive timing with specific ports
netscan -T4 -sV -O -sC -p 1-10000 192.168.1.0/24

# Fast aggressive scan of top ports
netscan -A -F target.com
```

## Enhanced Information Gathering

### Service Detection Probes
The scanner now sends multiple probe types to identify services:
- Empty probes for services that respond immediately
- HTTP requests for web services
- Service-specific handshakes (SSH, FTP, SMTP, etc.)
- Binary probes for database services

### Vulnerability Detection
Automatically checks for:
- **SSH**: Protocol 1 support, vulnerable versions
- **HTTP**: Missing security headers, outdated servers, exposed paths
- **FTP**: Anonymous login
- **SMTP**: Open relay indicators
- **SSL/TLS**: Weak protocols, expired certificates
- **Databases**: Default credentials warnings

### OS Fingerprinting
Uses multiple techniques:
- TCP SYN/ACK analysis
- TCP options fingerprinting
- Window size analysis
- TTL value checking
- ICMP response behavior

## Output Examples

### Vulnerability Output
```
PORT      STATE     SERVICE     VERSION
22/tcp    open      ssh         SSH 2.0 (OpenSSH_7.2p2)
    |_vulnerability-scan: 
      - OpenSSH 7.2 username enumeration (CVE-2016-6210)
80/tcp    open      http        Apache 2.2.34
    |_vulns:
      - Apache 2.2.x (EOL)
      - Missing X-Frame-Options header
      - Missing X-Content-Type-Options header
```

### OS Detection Output
```
OS details:
  Windows 10 (95%)
  Windows 7/8 (88%)
  Windows Server 2016/2019 (85%)
```

## Performance Considerations

Aggressive scanning is more thorough but:
- Sends more packets (higher chance of detection)
- Takes longer to complete
- Uses more bandwidth
- May trigger IDS/IPS systems

## Timing Templates

- **T0 (Paranoid)**: 5 min between packets
- **T1 (Sneaky)**: 15 sec between packets
- **T2 (Polite)**: 0.4 sec between packets
- **T3 (Normal)**: Default timing
- **T4 (Aggressive)**: Fast timing, parallel scanning
- **T5 (Insane)**: Fastest timing, may miss results

## Best Practices

1. **Permission**: Always have permission before scanning
2. **Start Small**: Test on single hosts before scanning networks
3. **Monitor Impact**: Watch for service disruption
4. **Use Appropriate Timing**: Balance speed vs stealth
5. **Review Results**: Manually verify detected vulnerabilities

## Example Commands

```bash
# Full aggressive scan with output
netscan -A -oA myscan 192.168.1.1

# Aggressive scan with custom timing
netscan -T4 -A --top-ports 1000 10.0.0.0/24

# Service version detection only
netscan -sV --version-intensity 9 target.com

# OS detection with script scanning
netscan -O -sC target.com

# Fast aggressive scan
netscan -A -F --max-rtt-timeout 100ms target.com
```

## Technical Details

### Probe Sequences
1. TCP SYN to identify open ports
2. Service-specific probes for version detection
3. OS fingerprinting probes
4. Vulnerability-specific checks

### Data Sources
- Port-based service identification
- Banner analysis with regex matching
- TCP/IP behavior analysis
- Known vulnerability patterns

### Integration
All aggressive features are integrated into the core scanner and can be combined with other options like decoys, fragmentation, and custom timing. 