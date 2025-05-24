# NetScan Quick Start Guide

## Installation

### Prerequisites
- Python 3.8 or higher
- Root/Administrator privileges (for raw socket operations)
- pip package manager

### Install from source
```bash
# Clone the repository
git clone https://github.com/yourusername/netscan.git
cd netscan

# Install dependencies
pip install -r requirements.txt

# Install NetScan
pip install -e .
```

### Quick Install
```bash
pip install netscan
```

## Basic Usage

### Command Line Interface

#### Simple TCP SYN Scan
```bash
# Scan a single host
sudo netscan 192.168.1.1

# Scan a network
sudo netscan 192.168.1.0/24

# Scan multiple targets
sudo netscan 192.168.1.1 192.168.1.2 scanme.nmap.org
```

#### Port Specification
```bash
# Scan specific ports
sudo netscan -p 22,80,443 192.168.1.1

# Scan port ranges
sudo netscan -p 1-1000 192.168.1.1

# Scan top 100 ports
sudo netscan -F 192.168.1.1

# Scan top 1000 ports
sudo netscan --top-ports 1000 192.168.1.1
```

#### Scan Types
```bash
# TCP SYN scan (default, requires root)
sudo netscan -sS 192.168.1.1

# TCP Connect scan (no root required)
netscan -sT 192.168.1.1

# UDP scan
sudo netscan -sU 192.168.1.1

# TCP ACK scan (firewall detection)
sudo netscan -sA 192.168.1.1

# Ping scan only (no port scan)
sudo netscan -sn 192.168.1.0/24
```

#### Timing and Performance
```bash
# Aggressive timing (fast)
sudo netscan -T4 192.168.1.0/24

# Insane timing (fastest, may miss ports)
sudo netscan -T5 192.168.1.0/24

# Polite timing (slow, less intrusive)
sudo netscan -T2 192.168.1.0/24

# Custom timing options
sudo netscan --min-rate 300 --max-retries 1 192.168.1.1
```

#### Service and OS Detection
```bash
# Service version detection
sudo netscan -sV 192.168.1.1

# OS detection
sudo netscan -O 192.168.1.1

# Aggressive scan (OS + version + scripts + traceroute)
sudo netscan -A 192.168.1.1
```

#### Output Options
```bash
# Save to normal format
sudo netscan -oN scan.txt 192.168.1.1

# Save to XML format
sudo netscan -oX scan.xml 192.168.1.1

# Save to all formats
sudo netscan -oA scan_results 192.168.1.1
```

### Web Interface

Start the web UI:
```bash
netscan --web-ui
```

Then open your browser to: http://localhost:8080

### Python API

```python
import asyncio
from netscan.core.scanner import Scanner, ScanOptions, ScanType

async def scan_network():
    # Configure scan options
    options = ScanOptions(
        scan_type=ScanType.TCP_SYN,
        ports="80,443,22",
        timing=TimingTemplate.AGGRESSIVE,
        version_detection=True
    )
    
    # Create scanner
    scanner = Scanner(options)
    
    # Run scan
    results = await scanner.scan(["192.168.1.0/24"])
    
    # Process results
    for ip, host in results.items():
        print(f"\nHost: {ip}")
        for port, port_info in host.ports.items():
            if port_info.state == "open":
                print(f"  Port {port}: {port_info.service or 'unknown'}")

# Run the scan
asyncio.run(scan_network())
```

## Common Use Cases

### Network Discovery
```bash
# Find all live hosts on network
sudo netscan -sn 192.168.1.0/24

# Quick scan of common ports
sudo netscan -F 192.168.1.0/24
```

### Security Assessment
```bash
# Comprehensive scan
sudo netscan -A -p- 192.168.1.1

# Stealth scan with decoys
sudo netscan -sS -D RND:10 target.com
```

### Service Inventory
```bash
# Find all web servers
sudo netscan -p 80,443,8080,8443 -sV 192.168.1.0/24

# Find all SSH servers
sudo netscan -p 22 -sV 192.168.1.0/24
```

### Firewall Testing
```bash
# ACK scan to map firewall rules
sudo netscan -sA -p 1-100 target.com

# Fragment packets to bypass filters
sudo netscan -f target.com
```

## Performance Tips

1. **Use Timing Templates**: Start with `-T4` for fast scans
2. **Limit Port Ranges**: Scan only necessary ports
3. **Increase Parallelism**: Use `--min-parallelism 100`
4. **Skip DNS Resolution**: Use `-n` for faster scans
5. **Optimize Retries**: Use `--max-retries 1` for speed

## Troubleshooting

### Permission Denied
- Most scan types require root/admin privileges
- Use `sudo` on Linux/macOS
- Run as Administrator on Windows

### No Results
- Check firewall settings
- Verify network connectivity
- Try different scan types (e.g., `-sT` instead of `-sS`)
- Increase timeouts with `--host-timeout`

### Slow Performance
- Use more aggressive timing (`-T4` or `-T5`)
- Reduce port range
- Increase min-rate: `--min-rate 1000`
- Check network latency

## Security Notice

NetScan is a powerful tool that should only be used on networks you own or have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction. 