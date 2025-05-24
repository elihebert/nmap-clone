"""
NetScan Web UI
Modern web interface for network scanning
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import asyncio
import json
import os
import uuid
from datetime import datetime
import threading
import logging
from typing import Dict, List, Optional

from netscan.core.scanner import Scanner, ScanOptions, ScanType, TimingTemplate
from netscan.utils.output import OutputFormatter

app = Flask(__name__)
CORS(app)

# Global scan manager
scan_manager = {}
logger = logging.getLogger(__name__)


class ScanJob:
    """Represents a running scan job"""
    
    def __init__(self, job_id: str, targets: List[str], options: dict):
        self.job_id = job_id
        self.targets = targets
        self.options = options
        self.status = 'queued'
        self.progress = 0
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.error = None
        self.scanner = None
        self.task = None
        
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'job_id': self.job_id,
            'targets': self.targets,
            'status': self.status,
            'progress': self.progress,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'error': self.error,
            'results_count': len(self.results),
            'open_ports': sum(len(h.ports) for h in self.results.values()) if self.results else 0
        }


@app.route('/')
def index():
    """Serve the main web UI"""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetScan - Network Scanner</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios@1.2.0/dist/axios.min.js"></script>
</head>
<body class="bg-gray-100">
    <div id="app" class="min-h-screen">
        <!-- Header -->
        <header class="bg-gray-900 text-white p-4 shadow-lg">
            <div class="container mx-auto flex justify-between items-center">
                <h1 class="text-2xl font-bold flex items-center">
                    <i class="fas fa-network-wired mr-3"></i>
                    NetScan
                </h1>
                <nav class="flex space-x-4">
                    <a href="#" class="hover:text-blue-300 transition" onclick="showSection('scanner')">Scanner</a>
                    <a href="#" class="hover:text-blue-300 transition" onclick="showSection('results')">Results</a>
                    <a href="#" class="hover:text-blue-300 transition" onclick="showSection('dashboard')">Dashboard</a>
                </nav>
            </div>
        </header>

        <!-- Scanner Section -->
        <section id="scanner-section" class="container mx-auto p-6">
            <div class="bg-white rounded-lg shadow-lg p-6">
                <h2 class="text-xl font-semibold mb-4">New Scan</h2>
                
                <form id="scan-form" class="space-y-4">
                    <!-- Targets -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            Target(s)
                        </label>
                        <input type="text" id="targets" 
                               class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                               placeholder="192.168.1.0/24, scanme.nmap.org" required>
                    </div>

                    <!-- Scan Type -->
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                Scan Type
                            </label>
                            <select id="scan-type" 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="syn">TCP SYN Scan</option>
                                <option value="connect">TCP Connect Scan</option>
                                <option value="udp">UDP Scan</option>
                                <option value="ack">TCP ACK Scan</option>
                                <option value="window">TCP Window Scan</option>
                                <option value="null">TCP Null Scan</option>
                                <option value="fin">TCP FIN Scan</option>
                                <option value="xmas">TCP Xmas Scan</option>
                            </select>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">
                                Timing Template
                            </label>
                            <select id="timing" 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="0">Paranoid (0)</option>
                                <option value="1">Sneaky (1)</option>
                                <option value="2">Polite (2)</option>
                                <option value="3" selected>Normal (3)</option>
                                <option value="4">Aggressive (4)</option>
                                <option value="5">Insane (5)</option>
                            </select>
                        </div>
                    </div>

                    <!-- Ports -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            Ports
                        </label>
                        <div class="flex space-x-4">
                            <label class="flex items-center">
                                <input type="radio" name="port-option" value="top" checked 
                                       class="mr-2" onchange="togglePortInput()">
                                Top Ports
                            </label>
                            <input type="number" id="top-ports" value="100" min="1" max="65535"
                                   class="px-3 py-1 border border-gray-300 rounded-md w-24">
                            
                            <label class="flex items-center ml-4">
                                <input type="radio" name="port-option" value="custom" 
                                       class="mr-2" onchange="togglePortInput()">
                                Custom
                            </label>
                            <input type="text" id="custom-ports" placeholder="1-1000,3389,8080"
                                   class="px-3 py-1 border border-gray-300 rounded-md flex-1" disabled>
                        </div>
                    </div>

                    <!-- Additional Options -->
                    <div class="space-y-2">
                        <label class="flex items-center">
                            <input type="checkbox" id="version-detection" class="mr-2">
                            Service Version Detection
                        </label>
                        <label class="flex items-center">
                            <input type="checkbox" id="os-detection" class="mr-2">
                            OS Detection
                        </label>
                        <label class="flex items-center">
                            <input type="checkbox" id="traceroute" class="mr-2">
                            Traceroute
                        </label>
                    </div>

                    <!-- Submit Button -->
                    <button type="submit" 
                            class="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 transition duration-200">
                        <i class="fas fa-search mr-2"></i>
                        Start Scan
                    </button>
                </form>
            </div>

            <!-- Active Scans -->
            <div class="bg-white rounded-lg shadow-lg p-6 mt-6">
                <h2 class="text-xl font-semibold mb-4">Active Scans</h2>
                <div id="active-scans" class="space-y-3">
                    <!-- Active scans will be populated here -->
                </div>
            </div>
        </section>

        <!-- Results Section -->
        <section id="results-section" class="container mx-auto p-6 hidden">
            <div class="bg-white rounded-lg shadow-lg p-6">
                <h2 class="text-xl font-semibold mb-4">Scan Results</h2>
                <div id="results-content">
                    <!-- Results will be populated here -->
                </div>
            </div>
        </section>

        <!-- Dashboard Section -->
        <section id="dashboard-section" class="container mx-auto p-6 hidden">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
                <!-- Stats Cards -->
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-500 text-sm">Total Scans</p>
                            <p class="text-2xl font-bold" id="total-scans">0</p>
                        </div>
                        <i class="fas fa-chart-line text-blue-500 text-3xl"></i>
                    </div>
                </div>
                
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-500 text-sm">Hosts Scanned</p>
                            <p class="text-2xl font-bold" id="hosts-scanned">0</p>
                        </div>
                        <i class="fas fa-server text-green-500 text-3xl"></i>
                    </div>
                </div>
                
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-500 text-sm">Open Ports</p>
                            <p class="text-2xl font-bold" id="open-ports">0</p>
                        </div>
                        <i class="fas fa-door-open text-red-500 text-3xl"></i>
                    </div>
                </div>
                
                <div class="bg-white rounded-lg shadow p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-500 text-sm">Services Found</p>
                            <p class="text-2xl font-bold" id="services-found">0</p>
                        </div>
                        <i class="fas fa-cogs text-purple-500 text-3xl"></i>
                    </div>
                </div>
            </div>

            <!-- Charts -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Port Distribution</h3>
                    <canvas id="port-chart"></canvas>
                </div>
                
                <div class="bg-white rounded-lg shadow p-6">
                    <h3 class="text-lg font-semibold mb-4">Service Distribution</h3>
                    <canvas id="service-chart"></canvas>
                </div>
            </div>
        </section>
    </div>

    <script>
        let activeScans = {};
        let allResults = {};

        // Toggle port input based on selection
        function togglePortInput() {
            const customPorts = document.getElementById('custom-ports');
            const topPorts = document.getElementById('top-ports');
            const isCustom = document.querySelector('input[name="port-option"]:checked').value === 'custom';
            
            customPorts.disabled = !isCustom;
            topPorts.disabled = isCustom;
        }

        // Show section
        function showSection(section) {
            document.querySelectorAll('section').forEach(s => s.classList.add('hidden'));
            document.getElementById(`${section}-section`).classList.remove('hidden');
        }

        // Handle form submission
        document.getElementById('scan-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const targets = document.getElementById('targets').value.split(',').map(t => t.trim());
            const scanType = document.getElementById('scan-type').value;
            const timing = document.getElementById('timing').value;
            const portOption = document.querySelector('input[name="port-option"]:checked').value;
            
            let ports;
            if (portOption === 'top') {
                ports = `top:${document.getElementById('top-ports').value}`;
            } else {
                ports = document.getElementById('custom-ports').value;
            }
            
            const options = {
                scan_type: scanType,
                timing: timing,
                ports: ports,
                version_detection: document.getElementById('version-detection').checked,
                os_detection: document.getElementById('os-detection').checked,
                traceroute: document.getElementById('traceroute').checked
            };
            
            try {
                const response = await axios.post('/api/scan', {
                    targets: targets,
                    options: options
                });
                
                const jobId = response.data.job_id;
                activeScans[jobId] = response.data;
                updateActiveScans();
                
                // Start polling for updates
                pollScanStatus(jobId);
                
                // Clear form
                document.getElementById('scan-form').reset();
                
            } catch (error) {
                alert('Error starting scan: ' + error.message);
            }
        });

        // Update active scans display
        function updateActiveScans() {
            const container = document.getElementById('active-scans');
            
            if (Object.keys(activeScans).length === 0) {
                container.innerHTML = '<p class="text-gray-500">No active scans</p>';
                return;
            }
            
            container.innerHTML = Object.values(activeScans).map(scan => `
                <div class="border rounded-lg p-4 ${scan.status === 'completed' ? 'bg-green-50' : 'bg-blue-50'}">
                    <div class="flex justify-between items-center">
                        <div>
                            <p class="font-semibold">${scan.targets.join(', ')}</p>
                            <p class="text-sm text-gray-600">Status: ${scan.status}</p>
                        </div>
                        <div class="flex items-center space-x-4">
                            ${scan.status === 'running' ? `
                                <div class="relative w-24 h-2 bg-gray-200 rounded">
                                    <div class="absolute h-full bg-blue-500 rounded" 
                                         style="width: ${scan.progress}%"></div>
                                </div>
                                <span class="text-sm">${scan.progress}%</span>
                            ` : ''}
                            ${scan.status === 'completed' ? `
                                <button onclick="viewResults('${scan.job_id}')" 
                                        class="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700">
                                    View Results
                                </button>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `).join('');
        }

        // Poll scan status
        async function pollScanStatus(jobId) {
            try {
                const response = await axios.get(`/api/scan/${jobId}`);
                activeScans[jobId] = response.data;
                updateActiveScans();
                
                if (response.data.status === 'running') {
                    setTimeout(() => pollScanStatus(jobId), 1000);
                } else if (response.data.status === 'completed') {
                    // Fetch full results
                    const resultsResponse = await axios.get(`/api/scan/${jobId}/results`);
                    allResults[jobId] = resultsResponse.data;
                    updateDashboard();
                }
            } catch (error) {
                console.error('Error polling scan status:', error);
            }
        }

        // View results
        function viewResults(jobId) {
            const results = allResults[jobId];
            if (!results) return;
            
            showSection('results');
            
            const container = document.getElementById('results-content');
            container.innerHTML = Object.entries(results.hosts).map(([ip, host]) => {
                if (host.state !== 'up') return '';
                
                const openPorts = Object.entries(host.ports || {})
                    .filter(([_, p]) => p.state === 'open');
                
                return `
                    <div class="mb-6 border rounded-lg p-4">
                        <h3 class="text-lg font-semibold mb-2">
                            ${ip} ${host.hostname ? `(${host.hostname})` : ''}
                        </h3>
                        ${host.mac_address ? `<p class="text-sm text-gray-600">MAC: ${host.mac_address}</p>` : ''}
                        
                        ${openPorts.length > 0 ? `
                            <table class="mt-3 w-full">
                                <thead>
                                    <tr class="border-b">
                                        <th class="text-left py-2">Port</th>
                                        <th class="text-left py-2">State</th>
                                        <th class="text-left py-2">Service</th>
                                        <th class="text-left py-2">Version</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${openPorts.map(([port, info]) => `
                                        <tr class="border-b">
                                            <td class="py-2">${port}/tcp</td>
                                            <td class="py-2">
                                                <span class="px-2 py-1 text-xs rounded bg-green-100 text-green-800">
                                                    ${info.state}
                                                </span>
                                            </td>
                                            <td class="py-2">${info.service || '-'}</td>
                                            <td class="py-2">${info.version || '-'}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        ` : '<p class="text-gray-500 mt-2">No open ports found</p>'}
                        
                        ${host.os_matches && host.os_matches.length > 0 ? `
                            <div class="mt-3">
                                <p class="font-semibold">OS Detection:</p>
                                <ul class="list-disc list-inside">
                                    ${host.os_matches.slice(0, 3).map(os => `
                                        <li>${os.name} (${os.accuracy}%)</li>
                                    `).join('')}
                                </ul>
                            </div>
                        ` : ''}
                    </div>
                `;
            }).join('');
        }

        // Update dashboard
        function updateDashboard() {
            let totalScans = Object.keys(allResults).length;
            let hostsScanned = 0;
            let openPorts = 0;
            let servicesFound = new Set();
            
            Object.values(allResults).forEach(result => {
                Object.entries(result.hosts).forEach(([ip, host]) => {
                    if (host.state === 'up') {
                        hostsScanned++;
                        Object.values(host.ports || {}).forEach(port => {
                            if (port.state === 'open') {
                                openPorts++;
                                if (port.service) {
                                    servicesFound.add(port.service);
                                }
                            }
                        });
                    }
                });
            });
            
            document.getElementById('total-scans').textContent = totalScans;
            document.getElementById('hosts-scanned').textContent = hostsScanned;
            document.getElementById('open-ports').textContent = openPorts;
            document.getElementById('services-found').textContent = servicesFound.size;
        }

        // Initialize
        updateActiveScans();
    </script>
</body>
</html>
    """


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    targets = data.get('targets', [])
    options = data.get('options', {})
    
    # Generate job ID
    job_id = str(uuid.uuid4())
    
    # Create scan job
    job = ScanJob(job_id, targets, options)
    scan_manager[job_id] = job
    
    # Start scan in background
    def run_scan():
        try:
            job.status = 'running'
            job.start_time = datetime.now()
            
            # Create scanner options
            scan_options = ScanOptions()
            if 'scan_type' in options:
                scan_options.scan_type = ScanType(options['scan_type'])
            if 'timing' in options:
                scan_options.timing = TimingTemplate(int(options['timing']))
            if 'ports' in options:
                if options['ports'].startswith('top:'):
                    # Handle top ports
                    n = int(options['ports'][4:])
                    from netscan.cli import get_top_ports
                    scan_options.ports = get_top_ports(n)
                else:
                    scan_options.ports = options['ports']
            
            scan_options.version_detection = options.get('version_detection', False)
            scan_options.os_detection = options.get('os_detection', False)
            scan_options.traceroute = options.get('traceroute', False)
            
            # Create scanner
            job.scanner = Scanner(scan_options)
            
            # Run scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            job.results = loop.run_until_complete(job.scanner.scan(targets))
            
            job.status = 'completed'
            job.progress = 100
            
        except Exception as e:
            job.status = 'failed'
            job.error = str(e)
            logger.exception(f"Scan failed for job {job_id}")
        finally:
            job.end_time = datetime.now()
    
    # Start scan thread
    scan_thread = threading.Thread(target=run_scan)
    scan_thread.start()
    
    return jsonify(job.to_dict())


@app.route('/api/scan/<job_id>', methods=['GET'])
def get_scan_status(job_id):
    """Get scan status"""
    job = scan_manager.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    return jsonify(job.to_dict())


@app.route('/api/scan/<job_id>/results', methods=['GET'])
def get_scan_results(job_id):
    """Get scan results"""
    job = scan_manager.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    if job.status != 'completed':
        return jsonify({'error': 'Scan not completed'}), 400
    
    # Convert results to JSON-serializable format
    results = {
        'job_id': job_id,
        'targets': job.targets,
        'start_time': job.start_time.isoformat() if job.start_time else None,
        'end_time': job.end_time.isoformat() if job.end_time else None,
        'hosts': {}
    }
    
    for host_ip, host_result in job.results.items():
        results['hosts'][host_ip] = {
            'state': host_result.state,
            'hostname': host_result.hostname,
            'mac_address': host_result.mac_address,
            'vendor': host_result.vendor,
            'ports': {
                str(port): {
                    'state': port_result.state,
                    'service': port_result.service,
                    'version': port_result.version,
                    'reason': port_result.reason
                }
                for port, port_result in host_result.ports.items()
            },
            'os_matches': host_result.os_matches,
            'traceroute': host_result.traceroute
        }
    
    return jsonify(results)


@app.route('/api/scan/<job_id>', methods=['DELETE'])
def cancel_scan(job_id):
    """Cancel a running scan"""
    job = scan_manager.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    
    if job.status == 'running' and job.task:
        job.task.cancel()
        job.status = 'cancelled'
    
    return jsonify({'status': 'cancelled'})


@app.route('/api/scans', methods=['GET'])
def list_scans():
    """List all scans"""
    scans = [job.to_dict() for job in scan_manager.values()]
    return jsonify(scans)


def start_web_server(host='0.0.0.0', port=8080):
    """Start the web server"""
    app.run(host=host, port=port, debug=False) 