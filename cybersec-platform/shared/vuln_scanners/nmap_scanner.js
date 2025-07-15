const { spawn } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');
const xml2js = require('xml2js');
const EventEmitter = require('events');

/**
 * Nmap Scanner Utility
 * Provides comprehensive network scanning capabilities with proper error handling
 */
class NmapScanner extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = {
      timeout: options.timeout || 300000, // 5 minutes default
      outputDir: options.outputDir || './scans',
      nmapPath: options.nmapPath || 'nmap',
      maxConcurrent: options.maxConcurrent || 3,
      ...options
    };
    
    this.currentScans = new Map();
    this.scanCounter = 0;
    
    // Ensure output directory exists
    if (!fs.existsSync(this.options.outputDir)) {
      fs.mkdirSync(this.options.outputDir, { recursive: true });
    }
  }

  /**
   * Validate target format
   * @param {string} target - Target to validate
   * @returns {boolean} - True if valid
   */
  validateTarget(target) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
    
    return ipRegex.test(target) || domainRegex.test(target) || cidrRegex.test(target);
  }

  /**
   * Build Nmap command arguments
   * @param {Object} config - Scan configuration
   * @returns {Array} - Command arguments
   */
  buildNmapArgs(config) {
    const args = [];
    
    // Basic scan type
    switch (config.scanType) {
      case 'tcp_syn':
        args.push('-sS');
        break;
      case 'tcp_connect':
        args.push('-sT');
        break;
      case 'udp':
        args.push('-sU');
        break;
      case 'comprehensive':
        args.push('-sS', '-sU', '-sC', '-sV', '-O');
        break;
      default:
        args.push('-sS');
    }
    
    // Port specification
    if (config.ports) {
      args.push('-p', config.ports);
    }
    
    // Timing template
    if (config.timing) {
      args.push(`-T${config.timing}`);
    } else {
      args.push('-T4'); // Default aggressive timing
    }
    
    // Service detection
    if (config.serviceDetection) {
      args.push('-sV');
    }
    
    // OS detection
    if (config.osDetection) {
      args.push('-O');
    }
    
    // Script scanning
    if (config.scriptScan) {
      args.push('-sC');
    }
    
    // Custom scripts
    if (config.scripts && config.scripts.length > 0) {
      args.push('--script', config.scripts.join(','));
    }
    
    // Vulnerability scripts
    if (config.vulnScripts) {
      args.push('--script', 'vuln');
    }
    
    // Output format
    const outputFile = path.join(this.options.outputDir, `scan_${config.scanId}`);
    args.push('-oX', `${outputFile}.xml`);
    args.push('-oN', `${outputFile}.txt`);
    
    // Additional options
    if (config.skipHostDiscovery) {
      args.push('-Pn');
    }
    
    if (config.fragmentPackets) {
      args.push('-f');
    }
    
    if (config.decoyIps && config.decoyIps.length > 0) {
      args.push('-D', config.decoyIps.join(','));
    }
    
    if (config.sourcePort) {
      args.push('--source-port', config.sourcePort);
    }
    
    if (config.maxRetries) {
      args.push('--max-retries', config.maxRetries);
    }
    
    if (config.minRate) {
      args.push('--min-rate', config.minRate);
    }
    
    if (config.maxRate) {
      args.push('--max-rate', config.maxRate);
    }
    
    // Verbosity
    if (config.verbose) {
      args.push('-v');
    }
    
    // Target
    args.push(config.target);
    
    return args;
  }

  /**
   * Start a new scan
   * @param {Object} config - Scan configuration
   * @returns {Promise} - Scan promise
   */
  async startScan(config) {
    if (!config.target) {
      throw new Error('Target is required');
    }
    
    if (!this.validateTarget(config.target)) {
      throw new Error('Invalid target format');
    }
    
    if (this.currentScans.size >= this.options.maxConcurrent) {
      throw new Error('Maximum concurrent scans reached');
    }
    
    const scanId = config.scanId || `scan_${++this.scanCounter}_${Date.now()}`;
    const args = this.buildNmapArgs({ ...config, scanId });
    
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      let stdout = '';
      let stderr = '';
      
      const child = spawn(this.options.nmapPath, args);
      
      // Store scan info
      this.currentScans.set(scanId, {
        process: child,
        config,
        startTime,
        status: 'running'
      });
      
      // Handle stdout
      child.stdout.on('data', (data) => {
        stdout += data.toString();
        this.emit('progress', {
          scanId,
          output: data.toString(),
          timestamp: Date.now()
        });
      });
      
      // Handle stderr
      child.stderr.on('data', (data) => {
        stderr += data.toString();
        this.emit('error', {
          scanId,
          error: data.toString(),
          timestamp: Date.now()
        });
      });
      
      // Handle process exit
      child.on('close', async (code) => {
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        this.currentScans.delete(scanId);
        
        if (code === 0) {
          try {
            const results = await this.parseScanResults(scanId);
            
            this.emit('complete', {
              scanId,
              results,
              duration,
              timestamp: endTime
            });
            
            resolve({
              scanId,
              status: 'completed',
              results,
              duration,
              stdout,
              stderr
            });
          } catch (parseError) {
            this.emit('error', {
              scanId,
              error: parseError.message,
              timestamp: Date.now()
            });
            
            reject(parseError);
          }
        } else {
          const error = new Error(`Nmap process exited with code ${code}`);
          error.code = code;
          error.stderr = stderr;
          
          this.emit('failed', {
            scanId,
            error: error.message,
            code,
            timestamp: Date.now()
          });
          
          reject(error);
        }
      });
      
      // Handle timeout
      const timeoutHandle = setTimeout(() => {
        child.kill('SIGTERM');
        
        const error = new Error('Scan timeout');
        error.code = 'TIMEOUT';
        
        this.emit('timeout', {
          scanId,
          error: error.message,
          timestamp: Date.now()
        });
        
        reject(error);
      }, this.options.timeout);
      
      child.on('close', () => {
        clearTimeout(timeoutHandle);
      });
    });
  }

  /**
   * Parse scan results from XML output
   * @param {string} scanId - Scan ID
   * @returns {Promise<Object>} - Parsed results
   */
  async parseScanResults(scanId) {
    const xmlFile = path.join(this.options.outputDir, `scan_${scanId}.xml`);
    
    if (!fs.existsSync(xmlFile)) {
      throw new Error('XML output file not found');
    }
    
    const xmlData = fs.readFileSync(xmlFile, 'utf8');
    const parser = new xml2js.Parser();
    const parseXml = promisify(parser.parseString);
    
    try {
      const result = await parseXml(xmlData);
      return this.processXmlResults(result);
    } catch (error) {
      throw new Error(`Failed to parse XML results: ${error.message}`);
    }
  }

  /**
   * Process XML results into structured format
   * @param {Object} xmlResult - Parsed XML
   * @returns {Object} - Structured results
   */
  processXmlResults(xmlResult) {
    const nmaprun = xmlResult.nmaprun;
    const results = {
      summary: {
        command: nmaprun.$.args,
        version: nmaprun.$.version,
        startTime: new Date(parseInt(nmaprun.$.startstr) * 1000),
        endTime: new Date(parseInt(nmaprun.runstats[0].finished[0].$.time) * 1000),
        totalHosts: 0,
        hostsUp: 0,
        hostsDown: 0,
        totalPorts: 0,
        openPorts: 0,
        closedPorts: 0,
        filteredPorts: 0
      },
      hosts: [],
      scanInfo: {}
    };
    
    // Process scan info
    if (nmaprun.scaninfo) {
      nmaprun.scaninfo.forEach(info => {
        results.scanInfo[info.$.type] = {
          protocol: info.$.protocol,
          numservices: parseInt(info.$.numservices),
          services: info.$.services
        };
      });
    }
    
    // Process hosts
    if (nmaprun.host) {
      nmaprun.host.forEach(host => {
        const hostResult = this.processHostResult(host);
        results.hosts.push(hostResult);
        
        // Update summary
        results.summary.totalHosts++;
        if (hostResult.status === 'up') {
          results.summary.hostsUp++;
        } else {
          results.summary.hostsDown++;
        }
        
        // Update port counts
        hostResult.ports.forEach(port => {
          results.summary.totalPorts++;
          switch (port.state) {
            case 'open':
              results.summary.openPorts++;
              break;
            case 'closed':
              results.summary.closedPorts++;
              break;
            case 'filtered':
              results.summary.filteredPorts++;
              break;
          }
        });
      });
    }
    
    return results;
  }

  /**
   * Process individual host result
   * @param {Object} host - Host XML object
   * @returns {Object} - Processed host
   */
  processHostResult(host) {
    const hostResult = {
      addresses: [],
      hostnames: [],
      status: 'unknown',
      ports: [],
      os: {},
      scripts: [],
      uptime: null,
      distance: null
    };
    
    // Process addresses
    if (host.address) {
      host.address.forEach(addr => {
        hostResult.addresses.push({
          addr: addr.$.addr,
          addrtype: addr.$.addrtype,
          vendor: addr.$.vendor || null
        });
      });
    }
    
    // Process hostnames
    if (host.hostnames && host.hostnames[0].hostname) {
      host.hostnames[0].hostname.forEach(hostname => {
        hostResult.hostnames.push({
          name: hostname.$.name,
          type: hostname.$.type
        });
      });
    }
    
    // Process status
    if (host.status) {
      hostResult.status = host.status[0].$.state;
    }
    
    // Process ports
    if (host.ports && host.ports[0].port) {
      host.ports[0].port.forEach(port => {
        const portResult = {
          portid: parseInt(port.$.portid),
          protocol: port.$.protocol,
          state: port.state[0].$.state,
          reason: port.state[0].$.reason,
          service: {},
          scripts: []
        };
        
        // Process service
        if (port.service) {
          const service = port.service[0].$;
          portResult.service = {
            name: service.name,
            product: service.product || null,
            version: service.version || null,
            extrainfo: service.extrainfo || null,
            method: service.method || null,
            conf: service.conf || null
          };
        }
        
        // Process scripts
        if (port.script) {
          port.script.forEach(script => {
            portResult.scripts.push({
              id: script.$.id,
              output: script.$.output,
              elements: script.elem || []
            });
          });
        }
        
        hostResult.ports.push(portResult);
      });
    }
    
    // Process OS detection
    if (host.os && host.os[0].osmatch) {
      host.os[0].osmatch.forEach(osmatch => {
        hostResult.os = {
          name: osmatch.$.name,
          accuracy: parseInt(osmatch.$.accuracy),
          line: osmatch.$.line
        };
      });
    }
    
    // Process host scripts
    if (host.hostscript && host.hostscript[0].script) {
      host.hostscript[0].script.forEach(script => {
        hostResult.scripts.push({
          id: script.$.id,
          output: script.$.output,
          elements: script.elem || []
        });
      });
    }
    
    return hostResult;
  }

  /**
   * Cancel a running scan
   * @param {string} scanId - Scan ID to cancel
   * @returns {boolean} - True if cancelled
   */
  cancelScan(scanId) {
    const scan = this.currentScans.get(scanId);
    
    if (!scan) {
      return false;
    }
    
    scan.process.kill('SIGTERM');
    scan.status = 'cancelled';
    
    this.emit('cancelled', {
      scanId,
      timestamp: Date.now()
    });
    
    return true;
  }

  /**
   * Get scan status
   * @param {string} scanId - Scan ID
   * @returns {Object|null} - Scan status
   */
  getScanStatus(scanId) {
    const scan = this.currentScans.get(scanId);
    
    if (!scan) {
      return null;
    }
    
    return {
      scanId,
      status: scan.status,
      startTime: scan.startTime,
      duration: Date.now() - scan.startTime,
      target: scan.config.target,
      scanType: scan.config.scanType
    };
  }

  /**
   * Get all active scans
   * @returns {Array} - Active scans
   */
  getActiveScans() {
    return Array.from(this.currentScans.keys()).map(scanId => {
      return this.getScanStatus(scanId);
    });
  }

  /**
   * Clean up old scan files
   * @param {number} maxAge - Maximum age in milliseconds
   */
  cleanupOldScans(maxAge = 7 * 24 * 60 * 60 * 1000) { // 7 days default
    const cutoffTime = Date.now() - maxAge;
    
    fs.readdirSync(this.options.outputDir).forEach(file => {
      const filePath = path.join(this.options.outputDir, file);
      const stats = fs.statSync(filePath);
      
      if (stats.mtime.getTime() < cutoffTime) {
        fs.unlinkSync(filePath);
      }
    });
  }

  /**
   * Get scan results by ID
   * @param {string} scanId - Scan ID
   * @returns {Object|null} - Scan results
   */
  async getScanResults(scanId) {
    try {
      return await this.parseScanResults(scanId);
    } catch (error) {
      return null;
    }
  }

  /**
   * Generate vulnerability report from scan results
   * @param {Object} results - Scan results
   * @returns {Object} - Vulnerability report
   */
  generateVulnerabilityReport(results) {
    const vulnerabilities = [];
    
    results.hosts.forEach(host => {
      host.ports.forEach(port => {
        if (port.state === 'open') {
          port.scripts.forEach(script => {
            if (script.id.includes('vuln') || script.output.toLowerCase().includes('vulnerability')) {
              vulnerabilities.push({
                host: host.addresses[0]?.addr || 'unknown',
                port: port.portid,
                protocol: port.protocol,
                service: port.service.name,
                vulnerability: script.id,
                description: script.output,
                severity: this.assessVulnerabilitySeverity(script.output),
                cve: this.extractCVE(script.output),
                solution: this.generateSolution(script.id, script.output)
              });
            }
          });
        }
      });
    });
    
    return {
      summary: {
        totalVulnerabilities: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'critical').length,
        high: vulnerabilities.filter(v => v.severity === 'high').length,
        medium: vulnerabilities.filter(v => v.severity === 'medium').length,
        low: vulnerabilities.filter(v => v.severity === 'low').length
      },
      vulnerabilities
    };
  }

  /**
   * Assess vulnerability severity
   * @param {string} output - Script output
   * @returns {string} - Severity level
   */
  assessVulnerabilitySeverity(output) {
    const lowerOutput = output.toLowerCase();
    
    if (lowerOutput.includes('critical') || lowerOutput.includes('remote code execution')) {
      return 'critical';
    } else if (lowerOutput.includes('high') || lowerOutput.includes('privilege escalation')) {
      return 'high';
    } else if (lowerOutput.includes('medium') || lowerOutput.includes('information disclosure')) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Extract CVE from output
   * @param {string} output - Script output
   * @returns {Array} - CVE numbers
   */
  extractCVE(output) {
    const cveRegex = /CVE-\d{4}-\d{4,}/g;
    const matches = output.match(cveRegex);
    return matches || [];
  }

  /**
   * Generate solution recommendation
   * @param {string} scriptId - Script ID
   * @param {string} output - Script output
   * @returns {string} - Solution recommendation
   */
  generateSolution(scriptId, output) {
    const solutions = {
      'ssl-cert': 'Update SSL certificate and ensure proper configuration',
      'ssl-ccs-injection': 'Disable SSL/TLS compression and update to latest version',
      'ssl-poodle': 'Disable SSLv3 and enable TLS 1.2 or higher',
      'ssl-heartbleed': 'Update OpenSSL to version 1.0.1g or later',
      'http-slowloris': 'Configure proper connection limits and timeouts',
      'http-csrf': 'Implement proper CSRF protection mechanisms',
      'http-sql-injection': 'Use parameterized queries and input validation',
      'http-xss': 'Implement proper input sanitization and output encoding'
    };
    
    return solutions[scriptId] || 'Review and address the identified security issue';
  }
}

module.exports = NmapScanner;