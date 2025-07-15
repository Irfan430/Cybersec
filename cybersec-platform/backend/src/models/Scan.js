const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  // Basic scan information
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  
  // Scan identification
  scanId: {
    type: String,
    unique: true,
    required: true,
    default: function() {
      return 'scan_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
  },
  
  // Target information
  target: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Target',
    required: true
  },
  targetSnapshot: {
    name: String,
    value: String,
    type: String,
    environment: String
  },
  
  // Scan configuration
  scanType: {
    type: String,
    enum: ['nmap', 'nikto', 'nuclei', 'openvas', 'custom', 'full'],
    required: true
  },
  scanMethods: [{
    type: String,
    enum: ['port_scan', 'service_detection', 'vuln_scan', 'brute_force', 'web_scan', 'ssl_scan']
  }],
  
  // Scan parameters
  configuration: {
    ports: {
      type: String,
      default: '1-1000'
    },
    timeout: {
      type: Number,
      default: 300,
      min: 60,
      max: 3600
    },
    intensity: {
      type: String,
      enum: ['light', 'normal', 'aggressive', 'insane'],
      default: 'normal'
    },
    nmapOptions: String,
    niktoOptions: String,
    customScript: String,
    excludeHosts: [String],
    includePorts: [String],
    excludePorts: [String],
    serviceDetection: {
      type: Boolean,
      default: true
    },
    osDetection: {
      type: Boolean,
      default: false
    },
    scriptScan: {
      type: Boolean,
      default: true
    },
    vulnerabilityScripts: {
      type: Boolean,
      default: true
    }
  },
  
  // Scan status and timing
  status: {
    type: String,
    enum: ['pending', 'queued', 'running', 'completed', 'failed', 'cancelled', 'timeout'],
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal'
  },
  
  // Timing information
  scheduledAt: {
    type: Date,
    default: Date.now
  },
  startedAt: Date,
  completedAt: Date,
  duration: Number, // in seconds
  
  // Progress tracking
  progress: {
    percentage: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    currentPhase: {
      type: String,
      enum: ['initializing', 'scanning', 'analyzing', 'reporting', 'completed'],
      default: 'initializing'
    },
    estimatedTimeRemaining: Number, // in seconds
    hostsScanned: {
      type: Number,
      default: 0
    },
    totalHosts: {
      type: Number,
      default: 1
    },
    portsScanned: {
      type: Number,
      default: 0
    },
    totalPorts: {
      type: Number,
      default: 1000
    }
  },
  
  // Scan results
  results: {
    summary: {
      totalHosts: {
        type: Number,
        default: 0
      },
      hostsUp: {
        type: Number,
        default: 0
      },
      hostsDown: {
        type: Number,
        default: 0
      },
      totalPorts: {
        type: Number,
        default: 0
      },
      openPorts: {
        type: Number,
        default: 0
      },
      closedPorts: {
        type: Number,
        default: 0
      },
      filteredPorts: {
        type: Number,
        default: 0
      },
      totalVulnerabilities: {
        type: Number,
        default: 0
      },
      vulnerabilitiesBySeverity: {
        critical: { type: Number, default: 0 },
        high: { type: Number, default: 0 },
        medium: { type: Number, default: 0 },
        low: { type: Number, default: 0 },
        info: { type: Number, default: 0 }
      }
    },
    
    // Host details
    hosts: [{
      ip: String,
      hostname: String,
      status: {
        type: String,
        enum: ['up', 'down', 'filtered'],
        default: 'up'
      },
      lastSeen: Date,
      os: {
        name: String,
        version: String,
        confidence: Number
      },
      ports: [{
        port: Number,
        protocol: {
          type: String,
          enum: ['tcp', 'udp'],
          default: 'tcp'
        },
        state: {
          type: String,
          enum: ['open', 'closed', 'filtered'],
          default: 'closed'
        },
        service: {
          name: String,
          version: String,
          product: String,
          extraInfo: String
        },
        scripts: [{
          name: String,
          output: String,
          elements: mongoose.Schema.Types.Mixed
        }]
      }]
    }],
    
    // Vulnerabilities found
    vulnerabilities: [{
      id: String,
      name: {
        type: String,
        required: true
      },
      description: String,
      severity: {
        type: String,
        enum: ['critical', 'high', 'medium', 'low', 'info'],
        required: true
      },
      cvss: {
        score: Number,
        vector: String,
        version: String
      },
      cve: [String],
      cwe: [String],
      references: [String],
      solution: String,
      host: String,
      port: Number,
      protocol: String,
      service: String,
      evidence: String,
      impact: String,
      confidence: {
        type: String,
        enum: ['certain', 'firm', 'tentative'],
        default: 'firm'
      },
      category: {
        type: String,
        enum: ['network', 'web', 'database', 'system', 'application', 'configuration'],
        default: 'network'
      },
      tags: [String],
      lastSeen: {
        type: Date,
        default: Date.now
      },
      firstSeen: {
        type: Date,
        default: Date.now
      },
      status: {
        type: String,
        enum: ['open', 'fixed', 'accepted', 'false_positive'],
        default: 'open'
      }
    }],
    
    // Raw scan output
    rawOutput: {
      nmap: String,
      nikto: String,
      nuclei: String,
      custom: String
    },
    
    // Screenshots for web scans
    screenshots: [{
      url: String,
      path: String,
      timestamp: {
        type: Date,
        default: Date.now
      }
    }],
    
    // SSL/TLS information
    ssl: [{
      host: String,
      port: Number,
      certificate: {
        issuer: String,
        subject: String,
        validFrom: Date,
        validTo: Date,
        fingerprint: String,
        algorithm: String,
        keySize: Number
      },
      protocols: [String],
      ciphers: [String],
      vulnerabilities: [String]
    }]
  },
  
  // Risk assessment
  riskAssessment: {
    overallRisk: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low', 'minimal'],
      default: 'minimal'
    },
    riskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    factors: [{
      name: String,
      value: String,
      weight: Number,
      impact: String
    }],
    recommendations: [String],
    aiPrediction: {
      threatProbability: Number,
      nextScanRecommendation: String,
      priorityActions: [String]
    }
  },
  
  // Compliance mapping
  compliance: {
    frameworks: [{
      name: String,
      requirements: [String],
      status: {
        type: String,
        enum: ['compliant', 'non-compliant', 'partial'],
        default: 'partial'
      }
    }],
    gaps: [String],
    recommendations: [String]
  },
  
  // Error handling
  errors: [{
    phase: String,
    message: String,
    code: String,
    timestamp: {
      type: Date,
      default: Date.now
    },
    severity: {
      type: String,
      enum: ['error', 'warning', 'info'],
      default: 'error'
    }
  }],
  
  // Scan metadata
  metadata: {
    initiatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    scannerVersion: String,
    scannerNode: String,
    scannerIP: String,
    environment: String,
    isScheduled: {
      type: Boolean,
      default: false
    },
    parentScan: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan'
    },
    childScans: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Scan'
    }],
    tags: [String],
    notes: String
  },
  
  // Notifications
  notifications: {
    sent: [{
      type: {
        type: String,
        enum: ['email', 'telegram', 'slack', 'webhook'],
        required: true
      },
      recipient: String,
      sentAt: {
        type: Date,
        default: Date.now
      },
      status: {
        type: String,
        enum: ['sent', 'failed', 'pending'],
        default: 'pending'
      },
      message: String
    }],
    alertTriggered: {
      type: Boolean,
      default: false
    },
    criticalFindings: {
      type: Boolean,
      default: false
    }
  },
  
  // Audit trail
  isActive: {
    type: Boolean,
    default: true
  },
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedAt: Date,
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
scanSchema.index({ scanId: 1 });
scanSchema.index({ target: 1 });
scanSchema.index({ status: 1 });
scanSchema.index({ 'metadata.initiatedBy': 1 });
scanSchema.index({ scheduledAt: 1 });
scanSchema.index({ startedAt: 1 });
scanSchema.index({ completedAt: 1 });
scanSchema.index({ priority: 1 });
scanSchema.index({ isActive: 1, isDeleted: 1 });

// Compound indexes
scanSchema.index({ target: 1, status: 1 });
scanSchema.index({ 'metadata.initiatedBy': 1, status: 1 });
scanSchema.index({ status: 1, priority: 1 });

// Virtual for scan duration in human readable format
scanSchema.virtual('durationFormatted').get(function() {
  if (!this.duration) return 'N/A';
  
  const hours = Math.floor(this.duration / 3600);
  const minutes = Math.floor((this.duration % 3600) / 60);
  const seconds = this.duration % 60;
  
  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  } else {
    return `${seconds}s`;
  }
});

// Virtual for risk color
scanSchema.virtual('riskColor').get(function() {
  const risk = this.riskAssessment.overallRisk;
  const colors = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#d97706',
    low: '#65a30d',
    minimal: '#059669'
  };
  return colors[risk] || '#6b7280';
});

// Virtual for completion percentage
scanSchema.virtual('completionPercentage').get(function() {
  if (this.status === 'completed') return 100;
  if (this.status === 'failed' || this.status === 'cancelled') return 0;
  return this.progress.percentage;
});

// Pre-save middleware to calculate duration
scanSchema.pre('save', function(next) {
  if (this.startedAt && this.completedAt) {
    this.duration = Math.floor((this.completedAt - this.startedAt) / 1000);
  }
  
  // Update progress based on status
  if (this.status === 'completed') {
    this.progress.percentage = 100;
    this.progress.currentPhase = 'completed';
  } else if (this.status === 'failed' || this.status === 'cancelled') {
    this.progress.currentPhase = 'failed';
  }
  
  next();
});

// Method to start scan
scanSchema.methods.start = function() {
  this.status = 'running';
  this.startedAt = new Date();
  this.progress.currentPhase = 'scanning';
  this.progress.percentage = 5;
  return this.save();
};

// Method to complete scan
scanSchema.methods.complete = function() {
  this.status = 'completed';
  this.completedAt = new Date();
  this.progress.percentage = 100;
  this.progress.currentPhase = 'completed';
  return this.save();
};

// Method to fail scan
scanSchema.methods.fail = function(error) {
  this.status = 'failed';
  this.completedAt = new Date();
  this.progress.currentPhase = 'failed';
  
  if (error) {
    this.errors.push({
      phase: this.progress.currentPhase,
      message: error.message || error,
      code: error.code || 'UNKNOWN_ERROR',
      severity: 'error'
    });
  }
  
  return this.save();
};

// Method to cancel scan
scanSchema.methods.cancel = function() {
  this.status = 'cancelled';
  this.completedAt = new Date();
  this.progress.currentPhase = 'cancelled';
  return this.save();
};

// Method to update progress
scanSchema.methods.updateProgress = function(percentage, phase, additionalData = {}) {
  this.progress.percentage = Math.min(100, Math.max(0, percentage));
  
  if (phase) {
    this.progress.currentPhase = phase;
  }
  
  Object.assign(this.progress, additionalData);
  return this.save();
};

// Method to add vulnerability
scanSchema.methods.addVulnerability = function(vulnerability) {
  this.results.vulnerabilities.push(vulnerability);
  
  // Update summary
  this.results.summary.totalVulnerabilities = this.results.vulnerabilities.length;
  
  const severityCount = this.results.summary.vulnerabilitiesBySeverity;
  if (severityCount[vulnerability.severity] !== undefined) {
    severityCount[vulnerability.severity]++;
  }
  
  // Update risk assessment
  this.updateRiskAssessment();
  
  return this.save();
};

// Method to add host
scanSchema.methods.addHost = function(host) {
  this.results.hosts.push(host);
  
  // Update summary
  this.results.summary.totalHosts = this.results.hosts.length;
  this.results.summary.hostsUp = this.results.hosts.filter(h => h.status === 'up').length;
  this.results.summary.hostsDown = this.results.hosts.filter(h => h.status === 'down').length;
  
  return this.save();
};

// Method to update risk assessment
scanSchema.methods.updateRiskAssessment = function() {
  const vulns = this.results.vulnerabilities;
  const severityCount = this.results.summary.vulnerabilitiesBySeverity;
  
  // Calculate risk score
  const riskScore = (severityCount.critical * 25) + 
                   (severityCount.high * 10) + 
                   (severityCount.medium * 5) + 
                   (severityCount.low * 2) + 
                   (severityCount.info * 1);
  
  this.riskAssessment.riskScore = Math.min(100, riskScore);
  
  // Determine overall risk
  if (this.riskAssessment.riskScore >= 80) {
    this.riskAssessment.overallRisk = 'critical';
  } else if (this.riskAssessment.riskScore >= 60) {
    this.riskAssessment.overallRisk = 'high';
  } else if (this.riskAssessment.riskScore >= 40) {
    this.riskAssessment.overallRisk = 'medium';
  } else if (this.riskAssessment.riskScore >= 20) {
    this.riskAssessment.overallRisk = 'low';
  } else {
    this.riskAssessment.overallRisk = 'minimal';
  }
  
  // Generate recommendations
  this.riskAssessment.recommendations = [];
  
  if (severityCount.critical > 0) {
    this.riskAssessment.recommendations.push('Immediately address critical vulnerabilities');
  }
  if (severityCount.high > 0) {
    this.riskAssessment.recommendations.push('Prioritize high-severity vulnerabilities');
  }
  if (this.results.summary.openPorts > 20) {
    this.riskAssessment.recommendations.push('Review and close unnecessary open ports');
  }
  
  return this;
};

// Method to check if scan needs alerting
scanSchema.methods.shouldAlert = function() {
  const criticalVulns = this.results.summary.vulnerabilitiesBySeverity.critical;
  const highVulns = this.results.summary.vulnerabilitiesBySeverity.high;
  const riskScore = this.riskAssessment.riskScore;
  
  return criticalVulns > 0 || highVulns > 5 || riskScore >= 70;
};

// Method to generate summary
scanSchema.methods.generateSummary = function() {
  return {
    scanId: this.scanId,
    target: this.targetSnapshot.value,
    status: this.status,
    duration: this.durationFormatted,
    riskScore: this.riskAssessment.riskScore,
    riskLevel: this.riskAssessment.overallRisk,
    vulnerabilities: this.results.summary.vulnerabilitiesBySeverity,
    totalVulnerabilities: this.results.summary.totalVulnerabilities,
    hostsScanned: this.results.summary.totalHosts,
    openPorts: this.results.summary.openPorts,
    completedAt: this.completedAt,
    recommendations: this.riskAssessment.recommendations
  };
};

// Static method to find by status
scanSchema.statics.findByStatus = function(status) {
  return this.find({ status, isActive: true, isDeleted: false });
};

// Static method to find recent scans
scanSchema.statics.findRecent = function(limit = 10) {
  return this.find({ isActive: true, isDeleted: false })
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('target', 'name value type')
    .populate('metadata.initiatedBy', 'firstName lastName email');
};

// Static method to find by user
scanSchema.statics.findByUser = function(userId) {
  return this.find({ 
    'metadata.initiatedBy': userId, 
    isActive: true, 
    isDeleted: false 
  }).populate('target', 'name value type');
};

// Static method to find pending scans
scanSchema.statics.findPending = function() {
  return this.find({ 
    status: { $in: ['pending', 'queued'] }, 
    isActive: true, 
    isDeleted: false 
  }).sort({ priority: -1, scheduledAt: 1 });
};

module.exports = mongoose.model('Scan', scanSchema);