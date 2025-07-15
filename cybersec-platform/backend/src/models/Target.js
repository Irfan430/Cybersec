const mongoose = require('mongoose');

const targetSchema = new mongoose.Schema({
  // Basic target information
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
  
  // Target details
  type: {
    type: String,
    enum: ['domain', 'ip', 'url', 'cidr', 'host'],
    required: true
  },
  value: {
    type: String,
    required: true,
    trim: true
  },
  
  // Additional target properties
  ports: [{
    port: {
      type: Number,
      min: 1,
      max: 65535
    },
    protocol: {
      type: String,
      enum: ['tcp', 'udp'],
      default: 'tcp'
    },
    service: String,
    state: {
      type: String,
      enum: ['open', 'closed', 'filtered', 'unknown'],
      default: 'unknown'
    }
  }],
  
  // Target metadata
  tags: [{
    type: String,
    trim: true,
    maxlength: 50
  }],
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  environment: {
    type: String,
    enum: ['development', 'staging', 'production'],
    default: 'production'
  },
  
  // Ownership and permissions
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  organization: {
    type: String,
    trim: true,
    maxlength: 100
  },
  team: {
    type: String,
    trim: true,
    maxlength: 100
  },
  
  // Access control
  isPublic: {
    type: Boolean,
    default: false
  },
  sharedWith: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    permission: {
      type: String,
      enum: ['read', 'write', 'admin'],
      default: 'read'
    },
    sharedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Scanning configuration
  scanConfig: {
    enabledScans: [{
      type: String,
      enum: ['nmap', 'nikto', 'nuclei', 'openvas', 'custom'],
      default: 'nmap'
    }],
    nmapOptions: {
      type: String,
      default: '-sV -sC'
    },
    niktoOptions: {
      type: String,
      default: '-h'
    },
    customScript: String,
    timeout: {
      type: Number,
      default: 300, // 5 minutes
      min: 60,
      max: 3600
    },
    maxConcurrentScans: {
      type: Number,
      default: 1,
      min: 1,
      max: 5
    }
  },
  
  // Monitoring and alerting
  monitoring: {
    enabled: {
      type: Boolean,
      default: false
    },
    frequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly'],
      default: 'weekly'
    },
    lastMonitoredAt: Date,
    nextMonitorAt: Date,
    alertThresholds: {
      newVulnerabilities: {
        type: Number,
        default: 1
      },
      riskScoreIncrease: {
        type: Number,
        default: 10
      },
      newOpenPorts: {
        type: Boolean,
        default: true
      }
    }
  },
  
  // Target statistics
  stats: {
    totalScans: {
      type: Number,
      default: 0
    },
    lastScanAt: Date,
    lastSuccessfulScanAt: Date,
    lastFailedScanAt: Date,
    vulnerabilitiesFound: {
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 }
    },
    currentRiskScore: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    riskTrend: {
      type: String,
      enum: ['increasing', 'decreasing', 'stable'],
      default: 'stable'
    }
  },
  
  // Compliance and regulations
  compliance: {
    frameworks: [{
      type: String,
      enum: ['pci-dss', 'hipaa', 'gdpr', 'sox', 'nist', 'iso27001'],
    }],
    requiresCompliance: {
      type: Boolean,
      default: false
    },
    lastComplianceCheck: Date,
    complianceStatus: {
      type: String,
      enum: ['compliant', 'non-compliant', 'partial', 'unknown'],
      default: 'unknown'
    }
  },
  
  // Status and health
  status: {
    type: String,
    enum: ['active', 'inactive', 'error', 'scanning', 'maintenance'],
    default: 'active'
  },
  health: {
    isReachable: {
      type: Boolean,
      default: true
    },
    lastHealthCheck: Date,
    responseTime: Number, // in milliseconds
    uptime: Number, // percentage
    errors: [{
      message: String,
      timestamp: {
        type: Date,
        default: Date.now
      },
      resolved: {
        type: Boolean,
        default: false
      }
    }]
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
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes for performance
targetSchema.index({ owner: 1 });
targetSchema.index({ type: 1 });
targetSchema.index({ value: 1 });
targetSchema.index({ tags: 1 });
targetSchema.index({ priority: 1 });
targetSchema.index({ environment: 1 });
targetSchema.index({ status: 1 });
targetSchema.index({ isActive: 1, isDeleted: 1 });
targetSchema.index({ 'monitoring.enabled': 1, 'monitoring.nextMonitorAt': 1 });

// Compound indexes
targetSchema.index({ owner: 1, type: 1 });
targetSchema.index({ owner: 1, status: 1 });
targetSchema.index({ owner: 1, priority: 1 });

// Virtual for total vulnerabilities
targetSchema.virtual('totalVulnerabilities').get(function() {
  const vuln = this.stats.vulnerabilitiesFound;
  return vuln.critical + vuln.high + vuln.medium + vuln.low + vuln.info;
});

// Virtual for risk level based on score
targetSchema.virtual('riskLevel').get(function() {
  const score = this.stats.currentRiskScore;
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'minimal';
});

// Virtual for next scan time
targetSchema.virtual('nextScanTime').get(function() {
  if (!this.monitoring.enabled) return null;
  
  const now = new Date();
  const frequency = this.monitoring.frequency;
  const lastScan = this.stats.lastScanAt || this.createdAt;
  
  let nextScan;
  switch (frequency) {
    case 'daily':
      nextScan = new Date(lastScan.getTime() + 24 * 60 * 60 * 1000);
      break;
    case 'weekly':
      nextScan = new Date(lastScan.getTime() + 7 * 24 * 60 * 60 * 1000);
      break;
    case 'monthly':
      nextScan = new Date(lastScan);
      nextScan.setMonth(nextScan.getMonth() + 1);
      break;
    default:
      nextScan = null;
  }
  
  return nextScan;
});

// Pre-save middleware to validate target value
targetSchema.pre('save', function(next) {
  const target = this;
  
  // Validate based on type
  switch (target.type) {
    case 'domain':
      if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(target.value)) {
        return next(new Error('Invalid domain format'));
      }
      break;
    case 'ip':
      if (!/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(target.value)) {
        return next(new Error('Invalid IP address format'));
      }
      break;
    case 'url':
      try {
        new URL(target.value);
      } catch (e) {
        return next(new Error('Invalid URL format'));
      }
      break;
    case 'cidr':
      if (!/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/.test(target.value)) {
        return next(new Error('Invalid CIDR format'));
      }
      break;
  }
  
  // Update monitoring next scan time
  if (target.monitoring.enabled && target.isModified('monitoring.frequency')) {
    target.monitoring.nextMonitorAt = target.nextScanTime;
  }
  
  next();
});

// Method to check if user can access target
targetSchema.methods.canAccess = function(user, permission = 'read') {
  // Owner has full access
  if (this.owner.toString() === user._id.toString()) return true;
  
  // Admin has full access
  if (user.role === 'admin') return true;
  
  // Public targets are readable by all
  if (this.isPublic && permission === 'read') return true;
  
  // Check shared permissions
  const sharedPermission = this.sharedWith.find(s => s.user.toString() === user._id.toString());
  if (sharedPermission) {
    if (permission === 'read') return true;
    if (permission === 'write' && ['write', 'admin'].includes(sharedPermission.permission)) return true;
    if (permission === 'admin' && sharedPermission.permission === 'admin') return true;
  }
  
  return false;
};

// Method to update vulnerability stats
targetSchema.methods.updateVulnerabilityStats = function(vulnerabilities) {
  const stats = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  vulnerabilities.forEach(vuln => {
    if (stats.hasOwnProperty(vuln.severity)) {
      stats[vuln.severity]++;
    }
  });
  
  this.stats.vulnerabilitiesFound = stats;
  this.stats.lastScanAt = new Date();
  this.stats.totalScans += 1;
  
  // Calculate risk score (simplified)
  const riskScore = (stats.critical * 25) + (stats.high * 10) + (stats.medium * 5) + (stats.low * 2) + (stats.info * 1);
  const oldScore = this.stats.currentRiskScore;
  this.stats.currentRiskScore = Math.min(100, riskScore);
  
  // Update trend
  if (this.stats.currentRiskScore > oldScore) {
    this.stats.riskTrend = 'increasing';
  } else if (this.stats.currentRiskScore < oldScore) {
    this.stats.riskTrend = 'decreasing';
  } else {
    this.stats.riskTrend = 'stable';
  }
  
  return this.save();
};

// Method to add shared user
targetSchema.methods.shareWith = function(userId, permission = 'read') {
  const existingShare = this.sharedWith.find(s => s.user.toString() === userId.toString());
  
  if (existingShare) {
    existingShare.permission = permission;
    existingShare.sharedAt = new Date();
  } else {
    this.sharedWith.push({
      user: userId,
      permission,
      sharedAt: new Date()
    });
  }
  
  return this.save();
};

// Method to remove shared user
targetSchema.methods.unshareWith = function(userId) {
  this.sharedWith = this.sharedWith.filter(s => s.user.toString() !== userId.toString());
  return this.save();
};

// Method to check if target needs monitoring
targetSchema.methods.needsMonitoring = function() {
  if (!this.monitoring.enabled) return false;
  if (!this.monitoring.nextMonitorAt) return true;
  return new Date() >= this.monitoring.nextMonitorAt;
};

// Static method to find targets by owner
targetSchema.statics.findByOwner = function(ownerId, options = {}) {
  const query = { 
    owner: ownerId, 
    isActive: true, 
    isDeleted: false,
    ...options
  };
  return this.find(query);
};

// Static method to find targets needing monitoring
targetSchema.statics.findNeedingMonitoring = function() {
  return this.find({
    'monitoring.enabled': true,
    'monitoring.nextMonitorAt': { $lte: new Date() },
    status: 'active',
    isActive: true,
    isDeleted: false
  });
};

// Static method to find high-risk targets
targetSchema.statics.findHighRisk = function(threshold = 60) {
  return this.find({
    'stats.currentRiskScore': { $gte: threshold },
    isActive: true,
    isDeleted: false
  });
};

module.exports = mongoose.model('Target', targetSchema);