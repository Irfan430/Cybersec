const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const userSchema = new mongoose.Schema({
  // Basic user information
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    select: false // Don't include in queries by default
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  phone: {
    type: String,
    trim: true,
    match: [/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number']
  },
  avatar: {
    type: String,
    default: null
  },

  // Role-based access control
  role: {
    type: String,
    enum: ['admin', 'manager', 'viewer'],
    default: 'viewer'
  },
  permissions: [{
    type: String,
    enum: [
      'scan:create',
      'scan:read',
      'scan:update',
      'scan:delete',
      'target:create',
      'target:read',
      'target:update',
      'target:delete',
      'report:create',
      'report:read',
      'report:download',
      'user:create',
      'user:read',
      'user:update',
      'user:delete',
      'billing:read',
      'billing:manage',
      'alert:create',
      'alert:read',
      'alert:update',
      'alert:delete',
      'phishing:create',
      'phishing:read',
      'dashboard:read',
      'admin:all'
    ]
  }],

  // Organization and team
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

  // Subscription and billing
  subscription: {
    plan: {
      type: String,
      enum: ['free', 'basic', 'professional', 'enterprise'],
      default: 'free'
    },
    status: {
      type: String,
      enum: ['active', 'cancelled', 'expired', 'trial'],
      default: 'trial'
    },
    trialEndsAt: {
      type: Date,
      default: () => new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14 days trial
    },
    subscriptionId: String,
    customerId: String,
    currentPeriodStart: Date,
    currentPeriodEnd: Date,
    cancelAtPeriodEnd: {
      type: Boolean,
      default: false
    }
  },

  // Usage tracking
  usage: {
    scansThisMonth: {
      type: Number,
      default: 0
    },
    targetsCount: {
      type: Number,
      default: 0
    },
    reportsGenerated: {
      type: Number,
      default: 0
    },
    phishingCampaigns: {
      type: Number,
      default: 0
    },
    lastScanAt: Date,
    lastLoginAt: Date
  },

  // Security settings
  security: {
    twoFactorEnabled: {
      type: Boolean,
      default: false
    },
    twoFactorSecret: String,
    passwordResetToken: String,
    passwordResetExpires: Date,
    emailVerificationToken: String,
    emailVerified: {
      type: Boolean,
      default: false
    },
    emailVerifiedAt: Date,
    loginAttempts: {
      type: Number,
      default: 0
    },
    lockUntil: Date,
    lastPasswordChange: {
      type: Date,
      default: Date.now
    }
  },

  // Notification preferences
  notifications: {
    email: {
      scanComplete: {
        type: Boolean,
        default: true
      },
      criticalThreats: {
        type: Boolean,
        default: true
      },
      weeklyReport: {
        type: Boolean,
        default: true
      },
      billing: {
        type: Boolean,
        default: true
      }
    },
    telegram: {
      enabled: {
        type: Boolean,
        default: false
      },
      chatId: String,
      criticalThreats: {
        type: Boolean,
        default: false
      }
    },
    slack: {
      enabled: {
        type: Boolean,
        default: false
      },
      webhookUrl: String,
      criticalThreats: {
        type: Boolean,
        default: false
      }
    }
  },

  // API access
  apiKey: {
    type: String,
    unique: true,
    sparse: true
  },
  apiKeyCreatedAt: Date,
  apiKeyLastUsed: Date,

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
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.security.twoFactorSecret;
      delete ret.security.passwordResetToken;
      delete ret.security.emailVerificationToken;
      return ret;
    }
  }
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ apiKey: 1 });
userSchema.index({ 'subscription.customerId': 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1, isDeleted: 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Virtual for account locked status
userSchema.virtual('isLocked').get(function() {
  return !!(this.security.lockUntil && this.security.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
    this.password = await bcrypt.hash(this.password, salt);
    this.security.lastPasswordChange = new Date();
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare password
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

// Method to generate JWT token
userSchema.methods.generateAuthToken = function() {
  return jwt.sign(
    { 
      userId: this._id, 
      email: this.email, 
      role: this.role 
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
};

// Method to generate API key
userSchema.methods.generateApiKey = function() {
  const crypto = require('crypto');
  const apiKey = crypto.randomBytes(32).toString('hex');
  this.apiKey = apiKey;
  this.apiKeyCreatedAt = new Date();
  return apiKey;
};

// Method to check if user has permission
userSchema.methods.hasPermission = function(permission) {
  if (this.role === 'admin') return true;
  return this.permissions.includes(permission);
};

// Method to check if subscription is active
userSchema.methods.isSubscriptionActive = function() {
  if (this.subscription.status === 'active') return true;
  if (this.subscription.status === 'trial' && this.subscription.trialEndsAt > new Date()) return true;
  return false;
};

// Method to get usage limits based on subscription
userSchema.methods.getUsageLimits = function() {
  const limits = {
    free: { scans: 5, targets: 3, reports: 2, phishing: 1 },
    basic: { scans: 50, targets: 20, reports: 10, phishing: 5 },
    professional: { scans: 200, targets: 100, reports: 50, phishing: 20 },
    enterprise: { scans: -1, targets: -1, reports: -1, phishing: -1 } // Unlimited
  };
  
  return limits[this.subscription.plan] || limits.free;
};

// Method to check if user can perform action based on usage
userSchema.methods.canPerformAction = function(action) {
  const limits = this.getUsageLimits();
  
  switch (action) {
    case 'scan':
      return limits.scans === -1 || this.usage.scansThisMonth < limits.scans;
    case 'target':
      return limits.targets === -1 || this.usage.targetsCount < limits.targets;
    case 'report':
      return limits.reports === -1 || this.usage.reportsGenerated < limits.reports;
    case 'phishing':
      return limits.phishing === -1 || this.usage.phishingCampaigns < limits.phishing;
    default:
      return false;
  }
};

// Method to increment usage counter
userSchema.methods.incrementUsage = function(action) {
  switch (action) {
    case 'scan':
      this.usage.scansThisMonth += 1;
      this.usage.lastScanAt = new Date();
      break;
    case 'target':
      this.usage.targetsCount += 1;
      break;
    case 'report':
      this.usage.reportsGenerated += 1;
      break;
    case 'phishing':
      this.usage.phishingCampaigns += 1;
      break;
  }
  return this.save();
};

// Method to handle failed login attempts
userSchema.methods.handleFailedLogin = function() {
  this.security.loginAttempts += 1;
  
  // Lock account after 5 failed attempts for 30 minutes
  if (this.security.loginAttempts >= 5) {
    this.security.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
  }
  
  return this.save();
};

// Method to handle successful login
userSchema.methods.handleSuccessfulLogin = function() {
  this.security.loginAttempts = 0;
  this.security.lockUntil = undefined;
  this.usage.lastLoginAt = new Date();
  
  return this.save();
};

// Static method to find by email
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase(), isActive: true, isDeleted: false });
};

// Static method to find by API key
userSchema.statics.findByApiKey = function(apiKey) {
  return this.findOne({ apiKey, isActive: true, isDeleted: false });
};

module.exports = mongoose.model('User', userSchema);