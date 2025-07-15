const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../config/logger');

/**
 * Middleware to authenticate JWT tokens
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authenticate = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        status: 'error',
        message: 'Access token required'
      });
    }
    
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find user
    const user = await User.findById(decoded.userId).select('+password');
    
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'User not found'
      });
    }
    
    // Check if user is active
    if (!user.isActive || user.isDeleted) {
      return res.status(401).json({
        status: 'error',
        message: 'Account is inactive'
      });
    }
    
    // Check if account is locked
    if (user.isLocked) {
      return res.status(423).json({
        status: 'error',
        message: 'Account is temporarily locked due to multiple failed login attempts'
      });
    }
    
    // Check if subscription is active (optional, can be configured)
    if (process.env.ENFORCE_SUBSCRIPTION === 'true' && !user.isSubscriptionActive()) {
      return res.status(402).json({
        status: 'error',
        message: 'Subscription required',
        code: 'SUBSCRIPTION_REQUIRED'
      });
    }
    
    // Attach user to request object
    req.user = user;
    
    // Log authentication
    logger.security('User authenticated', {
      userId: user._id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl
    });
    
    next();
    
  } catch (error) {
    logger.error('Authentication error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid token'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        status: 'error',
        message: 'Token expired'
      });
    }
    
    return res.status(500).json({
      status: 'error',
      message: 'Authentication failed'
    });
  }
};

/**
 * Middleware to authenticate API key
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authenticateApiKey = async (req, res, next) => {
  try {
    // Get API key from header
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        status: 'error',
        message: 'API key required'
      });
    }
    
    // Find user by API key
    const user = await User.findByApiKey(apiKey);
    
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid API key'
      });
    }
    
    // Check if user is active
    if (!user.isActive || user.isDeleted) {
      return res.status(401).json({
        status: 'error',
        message: 'Account is inactive'
      });
    }
    
    // Check if subscription is active
    if (!user.isSubscriptionActive()) {
      return res.status(402).json({
        status: 'error',
        message: 'Subscription required',
        code: 'SUBSCRIPTION_REQUIRED'
      });
    }
    
    // Update last API key usage
    user.apiKeyLastUsed = new Date();
    await user.save();
    
    // Attach user to request object
    req.user = user;
    req.isApiRequest = true;
    
    // Log API key usage
    logger.security('API key authenticated', {
      userId: user._id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl
    });
    
    next();
    
  } catch (error) {
    logger.error('API key authentication error:', error);
    
    return res.status(500).json({
      status: 'error',
      message: 'Authentication failed'
    });
  }
};

/**
 * Flexible authentication middleware that supports both JWT and API key
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authenticateFlexible = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'];
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authenticate(req, res, next);
  } else if (apiKey) {
    return authenticateApiKey(req, res, next);
  } else {
    return res.status(401).json({
      status: 'error',
      message: 'Authentication required (Bearer token or API key)'
    });
  }
};

/**
 * Optional authentication middleware
 * Attaches user if token is valid, but doesn't require authentication
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'];
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      if (user && user.isActive && !user.isDeleted) {
        req.user = user;
      }
    } else if (apiKey) {
      const user = await User.findByApiKey(apiKey);
      
      if (user && user.isActive && !user.isDeleted) {
        req.user = user;
        req.isApiRequest = true;
      }
    }
    
    next();
    
  } catch (error) {
    // Continue without authentication if token is invalid
    next();
  }
};

/**
 * Middleware to refresh user session
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const refreshSession = async (req, res, next) => {
  try {
    if (req.user && !req.isApiRequest) {
      // Update last login time
      req.user.usage.lastLoginAt = new Date();
      await req.user.save();
      
      // Refresh session if needed
      if (req.session) {
        req.session.touch();
      }
    }
    
    next();
    
  } catch (error) {
    logger.error('Session refresh error:', error);
    next(); // Continue even if session refresh fails
  }
};

/**
 * Middleware to validate subscription requirements
 * @param {String} feature - Feature name to check
 * @returns {Function} Middleware function
 */
const requireSubscription = (feature) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          status: 'error',
          message: 'Authentication required'
        });
      }
      
      // Check if user's subscription allows the feature
      if (!req.user.isSubscriptionActive()) {
        return res.status(402).json({
          status: 'error',
          message: 'Active subscription required',
          code: 'SUBSCRIPTION_REQUIRED',
          feature
        });
      }
      
      // Check usage limits
      if (feature && !req.user.canPerformAction(feature)) {
        const limits = req.user.getUsageLimits();
        
        return res.status(429).json({
          status: 'error',
          message: 'Usage limit exceeded',
          code: 'USAGE_LIMIT_EXCEEDED',
          feature,
          limits,
          currentUsage: req.user.usage
        });
      }
      
      next();
      
    } catch (error) {
      logger.error('Subscription validation error:', error);
      
      return res.status(500).json({
        status: 'error',
        message: 'Subscription validation failed'
      });
    }
  };
};

/**
 * Middleware to check if user is email verified
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireEmailVerification = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required'
      });
    }
    
    if (!req.user.security.emailVerified) {
      return res.status(403).json({
        status: 'error',
        message: 'Email verification required',
        code: 'EMAIL_VERIFICATION_REQUIRED'
      });
    }
    
    next();
    
  } catch (error) {
    logger.error('Email verification check error:', error);
    
    return res.status(500).json({
      status: 'error',
      message: 'Verification check failed'
    });
  }
};

/**
 * Middleware to rate limit based on user
 * @param {Number} maxRequests - Maximum requests per window
 * @param {Number} windowMs - Time window in milliseconds
 * @returns {Function} Middleware function
 */
const userRateLimit = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  const userRequests = new Map();
  
  return (req, res, next) => {
    const userId = req.user ? req.user._id.toString() : req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get user's request history
    let requests = userRequests.get(userId) || [];
    
    // Filter requests within the window
    requests = requests.filter(time => time > windowStart);
    
    // Check if limit exceeded
    if (requests.length >= maxRequests) {
      return res.status(429).json({
        status: 'error',
        message: 'Too many requests',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil((requests[0] + windowMs - now) / 1000)
      });
    }
    
    // Add current request
    requests.push(now);
    userRequests.set(userId, requests);
    
    // Clean up old entries periodically
    if (Math.random() < 0.01) { // 1% chance
      for (const [key, value] of userRequests.entries()) {
        const filtered = value.filter(time => time > windowStart);
        if (filtered.length === 0) {
          userRequests.delete(key);
        } else {
          userRequests.set(key, filtered);
        }
      }
    }
    
    next();
  };
};

module.exports = {
  authenticate,
  authenticateApiKey,
  authenticateFlexible,
  optionalAuth,
  refreshSession,
  requireSubscription,
  requireEmailVerification,
  userRateLimit
};