const logger = require('../config/logger');

/**
 * Custom error class for application errors
 */
class AppError extends Error {
  constructor(message, statusCode, code = null, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error handling middleware
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;
  
  // Log error details
  logger.error('Error caught by middleware:', {
    error: error.message,
    stack: error.stack,
    statusCode: error.statusCode,
    code: error.code,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    user: req.user ? req.user._id : null
  });
  
  // MongoDB validation error
  if (err.name === 'ValidationError') {
    const message = Object.values(err.errors).map(error => error.message).join(', ');
    error = new AppError(message, 400, 'VALIDATION_ERROR');
  }
  
  // MongoDB duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    const message = `${field} already exists`;
    error = new AppError(message, 409, 'DUPLICATE_FIELD');
  }
  
  // MongoDB ObjectId error
  if (err.name === 'CastError') {
    const message = 'Invalid ID format';
    error = new AppError(message, 400, 'INVALID_ID');
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token';
    error = new AppError(message, 401, 'INVALID_TOKEN');
  }
  
  if (err.name === 'TokenExpiredError') {
    const message = 'Token expired';
    error = new AppError(message, 401, 'TOKEN_EXPIRED');
  }
  
  // Multer errors (file upload)
  if (err.code === 'LIMIT_FILE_SIZE') {
    const message = 'File too large';
    error = new AppError(message, 413, 'FILE_TOO_LARGE');
  }
  
  if (err.code === 'LIMIT_FILE_COUNT') {
    const message = 'Too many files';
    error = new AppError(message, 413, 'TOO_MANY_FILES');
  }
  
  if (err.code === 'LIMIT_UNEXPECTED_FILE') {
    const message = 'Unexpected file field';
    error = new AppError(message, 400, 'UNEXPECTED_FILE');
  }
  
  // Stripe errors
  if (err.type === 'StripeCardError') {
    const message = 'Payment failed';
    error = new AppError(message, 402, 'PAYMENT_FAILED', {
      decline_code: err.decline_code,
      payment_intent: err.payment_intent
    });
  }
  
  if (err.type === 'StripeInvalidRequestError') {
    const message = 'Invalid payment request';
    error = new AppError(message, 400, 'INVALID_PAYMENT_REQUEST');
  }
  
  // Network/timeout errors
  if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
    const message = 'Service temporarily unavailable';
    error = new AppError(message, 503, 'SERVICE_UNAVAILABLE');
  }
  
  // Redis errors
  if (err.message && err.message.includes('Redis')) {
    const message = 'Cache service unavailable';
    error = new AppError(message, 503, 'CACHE_UNAVAILABLE');
  }
  
  // Rate limit errors
  if (err.status === 429) {
    const message = 'Too many requests';
    error = new AppError(message, 429, 'RATE_LIMIT_EXCEEDED');
  }
  
  // Default to 500 server error
  if (!error.statusCode) {
    error.statusCode = 500;
    error.code = 'INTERNAL_SERVER_ERROR';
  }
  
  // Send error response
  const response = {
    status: 'error',
    message: error.message || 'Internal server error',
    code: error.code || 'INTERNAL_SERVER_ERROR'
  };
  
  // Add additional details in development
  if (process.env.NODE_ENV === 'development') {
    response.stack = error.stack;
    response.details = error.details;
  }
  
  // Add additional details if provided
  if (error.details) {
    response.details = error.details;
  }
  
  res.status(error.statusCode).json(response);
};

/**
 * 404 handler for unmatched routes
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const notFoundHandler = (req, res, next) => {
  const error = new AppError(`Route ${req.originalUrl} not found`, 404, 'ROUTE_NOT_FOUND');
  next(error);
};

/**
 * Async error handler wrapper
 * @param {Function} fn - Async function to wrap
 * @returns {Function} Wrapped function
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Validation error handler
 * @param {Object} errors - Validation errors
 * @param {String} message - Error message
 * @returns {AppError} Application error
 */
const validationError = (errors, message = 'Validation failed') => {
  const details = {};
  
  if (Array.isArray(errors)) {
    errors.forEach(error => {
      if (error.param) {
        details[error.param] = error.msg;
      }
    });
  } else if (typeof errors === 'object') {
    Object.keys(errors).forEach(key => {
      details[key] = errors[key];
    });
  }
  
  return new AppError(message, 400, 'VALIDATION_ERROR', details);
};

/**
 * Permission error handler
 * @param {String} message - Error message
 * @param {String} permission - Required permission
 * @returns {AppError} Application error
 */
const permissionError = (message = 'Insufficient permissions', permission = null) => {
  return new AppError(message, 403, 'PERMISSION_DENIED', { permission });
};

/**
 * Subscription error handler
 * @param {String} message - Error message
 * @param {String} feature - Feature requiring subscription
 * @returns {AppError} Application error
 */
const subscriptionError = (message = 'Subscription required', feature = null) => {
  return new AppError(message, 402, 'SUBSCRIPTION_REQUIRED', { feature });
};

/**
 * Usage limit error handler
 * @param {String} message - Error message
 * @param {String} feature - Feature with usage limit
 * @param {Object} limits - Usage limits
 * @param {Object} current - Current usage
 * @returns {AppError} Application error
 */
const usageLimitError = (message = 'Usage limit exceeded', feature = null, limits = null, current = null) => {
  return new AppError(message, 429, 'USAGE_LIMIT_EXCEEDED', { feature, limits, current });
};

/**
 * Rate limit error handler
 * @param {String} message - Error message
 * @param {Number} retryAfter - Retry after seconds
 * @returns {AppError} Application error
 */
const rateLimitError = (message = 'Too many requests', retryAfter = null) => {
  return new AppError(message, 429, 'RATE_LIMIT_EXCEEDED', { retryAfter });
};

/**
 * File upload error handler
 * @param {String} message - Error message
 * @param {String} type - Error type
 * @returns {AppError} Application error
 */
const uploadError = (message, type = 'UPLOAD_ERROR') => {
  return new AppError(message, 400, type);
};

/**
 * Database error handler
 * @param {String} message - Error message
 * @param {String} operation - Database operation
 * @returns {AppError} Application error
 */
const databaseError = (message = 'Database operation failed', operation = null) => {
  return new AppError(message, 500, 'DATABASE_ERROR', { operation });
};

/**
 * External service error handler
 * @param {String} message - Error message
 * @param {String} service - Service name
 * @returns {AppError} Application error
 */
const serviceError = (message = 'External service error', service = null) => {
  return new AppError(message, 503, 'SERVICE_ERROR', { service });
};

/**
 * Scan error handler
 * @param {String} message - Error message
 * @param {String} scanId - Scan ID
 * @param {String} phase - Scan phase
 * @returns {AppError} Application error
 */
const scanError = (message = 'Scan failed', scanId = null, phase = null) => {
  return new AppError(message, 500, 'SCAN_ERROR', { scanId, phase });
};

/**
 * Configuration error handler
 * @param {String} message - Error message
 * @param {String} config - Configuration key
 * @returns {AppError} Application error
 */
const configError = (message = 'Configuration error', config = null) => {
  return new AppError(message, 500, 'CONFIG_ERROR', { config });
};

/**
 * Security error handler
 * @param {String} message - Error message
 * @param {String} type - Security violation type
 * @returns {AppError} Application error
 */
const securityError = (message = 'Security violation', type = null) => {
  return new AppError(message, 403, 'SECURITY_ERROR', { type });
};

/**
 * Global error handler for unhandled promise rejections
 */
process.on('unhandledRejection', (err, promise) => {
  logger.error('Unhandled promise rejection:', {
    error: err.message,
    stack: err.stack,
    promise: promise
  });
  
  // Exit process with failure
  process.exit(1);
});

/**
 * Global error handler for uncaught exceptions
 */
process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception:', {
    error: err.message,
    stack: err.stack
  });
  
  // Exit process with failure
  process.exit(1);
});

module.exports = {
  AppError,
  errorHandler,
  notFoundHandler,
  asyncHandler,
  validationError,
  permissionError,
  subscriptionError,
  usageLimitError,
  rateLimitError,
  uploadError,
  databaseError,
  serviceError,
  scanError,
  configError,
  securityError
};