const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logDir = path.join(__dirname, '..', '..', 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

// Custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let log = `${timestamp} [${level}]: ${message}`;
    
    // Add metadata if present
    if (Object.keys(meta).length > 0) {
      log += ` ${JSON.stringify(meta)}`;
    }
    
    return log;
  })
);

// Custom format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Create transports
const transports = [
  // Console transport
  new winston.transports.Console({
    level: process.env.LOG_LEVEL || 'info',
    format: consoleFormat,
    handleExceptions: true,
    handleRejections: true
  }),

  // Daily rotate file for all logs
  new DailyRotateFile({
    filename: path.join(logDir, 'application-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '14d',
    level: 'info',
    format: fileFormat,
    handleExceptions: true,
    handleRejections: true
  }),

  // Daily rotate file for error logs
  new DailyRotateFile({
    filename: path.join(logDir, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '30d',
    level: 'error',
    format: fileFormat,
    handleExceptions: true,
    handleRejections: true
  }),

  // Daily rotate file for audit logs
  new DailyRotateFile({
    filename: path.join(logDir, 'audit-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '90d',
    level: 'info',
    format: fileFormat
  })
];

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: fileFormat,
  transports,
  exitOnError: false
});

// Additional logging methods for security events
logger.security = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'security' });
};

logger.audit = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'audit' });
};

logger.performance = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'performance' });
};

logger.scan = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'scan' });
};

logger.user = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'user' });
};

logger.billing = (message, meta = {}) => {
  logger.info(message, { ...meta, type: 'billing' });
};

logger.alert = (message, meta = {}) => {
  logger.warn(message, { ...meta, type: 'alert' });
};

// Stream interface for Morgan HTTP logger
logger.stream = {
  write: (message) => {
    logger.info(message.trim());
  }
};

// Handle uncaught exceptions and rejections
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

module.exports = logger;