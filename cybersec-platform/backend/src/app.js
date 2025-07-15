const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

// Import configurations
const connectDB = require('./config/database');
const redisClient = require('./config/redis');
const logger = require('./config/logger');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const targetRoutes = require('./routes/targets');
const scanRoutes = require('./routes/scans');
const reportRoutes = require('./routes/reports');
const billingRoutes = require('./routes/billing');
const alertRoutes = require('./routes/alerts');
const phishingRoutes = require('./routes/phishing');
const dashboardRoutes = require('./routes/dashboard');
const cicdRoutes = require('./routes/cicd');

// Import middleware
const errorHandler = require('./middleware/errorHandler');
const authMiddleware = require('./middleware/auth');
const roleMiddleware = require('./middleware/roles');

// Import services
const socketService = require('./services/socketService');
const cronService = require('./services/cronService');

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Connect to MongoDB
connectDB();

// Connect to Redis
redisClient.connect().catch(err => {
  logger.error('Redis connection error:', err);
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: 'Too many requests from this IP, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api/', limiter);

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN || "http://localhost:3000",
  credentials: process.env.CORS_CREDENTIALS === 'true',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Data sanitization
app.use(mongoSanitize());

// Compression
app.use(compression());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: parseInt(process.env.SESSION_COOKIE_MAX_AGE) || 24 * 60 * 60 * 1000
  }
}));

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url} - ${req.ip}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version || '1.0.0'
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', authMiddleware, userRoutes);
app.use('/api/targets', authMiddleware, targetRoutes);
app.use('/api/scans', authMiddleware, scanRoutes);
app.use('/api/reports', authMiddleware, reportRoutes);
app.use('/api/billing', authMiddleware, billingRoutes);
app.use('/api/alerts', authMiddleware, alertRoutes);
app.use('/api/phishing', authMiddleware, phishingRoutes);
app.use('/api/dashboard', authMiddleware, dashboardRoutes);
app.use('/api/cicd', cicdRoutes); // No auth required for CI/CD integration

// Static files
app.use('/uploads', express.static('uploads'));

// Socket.io configuration
socketService.initialize(io);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Route not found'
  });
});

// Error handling middleware
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('HTTP server closed');
    process.exit(0);
  });
});

// Start cron jobs
cronService.startAll();

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
});

module.exports = app;