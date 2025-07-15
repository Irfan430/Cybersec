const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const User = require('../models/User');
const { authenticate, requireEmailVerification } = require('../middleware/auth');
const { asyncHandler, validationError } = require('../middleware/errorHandler');
const logger = require('../config/logger');

const router = express.Router();

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    status: 'error',
    message: 'Too many authentication attempts, please try again later'
  }
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    status: 'error',
    message: 'Too many requests, please try again later'
  }
});

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', [
  authLimiter,
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  body('firstName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters'),
  body('phone')
    .optional()
    .isMobilePhone()
    .withMessage('Please provide a valid phone number'),
  body('organization')
    .optional()
    .trim()
    .isLength({ max: 100 })
    .withMessage('Organization name must be less than 100 characters'),
  body('acceptTerms')
    .isBoolean()
    .custom((value) => {
      if (!value) {
        throw new Error('You must accept the terms and conditions');
      }
      return true;
    })
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    throw validationError(errors.array());
  }

  const { email, password, firstName, lastName, phone, organization } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(409).json({
      status: 'error',
      message: 'User already exists with this email'
    });
  }

  // Create new user
  const user = new User({
    email,
    password,
    firstName,
    lastName,
    phone,
    organization,
    role: 'viewer', // Default role
    permissions: ['scan:read', 'target:read', 'report:read', 'dashboard:read']
  });

  // Generate email verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  user.security.emailVerificationToken = verificationToken;

  await user.save();

  // TODO: Send verification email
  // await emailService.sendVerificationEmail(user.email, verificationToken);

  logger.audit('User registered', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.status(201).json({
    status: 'success',
    message: 'User registered successfully. Please check your email to verify your account.',
    data: {
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        emailVerified: user.security.emailVerified
      }
    }
  });
}));

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', [
  authLimiter,
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    throw validationError(errors.array());
  }

  const { email, password } = req.body;

  // Find user by email with password field
  const user = await User.findOne({ email }).select('+password');
  
  if (!user || !await user.comparePassword(password)) {
    // Track failed login attempt
    if (user) {
      await user.handleFailedLogin();
    }
    
    return res.status(401).json({
      status: 'error',
      message: 'Invalid credentials'
    });
  }

  // Check if account is locked
  if (user.isLocked) {
    return res.status(423).json({
      status: 'error',
      message: 'Account is temporarily locked due to multiple failed login attempts'
    });
  }

  // Check if account is active
  if (!user.isActive || user.isDeleted) {
    return res.status(401).json({
      status: 'error',
      message: 'Account is inactive'
    });
  }

  // Handle successful login
  await user.handleSuccessfulLogin();

  // Generate JWT token
  const token = user.generateAuthToken();

  logger.audit('User logged in', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'Login successful',
    data: {
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        permissions: user.permissions,
        emailVerified: user.security.emailVerified,
        subscription: user.subscription
      }
    }
  });
}));

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout', authenticate, asyncHandler(async (req, res) => {
  // In a stateless JWT system, logout is handled client-side
  // But we can log the logout event for audit purposes
  
  logger.audit('User logged out', {
    userId: req.user._id,
    email: req.user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'Logout successful'
  });
}));

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post('/forgot-password', [
  generalLimiter,
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    throw validationError(errors.array());
  }

  const { email } = req.body;

  const user = await User.findOne({ email });
  
  // Don't reveal if user exists or not
  if (!user) {
    return res.json({
      status: 'success',
      message: 'If an account with that email exists, we have sent a password reset link'
    });
  }

  // Generate password reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  user.security.passwordResetToken = resetToken;
  user.security.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await user.save();

  // TODO: Send password reset email
  // await emailService.sendPasswordResetEmail(user.email, resetToken);

  logger.audit('Password reset requested', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'If an account with that email exists, we have sent a password reset link'
  });
}));

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password', [
  generalLimiter,
  body('token')
    .notEmpty()
    .withMessage('Reset token is required'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    throw validationError(errors.array());
  }

  const { token, password } = req.body;

  const user = await User.findOne({
    'security.passwordResetToken': token,
    'security.passwordResetExpires': { $gt: Date.now() }
  });

  if (!user) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid or expired reset token'
    });
  }

  // Update password
  user.password = password;
  user.security.passwordResetToken = undefined;
  user.security.passwordResetExpires = undefined;
  user.security.loginAttempts = 0;
  user.security.lockUntil = undefined;

  await user.save();

  logger.audit('Password reset completed', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'Password reset successful'
  });
}));

/**
 * @route   POST /api/auth/verify-email
 * @desc    Verify email address
 * @access  Public
 */
router.post('/verify-email', [
  generalLimiter,
  body('token')
    .notEmpty()
    .withMessage('Verification token is required')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    throw validationError(errors.array());
  }

  const { token } = req.body;

  const user = await User.findOne({
    'security.emailVerificationToken': token
  });

  if (!user) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid verification token'
    });
  }

  // Mark email as verified
  user.security.emailVerified = true;
  user.security.emailVerifiedAt = new Date();
  user.security.emailVerificationToken = undefined;

  await user.save();

  logger.audit('Email verified', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'Email verified successfully'
  });
}));

/**
 * @route   POST /api/auth/resend-verification
 * @desc    Resend email verification
 * @access  Private
 */
router.post('/resend-verification', [
  authenticate,
  generalLimiter
], asyncHandler(async (req, res) => {
  const user = req.user;

  if (user.security.emailVerified) {
    return res.status(400).json({
      status: 'error',
      message: 'Email is already verified'
    });
  }

  // Generate new verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  user.security.emailVerificationToken = verificationToken;

  await user.save();

  // TODO: Send verification email
  // await emailService.sendVerificationEmail(user.email, verificationToken);

  logger.audit('Email verification resent', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'Verification email sent'
  });
}));

/**
 * @route   POST /api/auth/change-password
 * @desc    Change password for authenticated user
 * @access  Private
 */
router.post('/change-password', [
  authenticate,
  requireEmailVerification,
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], asyncHandler(async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    throw validationError(errors.array());
  }

  const { currentPassword, newPassword } = req.body;
  const user = await User.findById(req.user._id).select('+password');

  // Verify current password
  if (!await user.comparePassword(currentPassword)) {
    return res.status(400).json({
      status: 'error',
      message: 'Current password is incorrect'
    });
  }

  // Update password
  user.password = newPassword;
  await user.save();

  logger.audit('Password changed', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'Password changed successfully'
  });
}));

/**
 * @route   GET /api/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me', authenticate, asyncHandler(async (req, res) => {
  const user = req.user;

  res.json({
    status: 'success',
    data: {
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
        avatar: user.avatar,
        role: user.role,
        permissions: user.permissions,
        organization: user.organization,
        team: user.team,
        subscription: user.subscription,
        usage: user.usage,
        notifications: user.notifications,
        emailVerified: user.security.emailVerified,
        twoFactorEnabled: user.security.twoFactorEnabled,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }
    }
  });
}));

/**
 * @route   POST /api/auth/generate-api-key
 * @desc    Generate API key for authenticated user
 * @access  Private
 */
router.post('/generate-api-key', [
  authenticate,
  requireEmailVerification
], asyncHandler(async (req, res) => {
  const user = req.user;

  // Generate new API key
  const apiKey = user.generateApiKey();
  await user.save();

  logger.audit('API key generated', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'API key generated successfully',
    data: {
      apiKey,
      createdAt: user.apiKeyCreatedAt
    }
  });
}));

/**
 * @route   DELETE /api/auth/revoke-api-key
 * @desc    Revoke API key for authenticated user
 * @access  Private
 */
router.delete('/revoke-api-key', authenticate, asyncHandler(async (req, res) => {
  const user = req.user;

  user.apiKey = undefined;
  user.apiKeyCreatedAt = undefined;
  user.apiKeyLastUsed = undefined;

  await user.save();

  logger.audit('API key revoked', {
    userId: user._id,
    email: user.email,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  res.json({
    status: 'success',
    message: 'API key revoked successfully'
  });
}));

module.exports = router;