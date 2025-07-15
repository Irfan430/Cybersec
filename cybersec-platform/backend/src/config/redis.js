const redis = require('redis');
const logger = require('./logger');

// Redis client configuration
const redisConfig = {
  url: process.env.REDIS_URL || 'redis://localhost:6379',
  password: process.env.REDIS_PASSWORD || undefined,
  socket: {
    connectTimeout: 5000,
    lazyConnect: true
  },
  retryDelayOnFailover: 100,
  enableAutoPipelining: true,
  maxRetriesPerRequest: 3
};

// Create Redis client
const client = redis.createClient(redisConfig);

// Redis event handlers
client.on('connect', () => {
  logger.info('Redis client connected');
});

client.on('ready', () => {
  logger.info('Redis client ready');
});

client.on('error', (err) => {
  logger.error('Redis client error:', err);
});

client.on('end', () => {
  logger.warn('Redis client disconnected');
});

client.on('reconnecting', () => {
  logger.info('Redis client reconnecting');
});

// Redis utility functions
const redisUtils = {
  /**
   * Set a key-value pair with optional expiration
   * @param {string} key - The key
   * @param {any} value - The value
   * @param {number} ttl - Time to live in seconds
   */
  async set(key, value, ttl = null) {
    try {
      const serializedValue = JSON.stringify(value);
      if (ttl) {
        await client.setEx(key, ttl, serializedValue);
      } else {
        await client.set(key, serializedValue);
      }
      return true;
    } catch (error) {
      logger.error('Redis SET error:', error);
      return false;
    }
  },

  /**
   * Get value by key
   * @param {string} key - The key
   */
  async get(key) {
    try {
      const value = await client.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error('Redis GET error:', error);
      return null;
    }
  },

  /**
   * Delete key
   * @param {string} key - The key
   */
  async del(key) {
    try {
      const result = await client.del(key);
      return result > 0;
    } catch (error) {
      logger.error('Redis DEL error:', error);
      return false;
    }
  },

  /**
   * Check if key exists
   * @param {string} key - The key
   */
  async exists(key) {
    try {
      const result = await client.exists(key);
      return result === 1;
    } catch (error) {
      logger.error('Redis EXISTS error:', error);
      return false;
    }
  },

  /**
   * Set expiration for key
   * @param {string} key - The key
   * @param {number} ttl - Time to live in seconds
   */
  async expire(key, ttl) {
    try {
      const result = await client.expire(key, ttl);
      return result === 1;
    } catch (error) {
      logger.error('Redis EXPIRE error:', error);
      return false;
    }
  },

  /**
   * Add item to list
   * @param {string} key - The list key
   * @param {any} value - The value to add
   */
  async lpush(key, value) {
    try {
      const serializedValue = JSON.stringify(value);
      const result = await client.lPush(key, serializedValue);
      return result;
    } catch (error) {
      logger.error('Redis LPUSH error:', error);
      return 0;
    }
  },

  /**
   * Remove and get first item from list
   * @param {string} key - The list key
   */
  async lpop(key) {
    try {
      const value = await client.lPop(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error('Redis LPOP error:', error);
      return null;
    }
  },

  /**
   * Get list length
   * @param {string} key - The list key
   */
  async llen(key) {
    try {
      const result = await client.lLen(key);
      return result;
    } catch (error) {
      logger.error('Redis LLEN error:', error);
      return 0;
    }
  },

  /**
   * Increment counter
   * @param {string} key - The counter key
   */
  async incr(key) {
    try {
      const result = await client.incr(key);
      return result;
    } catch (error) {
      logger.error('Redis INCR error:', error);
      return 0;
    }
  },

  /**
   * Get all keys matching pattern
   * @param {string} pattern - The pattern
   */
  async keys(pattern) {
    try {
      const result = await client.keys(pattern);
      return result;
    } catch (error) {
      logger.error('Redis KEYS error:', error);
      return [];
    }
  },

  /**
   * Flush all data
   */
  async flushAll() {
    try {
      await client.flushAll();
      return true;
    } catch (error) {
      logger.error('Redis FLUSHALL error:', error);
      return false;
    }
  }
};

// Attach utility functions to client
Object.assign(client, redisUtils);

module.exports = client;