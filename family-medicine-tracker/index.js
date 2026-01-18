/**
 * Family Medicine Tracker - Main Entry Point
 * 家庭药箱管家 - 主入口文件
 * 
 * This is the main entry point for the Family Medicine Tracker application.
 * It exports all the core modules, models, services, and utilities.
 */

// Models
const Medicine = require('./src/models/Medicine');
const User = require('./src/models/User');
const UsageRecord = require('./src/models/UsageRecord');
const FamilyGroup = require('./src/models/FamilyGroup');

// Services
const BarcodeAPI = require('./src/services/BarcodeAPI');
const Storage = require('./src/services/Storage');
const Notification = require('./src/services/Notification');
const CloudSync = require('./src/services/CloudSync');

// Utils
const DateHelper = require('./src/utils/dateHelper');
const Validator = require('./src/utils/validator');

// Config
const apiConfig = require('./src/config/api');
const appConfig = require('./src/config/app');

/**
 * Main Application Class
 * 主应用程序类
 */
class FamilyMedicineTracker {
  constructor() {
    this.version = '1.0.0';
    this.initialized = false;
  }

  /**
   * Initialize the application
   * 初始化应用程序
   */
  async initialize(config = {}) {
    try {
      console.log('Initializing Family Medicine Tracker...');

      // Initialize cloud sync if enabled
      if (config.cloudSync?.enabled) {
        await CloudSync.initialize(config.cloudSync);
        CloudSync.setSyncEnabled(true);
      }

      this.initialized = true;
      console.log('Family Medicine Tracker initialized successfully');
      return true;
    } catch (error) {
      console.error('Failed to initialize Family Medicine Tracker:', error);
      throw error;
    }
  }

  /**
   * Get application version
   * 获取应用版本
   */
  getVersion() {
    return this.version;
  }

  /**
   * Check if application is initialized
   * 检查应用是否已初始化
   */
  isInitialized() {
    return this.initialized;
  }
}

// Export everything
module.exports = {
  // Main app
  FamilyMedicineTracker,

  // Models
  Medicine,
  User,
  UsageRecord,
  FamilyGroup,

  // Services
  BarcodeAPI,
  Storage,
  Notification,
  CloudSync,

  // Utils
  DateHelper,
  Validator,

  // Config
  apiConfig,
  appConfig
};

// For convenience, also export a default instance
module.exports.default = new FamilyMedicineTracker();
