/**
 * Application Configuration
 * 应用配置文件
 */

module.exports = {
  app: {
    name: 'Family Medicine Tracker',
    nameCN: '家庭药箱管家',
    version: '1.0.0',
    description: 'A mobile application to help families manage their medicine cabinet',
    descriptionCN: '帮助家庭管理药品、追踪有效期、防止药品浪费的移动应用'
  },

  // Default user preferences
  defaultPreferences: {
    language: 'zh-CN',
    theme: 'light',
    notifications: {
      expiryReminders: true,
      oneMonthBefore: true,
      oneWeekBefore: true,
      oneDayBefore: false,
      usageReminders: true
    }
  },

  // Medicine categories
  medicineCategories: [
    { id: 'antibiotics', name: '抗生素', nameEN: 'Antibiotics' },
    { id: 'painkillers', name: '止痛药', nameEN: 'Painkillers' },
    { id: 'cold', name: '感冒药', nameEN: 'Cold Medicine' },
    { id: 'stomach', name: '胃药', nameEN: 'Stomach Medicine' },
    { id: 'vitamins', name: '维生素', nameEN: 'Vitamins' },
    { id: 'supplements', name: '保健品', nameEN: 'Supplements' },
    { id: 'external', name: '外用药', nameEN: 'External Use' },
    { id: 'chronic', name: '慢性病药', nameEN: 'Chronic Disease' },
    { id: 'other', name: '其他', nameEN: 'Other' }
  ],

  // Storage locations
  storageLocations: [
    { id: 'drawer', name: '抽屉', nameEN: 'Drawer' },
    { id: 'cabinet', name: '柜子', nameEN: 'Cabinet' },
    { id: 'refrigerator', name: '冰箱', nameEN: 'Refrigerator' },
    { id: 'bedside', name: '床头', nameEN: 'Bedside' },
    { id: 'other', name: '其他', nameEN: 'Other' }
  ],

  // Units
  units: [
    { id: 'box', name: '盒', nameEN: 'Box' },
    { id: 'bottle', name: '瓶', nameEN: 'Bottle' },
    { id: 'tablet', name: '片', nameEN: 'Tablet' },
    { id: 'capsule', name: '粒', nameEN: 'Capsule' },
    { id: 'ml', name: '毫升', nameEN: 'ml' },
    { id: 'g', name: '克', nameEN: 'g' },
    { id: 'bag', name: '袋', nameEN: 'Bag' }
  ],

  // Expiry warning thresholds (in days)
  expiryThresholds: {
    urgent: 7,    // Show as urgent warning
    soon: 30,     // Show as expiring soon
    good: 365     // Consider as good condition
  },

  // User roles
  userRoles: [
    { id: 'admin', name: '管理员', nameEN: 'Admin' },
    { id: 'member', name: '成员', nameEN: 'Member' },
    { id: 'viewer', name: '访客', nameEN: 'Viewer' }
  ],

  // Feature flags
  features: {
    barcodeScanning: true,
    cloudSync: true,
    familySharing: true,
    usageTracking: true,
    expiryReminders: true,
    ocr: false  // Future feature
  }
};
