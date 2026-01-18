/**
 * User Model
 * 用户数据模型
 * 
 * Represents a user of the application
 */

class User {
  constructor({
    id,
    username,
    email,
    displayName,
    avatar,
    role,
    familyGroupId,
    preferences,
    createdAt,
    updatedAt
  }) {
    this.id = id || this.generateId();
    this.username = username;
    this.email = email;
    this.displayName = displayName;
    this.avatar = avatar;
    this.role = role || 'member'; // 'admin', 'member', 'viewer'
    this.familyGroupId = familyGroupId;
    this.preferences = preferences || this.getDefaultPreferences();
    this.createdAt = createdAt || new Date();
    this.updatedAt = updatedAt || new Date();
  }

  /**
   * Generate unique ID for user
   */
  generateId() {
    return `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get default user preferences
   * 获取默认用户偏好设置
   */
  getDefaultPreferences() {
    return {
      notifications: {
        expiryReminders: true,
        oneMonthBefore: true,
        oneWeekBefore: true,
        oneDayBefore: false,
        usageReminders: true
      },
      language: 'zh-CN',
      theme: 'light'
    };
  }

  /**
   * Update user preferences
   * 更新用户偏好设置
   */
  updatePreferences(newPreferences) {
    this.preferences = { ...this.preferences, ...newPreferences };
    this.updatedAt = new Date();
  }

  /**
   * Check if user is admin
   * 检查用户是否为管理员
   */
  isAdmin() {
    return this.role === 'admin';
  }

  /**
   * Check if user can edit
   * 检查用户是否可以编辑
   */
  canEdit() {
    return this.role === 'admin' || this.role === 'member';
  }

  /**
   * Convert to JSON for storage
   * 转换为JSON格式用于存储
   */
  toJSON() {
    return {
      id: this.id,
      username: this.username,
      email: this.email,
      displayName: this.displayName,
      avatar: this.avatar,
      role: this.role,
      familyGroupId: this.familyGroupId,
      preferences: this.preferences,
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString()
    };
  }

  /**
   * Create User instance from JSON
   * 从JSON创建User实例
   */
  static fromJSON(json) {
    return new User(json);
  }
}

module.exports = User;
