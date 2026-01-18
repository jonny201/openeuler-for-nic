/**
 * FamilyGroup Model
 * 家庭组数据模型
 * 
 * Represents a family group for sharing medicine information
 */

class FamilyGroup {
  constructor({
    id,
    name,
    adminUserId,
    memberIds,
    inviteCode,
    createdAt,
    updatedAt
  }) {
    this.id = id || this.generateId();
    this.name = name;
    this.adminUserId = adminUserId;
    this.memberIds = memberIds || [];
    this.inviteCode = inviteCode || this.generateInviteCode();
    this.createdAt = createdAt || new Date();
    this.updatedAt = updatedAt || new Date();
  }

  /**
   * Generate unique ID for family group
   */
  generateId() {
    return `group_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Generate invite code for family group
   * 生成家庭组邀请码
   */
  generateInviteCode() {
    return Math.random().toString(36).substr(2, 8).toUpperCase();
  }

  /**
   * Add member to family group
   * 添加成员到家庭组
   */
  addMember(userId) {
    if (!this.memberIds.includes(userId)) {
      this.memberIds.push(userId);
      this.updatedAt = new Date();
      return true;
    }
    return false;
  }

  /**
   * Remove member from family group
   * 从家庭组移除成员
   */
  removeMember(userId) {
    const index = this.memberIds.indexOf(userId);
    if (index > -1) {
      this.memberIds.splice(index, 1);
      this.updatedAt = new Date();
      return true;
    }
    return false;
  }

  /**
   * Check if user is member
   * 检查用户是否为成员
   */
  isMember(userId) {
    return this.memberIds.includes(userId);
  }

  /**
   * Check if user is admin
   * 检查用户是否为管理员
   */
  isAdmin(userId) {
    return this.adminUserId === userId;
  }

  /**
   * Get member count
   * 获取成员数量
   */
  getMemberCount() {
    return this.memberIds.length;
  }

  /**
   * Convert to JSON for storage
   * 转换为JSON格式用于存储
   */
  toJSON() {
    return {
      id: this.id,
      name: this.name,
      adminUserId: this.adminUserId,
      memberIds: this.memberIds,
      inviteCode: this.inviteCode,
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString()
    };
  }

  /**
   * Create FamilyGroup instance from JSON
   * 从JSON创建FamilyGroup实例
   */
  static fromJSON(json) {
    return new FamilyGroup({
      ...json,
      createdAt: new Date(json.createdAt),
      updatedAt: new Date(json.updatedAt)
    });
  }
}

module.exports = FamilyGroup;
