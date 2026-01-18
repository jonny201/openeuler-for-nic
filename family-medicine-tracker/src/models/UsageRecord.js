/**
 * UsageRecord Model
 * 用药记录数据模型
 * 
 * Represents a medication usage record
 */

class UsageRecord {
  constructor({
    id,
    medicineId,
    userId,
    userName,
    timestamp,
    quantity,
    notes,
    createdAt
  }) {
    this.id = id || this.generateId();
    this.medicineId = medicineId;
    this.userId = userId;
    this.userName = userName;
    this.timestamp = timestamp || new Date();
    this.quantity = quantity || 1;
    this.notes = notes;
    this.createdAt = createdAt || new Date();
  }

  /**
   * Generate unique ID for usage record
   */
  generateId() {
    return `usage_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get formatted timestamp
   * 获取格式化的时间戳
   */
  getFormattedTimestamp() {
    return this.timestamp.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  /**
   * Check if usage was today
   * 检查是否为今天的用药记录
   */
  isToday() {
    const today = new Date();
    return (
      this.timestamp.getDate() === today.getDate() &&
      this.timestamp.getMonth() === today.getMonth() &&
      this.timestamp.getFullYear() === today.getFullYear()
    );
  }

  /**
   * Get usage summary
   * 获取用药摘要
   */
  getSummary() {
    return `${this.userName} took ${this.quantity} dose(s) at ${this.getFormattedTimestamp()}`;
  }

  /**
   * Convert to JSON for storage
   * 转换为JSON格式用于存储
   */
  toJSON() {
    return {
      id: this.id,
      medicineId: this.medicineId,
      userId: this.userId,
      userName: this.userName,
      timestamp: this.timestamp.toISOString(),
      quantity: this.quantity,
      notes: this.notes,
      createdAt: this.createdAt.toISOString()
    };
  }

  /**
   * Create UsageRecord instance from JSON
   * 从JSON创建UsageRecord实例
   */
  static fromJSON(json) {
    return new UsageRecord({
      ...json,
      timestamp: new Date(json.timestamp),
      createdAt: new Date(json.createdAt)
    });
  }
}

module.exports = UsageRecord;
