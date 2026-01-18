/**
 * Medicine Model
 * 药品数据模型
 * 
 * Represents a medicine item in the family medicine cabinet
 */

class Medicine {
  constructor({
    id,
    barcode,
    name,
    genericName,
    manufacturer,
    description,
    dosage,
    sideEffects,
    category,
    expiryDate,
    purchaseDate,
    quantity,
    unit,
    storage,
    imageUrl,
    userId,
    familyGroupId,
    createdAt,
    updatedAt
  }) {
    this.id = id || this.generateId();
    this.barcode = barcode;
    this.name = name;
    this.genericName = genericName;
    this.manufacturer = manufacturer;
    this.description = description;
    this.dosage = dosage;
    this.sideEffects = sideEffects;
    this.category = category;
    this.expiryDate = new Date(expiryDate);
    this.purchaseDate = purchaseDate ? new Date(purchaseDate) : new Date();
    this.quantity = quantity || 1;
    this.unit = unit || 'box';
    this.storage = storage;
    this.imageUrl = imageUrl;
    this.userId = userId;
    this.familyGroupId = familyGroupId;
    this.createdAt = createdAt || new Date();
    this.updatedAt = updatedAt || new Date();
  }

  /**
   * Generate unique ID for medicine
   */
  generateId() {
    return `med_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Check if medicine is expired
   * 检查药品是否已过期
   */
  isExpired() {
    return new Date() > this.expiryDate;
  }

  /**
   * Get days until expiry
   * 获取距离过期的天数
   */
  getDaysUntilExpiry() {
    const today = new Date();
    const timeDiff = this.expiryDate.getTime() - today.getTime();
    return Math.ceil(timeDiff / (1000 * 3600 * 24));
  }

  /**
   * Check if medicine is expiring soon (within 30 days)
   * 检查药品是否即将过期（30天内）
   */
  isExpiringSoon() {
    const daysUntilExpiry = this.getDaysUntilExpiry();
    return daysUntilExpiry > 0 && daysUntilExpiry <= 30;
  }

  /**
   * Check if medicine needs urgent attention (within 7 days)
   * 检查药品是否需要紧急关注（7天内）
   */
  needsUrgentAttention() {
    const daysUntilExpiry = this.getDaysUntilExpiry();
    return daysUntilExpiry > 0 && daysUntilExpiry <= 7;
  }

  /**
   * Get expiry status
   * 获取过期状态
   * @returns {string} 'expired', 'urgent', 'soon', 'good'
   */
  getExpiryStatus() {
    if (this.isExpired()) {
      return 'expired';
    } else if (this.needsUrgentAttention()) {
      return 'urgent';
    } else if (this.isExpiringSoon()) {
      return 'soon';
    }
    return 'good';
  }

  /**
   * Update quantity after usage
   * 使用后更新数量
   */
  decrementQuantity(amount = 1) {
    this.quantity = Math.max(0, this.quantity - amount);
    this.updatedAt = new Date();
  }

  /**
   * Convert to JSON for storage
   * 转换为JSON格式用于存储
   */
  toJSON() {
    return {
      id: this.id,
      barcode: this.barcode,
      name: this.name,
      genericName: this.genericName,
      manufacturer: this.manufacturer,
      description: this.description,
      dosage: this.dosage,
      sideEffects: this.sideEffects,
      category: this.category,
      expiryDate: this.expiryDate.toISOString(),
      purchaseDate: this.purchaseDate.toISOString(),
      quantity: this.quantity,
      unit: this.unit,
      storage: this.storage,
      imageUrl: this.imageUrl,
      userId: this.userId,
      familyGroupId: this.familyGroupId,
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString()
    };
  }

  /**
   * Create Medicine instance from JSON
   * 从JSON创建Medicine实例
   */
  static fromJSON(json) {
    return new Medicine(json);
  }
}

module.exports = Medicine;
