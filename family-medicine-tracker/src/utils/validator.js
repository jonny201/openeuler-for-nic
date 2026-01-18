/**
 * Validator Utilities
 * 数据验证工具函数
 */

class Validator {
  /**
   * Validate medicine data
   * 验证药品数据
   */
  static validateMedicine(data) {
    const errors = [];

    if (!data.name || data.name.trim() === '') {
      errors.push('Medicine name is required');
    }

    if (!data.expiryDate) {
      errors.push('Expiry date is required');
    } else {
      const expiryDate = new Date(data.expiryDate);
      if (isNaN(expiryDate.getTime())) {
        errors.push('Invalid expiry date');
      }
    }

    if (data.quantity !== undefined && data.quantity < 0) {
      errors.push('Quantity cannot be negative');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate user data
   * 验证用户数据
   */
  static validateUser(data) {
    const errors = [];

    if (!data.username || data.username.trim() === '') {
      errors.push('Username is required');
    }

    if (data.email && !this.isValidEmail(data.email)) {
      errors.push('Invalid email format');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate usage record data
   * 验证用药记录数据
   */
  static validateUsageRecord(data) {
    const errors = [];

    if (!data.medicineId) {
      errors.push('Medicine ID is required');
    }

    if (!data.userId) {
      errors.push('User ID is required');
    }

    if (data.quantity !== undefined && data.quantity <= 0) {
      errors.push('Quantity must be greater than 0');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate email format
   * 验证邮箱格式
   */
  static isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validate barcode format
   * 验证条形码格式
   */
  static isValidBarcode(barcode) {
    // Support common barcode formats
    const patterns = {
      ean13: /^\d{13}$/,
      ean8: /^\d{8}$/,
      upca: /^\d{12}$/,
      code128: /^[\x00-\x7F]{1,128}$/
    };

    return Object.values(patterns).some(pattern => pattern.test(barcode));
  }

  /**
   * Sanitize string input
   * 清理字符串输入
   */
  static sanitizeString(str) {
    if (typeof str !== 'string') return '';
    return str.trim().replace(/[<>]/g, '');
  }

  /**
   * Validate date range
   * 验证日期范围
   */
  static isValidDateRange(startDate, endDate) {
    const start = new Date(startDate);
    const end = new Date(endDate);
    
    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      return false;
    }
    
    return start <= end;
  }
}

module.exports = Validator;
