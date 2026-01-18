/**
 * Date Helper Utilities
 * 日期处理工具函数
 */

class DateHelper {
  /**
   * Format date to locale string
   * 格式化日期为本地字符串
   */
  static formatDate(date, locale = 'zh-CN') {
    return new Date(date).toLocaleDateString(locale, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    });
  }

  /**
   * Format datetime to locale string
   * 格式化日期时间为本地字符串
   */
  static formatDateTime(date, locale = 'zh-CN') {
    return new Date(date).toLocaleString(locale, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  /**
   * Get days between two dates
   * 计算两个日期之间的天数
   */
  static getDaysBetween(date1, date2) {
    const oneDay = 24 * 60 * 60 * 1000;
    const diffTime = Math.abs(new Date(date2) - new Date(date1));
    return Math.ceil(diffTime / oneDay);
  }

  /**
   * Check if date is in the past
   * 检查日期是否已过去
   */
  static isPast(date) {
    return new Date(date) < new Date();
  }

  /**
   * Check if date is today
   * 检查是否为今天
   */
  static isToday(date) {
    const today = new Date();
    const checkDate = new Date(date);
    return (
      checkDate.getDate() === today.getDate() &&
      checkDate.getMonth() === today.getMonth() &&
      checkDate.getFullYear() === today.getFullYear()
    );
  }

  /**
   * Get relative time string
   * 获取相对时间字符串
   */
  static getRelativeTime(date, locale = 'zh-CN') {
    const now = new Date();
    const targetDate = new Date(date);
    const diffSeconds = Math.floor((now - targetDate) / 1000);

    if (locale === 'zh-CN') {
      if (diffSeconds < 60) return '刚刚';
      if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}分钟前`;
      if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}小时前`;
      if (diffSeconds < 604800) return `${Math.floor(diffSeconds / 86400)}天前`;
      return this.formatDate(date, locale);
    } else {
      if (diffSeconds < 60) return 'just now';
      if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)} minutes ago`;
      if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)} hours ago`;
      if (diffSeconds < 604800) return `${Math.floor(diffSeconds / 86400)} days ago`;
      return this.formatDate(date, locale);
    }
  }

  /**
   * Add days to date
   * 给日期增加天数
   */
  static addDays(date, days) {
    const result = new Date(date);
    result.setDate(result.getDate() + days);
    return result;
  }

  /**
   * Subtract days from date
   * 从日期减去天数
   */
  static subtractDays(date, days) {
    return this.addDays(date, -days);
  }

  /**
   * Get start of day
   * 获取当天开始时间
   */
  static getStartOfDay(date) {
    const result = new Date(date);
    result.setHours(0, 0, 0, 0);
    return result;
  }

  /**
   * Get end of day
   * 获取当天结束时间
   */
  static getEndOfDay(date) {
    const result = new Date(date);
    result.setHours(23, 59, 59, 999);
    return result;
  }
}

module.exports = DateHelper;
