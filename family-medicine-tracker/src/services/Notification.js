/**
 * Notification Service
 * 通知服务
 * 
 * Handles expiry reminders and medication notifications
 */

class NotificationService {
  constructor() {
    this.scheduledNotifications = new Map();
  }

  /**
   * Schedule expiry reminder notification
   * 安排过期提醒通知
   * 
   * @param {Medicine} medicine - The medicine object
   * @param {User} user - The user object
   */
  async scheduleExpiryReminder(medicine, user) {
    try {
      const preferences = user.preferences.notifications;
      
      // Schedule 1 month before expiry
      if (preferences.oneMonthBefore) {
        await this.scheduleNotification({
          id: `expiry_30_${medicine.id}`,
          title: '药品即将过期提醒',
          body: `${medicine.name} 将在30天后过期，请注意检查！`,
          triggerDate: this.getDateBeforeExpiry(medicine.expiryDate, 30),
          data: {
            type: 'expiry_warning',
            medicineId: medicine.id,
            daysUntilExpiry: 30
          }
        });
      }

      // Schedule 1 week before expiry
      if (preferences.oneWeekBefore) {
        await this.scheduleNotification({
          id: `expiry_7_${medicine.id}`,
          title: '药品即将过期警告',
          body: `${medicine.name} 将在7天后过期，请尽快使用或处理！`,
          triggerDate: this.getDateBeforeExpiry(medicine.expiryDate, 7),
          data: {
            type: 'expiry_urgent',
            medicineId: medicine.id,
            daysUntilExpiry: 7
          }
        });
      }

      // Schedule 1 day before expiry
      if (preferences.oneDayBefore) {
        await this.scheduleNotification({
          id: `expiry_1_${medicine.id}`,
          title: '药品明天过期！',
          body: `${medicine.name} 明天就要过期了！`,
          triggerDate: this.getDateBeforeExpiry(medicine.expiryDate, 1),
          data: {
            type: 'expiry_critical',
            medicineId: medicine.id,
            daysUntilExpiry: 1
          }
        });
      }

      return true;
    } catch (error) {
      console.error('Error scheduling expiry reminder:', error);
      throw error;
    }
  }

  /**
   * Schedule a notification
   * 安排一个通知
   */
  async scheduleNotification({ id, title, body, triggerDate, data }) {
    try {
      // In React Native, this would use react-native-push-notification
      // For now, we'll use a mock implementation
      const notification = {
        id,
        title,
        body,
        triggerDate,
        data,
        scheduled: new Date()
      };

      this.scheduledNotifications.set(id, notification);
      
      console.log(`Scheduled notification: ${title} for ${triggerDate}`);
      
      return notification;
    } catch (error) {
      console.error('Error scheduling notification:', error);
      throw error;
    }
  }

  /**
   * Cancel a notification
   * 取消通知
   */
  async cancelNotification(id) {
    try {
      this.scheduledNotifications.delete(id);
      console.log(`Cancelled notification: ${id}`);
      return true;
    } catch (error) {
      console.error('Error cancelling notification:', error);
      throw error;
    }
  }

  /**
   * Cancel all expiry notifications for a medicine
   * 取消药品的所有过期通知
   */
  async cancelExpiryNotifications(medicineId) {
    try {
      const ids = [
        `expiry_30_${medicineId}`,
        `expiry_7_${medicineId}`,
        `expiry_1_${medicineId}`
      ];

      for (const id of ids) {
        await this.cancelNotification(id);
      }

      return true;
    } catch (error) {
      console.error('Error cancelling expiry notifications:', error);
      throw error;
    }
  }

  /**
   * Send immediate notification
   * 发送即时通知
   */
  async sendNotification({ title, body, data }) {
    try {
      // In React Native, this would trigger an immediate notification
      console.log(`Sending notification: ${title} - ${body}`);
      
      return {
        title,
        body,
        data,
        sent: new Date()
      };
    } catch (error) {
      console.error('Error sending notification:', error);
      throw error;
    }
  }

  /**
   * Get date before expiry
   * 获取过期前的日期
   */
  getDateBeforeExpiry(expiryDate, daysBefore) {
    const date = new Date(expiryDate);
    date.setDate(date.getDate() - daysBefore);
    return date;
  }

  /**
   * Get all scheduled notifications
   * 获取所有已安排的通知
   */
  getScheduledNotifications() {
    return Array.from(this.scheduledNotifications.values());
  }

  /**
   * Check and send due notifications
   * 检查并发送到期的通知
   */
  async checkDueNotifications() {
    const now = new Date();
    const dueNotifications = [];

    for (const [id, notification] of this.scheduledNotifications) {
      if (notification.triggerDate <= now) {
        await this.sendNotification(notification);
        dueNotifications.push(notification);
        this.scheduledNotifications.delete(id);
      }
    }

    return dueNotifications;
  }
}

module.exports = new NotificationService();
