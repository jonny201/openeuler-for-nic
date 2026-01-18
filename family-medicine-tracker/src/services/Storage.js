/**
 * Storage Service
 * 本地存储服务
 * 
 * Handles local data storage using AsyncStorage
 */

const Medicine = require('../models/Medicine');
const User = require('../models/User');
const UsageRecord = require('../models/UsageRecord');
const FamilyGroup = require('../models/FamilyGroup');

class StorageService {
  constructor() {
    this.KEYS = {
      MEDICINES: '@medicines',
      USERS: '@users',
      USAGE_RECORDS: '@usage_records',
      FAMILY_GROUPS: '@family_groups',
      CURRENT_USER: '@current_user'
    };
  }

  /**
   * Save data to storage
   * 保存数据到存储
   */
  async save(key, data) {
    try {
      const jsonData = JSON.stringify(data);
      // In React Native, this would use AsyncStorage
      // For now, we'll use a mock implementation
      await this.mockAsyncStorage.setItem(key, jsonData);
      return true;
    } catch (error) {
      console.error('Error saving data:', error);
      throw error;
    }
  }

  /**
   * Load data from storage
   * 从存储加载数据
   */
  async load(key) {
    try {
      const jsonData = await this.mockAsyncStorage.getItem(key);
      return jsonData ? JSON.parse(jsonData) : null;
    } catch (error) {
      console.error('Error loading data:', error);
      throw error;
    }
  }

  /**
   * Delete data from storage
   * 从存储删除数据
   */
  async delete(key) {
    try {
      await this.mockAsyncStorage.removeItem(key);
      return true;
    } catch (error) {
      console.error('Error deleting data:', error);
      throw error;
    }
  }

  /**
   * Save medicines
   * 保存药品列表
   */
  async saveMedicines(medicines) {
    const data = medicines.map(m => m.toJSON());
    return await this.save(this.KEYS.MEDICINES, data);
  }

  /**
   * Load medicines
   * 加载药品列表
   */
  async loadMedicines() {
    const data = await this.load(this.KEYS.MEDICINES);
    return data ? data.map(m => Medicine.fromJSON(m)) : [];
  }

  /**
   * Save usage records
   * 保存用药记录
   */
  async saveUsageRecords(records) {
    const data = records.map(r => r.toJSON());
    return await this.save(this.KEYS.USAGE_RECORDS, data);
  }

  /**
   * Load usage records
   * 加载用药记录
   */
  async loadUsageRecords() {
    const data = await this.load(this.KEYS.USAGE_RECORDS);
    return data ? data.map(r => UsageRecord.fromJSON(r)) : [];
  }

  /**
   * Save current user
   * 保存当前用户
   */
  async saveCurrentUser(user) {
    return await this.save(this.KEYS.CURRENT_USER, user.toJSON());
  }

  /**
   * Load current user
   * 加载当前用户
   */
  async loadCurrentUser() {
    const data = await this.load(this.KEYS.CURRENT_USER);
    return data ? User.fromJSON(data) : null;
  }

  /**
   * Save family group
   * 保存家庭组
   */
  async saveFamilyGroup(group) {
    return await this.save(this.KEYS.FAMILY_GROUPS, group.toJSON());
  }

  /**
   * Load family group
   * 加载家庭组
   */
  async loadFamilyGroup() {
    const data = await this.load(this.KEYS.FAMILY_GROUPS);
    return data ? FamilyGroup.fromJSON(data) : null;
  }

  /**
   * Clear all data
   * 清空所有数据
   */
  async clearAll() {
    try {
      await this.delete(this.KEYS.MEDICINES);
      await this.delete(this.KEYS.USAGE_RECORDS);
      await this.delete(this.KEYS.CURRENT_USER);
      await this.delete(this.KEYS.FAMILY_GROUPS);
      return true;
    } catch (error) {
      console.error('Error clearing all data:', error);
      throw error;
    }
  }

  /**
   * Mock AsyncStorage implementation
   * This would be replaced with actual AsyncStorage in React Native
   */
  mockAsyncStorage = {
    storage: new Map(),
    
    async setItem(key, value) {
      this.storage.set(key, value);
      return Promise.resolve();
    },
    
    async getItem(key) {
      return Promise.resolve(this.storage.get(key) || null);
    },
    
    async removeItem(key) {
      this.storage.delete(key);
      return Promise.resolve();
    },
    
    async clear() {
      this.storage.clear();
      return Promise.resolve();
    }
  };
}

module.exports = new StorageService();
