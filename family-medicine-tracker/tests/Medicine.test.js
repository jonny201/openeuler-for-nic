/**
 * Medicine Model Tests
 * 药品模型测试
 */

const Medicine = require('../src/models/Medicine');

describe('Medicine Model', () => {
  describe('Constructor', () => {
    test('should create medicine with required fields', () => {
      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: '2025-12-31'
      });

      expect(medicine.name).toBe('Aspirin');
      expect(medicine.expiryDate).toBeInstanceOf(Date);
      expect(medicine.id).toBeDefined();
    });

    test('should set default values', () => {
      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: '2025-12-31'
      });

      expect(medicine.quantity).toBe(1);
      expect(medicine.unit).toBe('box');
      expect(medicine.createdAt).toBeInstanceOf(Date);
    });
  });

  describe('isExpired', () => {
    test('should return true for expired medicine', () => {
      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: '2020-01-01'
      });

      expect(medicine.isExpired()).toBe(true);
    });

    test('should return false for valid medicine', () => {
      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: '2030-12-31'
      });

      expect(medicine.isExpired()).toBe(false);
    });
  });

  describe('getDaysUntilExpiry', () => {
    test('should calculate days until expiry correctly', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 30);

      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: futureDate.toISOString()
      });

      const days = medicine.getDaysUntilExpiry();
      expect(days).toBeGreaterThanOrEqual(29);
      expect(days).toBeLessThanOrEqual(31);
    });
  });

  describe('isExpiringSoon', () => {
    test('should return true for medicine expiring within 30 days', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 15);

      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: futureDate.toISOString()
      });

      expect(medicine.isExpiringSoon()).toBe(true);
    });

    test('should return false for medicine expiring after 30 days', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 60);

      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: futureDate.toISOString()
      });

      expect(medicine.isExpiringSoon()).toBe(false);
    });
  });

  describe('needsUrgentAttention', () => {
    test('should return true for medicine expiring within 7 days', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 5);

      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: futureDate.toISOString()
      });

      expect(medicine.needsUrgentAttention()).toBe(true);
    });
  });

  describe('getExpiryStatus', () => {
    test('should return "expired" for expired medicine', () => {
      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: '2020-01-01'
      });

      expect(medicine.getExpiryStatus()).toBe('expired');
    });

    test('should return "urgent" for medicine expiring within 7 days', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 5);

      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: futureDate.toISOString()
      });

      expect(medicine.getExpiryStatus()).toBe('urgent');
    });

    test('should return "soon" for medicine expiring within 30 days', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 20);

      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: futureDate.toISOString()
      });

      expect(medicine.getExpiryStatus()).toBe('soon');
    });

    test('should return "good" for medicine expiring after 30 days', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 60);

      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: futureDate.toISOString()
      });

      expect(medicine.getExpiryStatus()).toBe('good');
    });
  });

  describe('decrementQuantity', () => {
    test('should decrease quantity correctly', () => {
      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: '2025-12-31',
        quantity: 5
      });

      medicine.decrementQuantity(2);
      expect(medicine.quantity).toBe(3);
    });

    test('should not go below zero', () => {
      const medicine = new Medicine({
        name: 'Aspirin',
        expiryDate: '2025-12-31',
        quantity: 2
      });

      medicine.decrementQuantity(5);
      expect(medicine.quantity).toBe(0);
    });
  });

  describe('toJSON and fromJSON', () => {
    test('should serialize and deserialize correctly', () => {
      const original = new Medicine({
        name: 'Aspirin',
        barcode: '1234567890123',
        expiryDate: '2025-12-31',
        quantity: 3
      });

      const json = original.toJSON();
      const restored = Medicine.fromJSON(json);

      expect(restored.name).toBe(original.name);
      expect(restored.barcode).toBe(original.barcode);
      expect(restored.quantity).toBe(original.quantity);
      expect(restored.expiryDate.getTime()).toBe(original.expiryDate.getTime());
    });
  });
});
