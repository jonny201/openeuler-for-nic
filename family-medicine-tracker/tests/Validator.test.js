/**
 * Validator Tests
 * 验证器测试
 */

const Validator = require('../src/utils/validator');

describe('Validator', () => {
  describe('validateMedicine', () => {
    test('should pass validation for valid medicine data', () => {
      const data = {
        name: 'Aspirin',
        expiryDate: '2025-12-31',
        quantity: 2
      };

      const result = Validator.validateMedicine(data);
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    test('should fail validation when name is missing', () => {
      const data = {
        expiryDate: '2025-12-31'
      };

      const result = Validator.validateMedicine(data);
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Medicine name is required');
    });

    test('should fail validation when expiry date is missing', () => {
      const data = {
        name: 'Aspirin'
      };

      const result = Validator.validateMedicine(data);
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Expiry date is required');
    });

    test('should fail validation for invalid expiry date', () => {
      const data = {
        name: 'Aspirin',
        expiryDate: 'invalid-date'
      };

      const result = Validator.validateMedicine(data);
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Invalid expiry date');
    });

    test('should fail validation for negative quantity', () => {
      const data = {
        name: 'Aspirin',
        expiryDate: '2025-12-31',
        quantity: -1
      };

      const result = Validator.validateMedicine(data);
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Quantity cannot be negative');
    });
  });

  describe('isValidEmail', () => {
    test('should validate correct email addresses', () => {
      expect(Validator.isValidEmail('user@example.com')).toBe(true);
      expect(Validator.isValidEmail('john.doe@company.co.uk')).toBe(true);
      expect(Validator.isValidEmail('test+tag@domain.com')).toBe(true);
    });

    test('should reject invalid email addresses', () => {
      expect(Validator.isValidEmail('invalid')).toBe(false);
      expect(Validator.isValidEmail('invalid@')).toBe(false);
      expect(Validator.isValidEmail('@example.com')).toBe(false);
      expect(Validator.isValidEmail('user@domain')).toBe(false);
    });
  });

  describe('isValidBarcode', () => {
    test('should validate EAN-13 barcode', () => {
      expect(Validator.isValidBarcode('1234567890123')).toBe(true);
    });

    test('should validate EAN-8 barcode', () => {
      expect(Validator.isValidBarcode('12345678')).toBe(true);
    });

    test('should validate UPC-A barcode', () => {
      expect(Validator.isValidBarcode('123456789012')).toBe(true);
    });

    test('should reject invalid barcodes', () => {
      expect(Validator.isValidBarcode('123')).toBe(false);
      expect(Validator.isValidBarcode('abc')).toBe(false);
      expect(Validator.isValidBarcode('')).toBe(false);
    });
  });

  describe('sanitizeString', () => {
    test('should remove HTML tags', () => {
      const input = '<script>alert("xss")</script>Hello';
      const result = Validator.sanitizeString(input);
      expect(result).not.toContain('<');
      expect(result).not.toContain('>');
    });

    test('should trim whitespace', () => {
      const input = '  Hello World  ';
      const result = Validator.sanitizeString(input);
      expect(result).toBe('Hello World');
    });

    test('should handle non-string input', () => {
      expect(Validator.sanitizeString(123)).toBe('');
      expect(Validator.sanitizeString(null)).toBe('');
      expect(Validator.sanitizeString(undefined)).toBe('');
    });
  });

  describe('isValidDateRange', () => {
    test('should validate correct date ranges', () => {
      const start = '2024-01-01';
      const end = '2024-12-31';
      expect(Validator.isValidDateRange(start, end)).toBe(true);
    });

    test('should reject invalid date ranges', () => {
      const start = '2024-12-31';
      const end = '2024-01-01';
      expect(Validator.isValidDateRange(start, end)).toBe(false);
    });

    test('should reject invalid dates', () => {
      expect(Validator.isValidDateRange('invalid', '2024-12-31')).toBe(false);
      expect(Validator.isValidDateRange('2024-01-01', 'invalid')).toBe(false);
    });
  });
});
