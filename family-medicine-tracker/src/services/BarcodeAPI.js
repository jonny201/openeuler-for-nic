/**
 * Barcode API Service
 * 条形码API服务
 * 
 * Handles barcode scanning and medicine information retrieval
 */

class BarcodeAPIService {
  constructor() {
    // Supported barcode APIs
    this.apis = {
      // Open Drug Database API (example)
      openDrug: 'https://api.opendrug.com/v1/medicines',
      // China Food and Drug Administration (example)
      cfda: 'https://api.cfda.gov.cn/drugs/barcode',
      // Custom fallback API
      fallback: 'https://api.medicine-tracker.com/barcode'
    };
  }

  /**
   * Scan barcode and fetch medicine information
   * 扫描条形码并获取药品信息
   * 
   * @param {string} barcode - The scanned barcode
   * @returns {Promise<Object>} Medicine information
   */
  async fetchMedicineByBarcode(barcode) {
    try {
      // Try primary API first
      let result = await this.tryAPI('openDrug', barcode);
      if (result) return result;

      // Try CFDA API
      result = await this.tryAPI('cfda', barcode);
      if (result) return result;

      // Try fallback API
      result = await this.tryAPI('fallback', barcode);
      if (result) return result;

      // If all APIs fail, return null
      return null;
    } catch (error) {
      console.error('Error fetching medicine by barcode:', error);
      throw error;
    }
  }

  /**
   * Try a specific API
   * 尝试特定的API
   */
  async tryAPI(apiName, barcode) {
    try {
      const url = `${this.apis[apiName]}/${barcode}`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      return this.normalizeResponse(data, apiName);
    } catch (error) {
      console.warn(`API ${apiName} failed:`, error.message);
      return null;
    }
  }

  /**
   * Normalize different API responses to a standard format
   * 将不同API的响应标准化为统一格式
   */
  normalizeResponse(data, apiName) {
    // Each API may have different response format
    // Normalize to our standard format
    switch (apiName) {
      case 'openDrug':
        return {
          name: data.name || data.productName,
          genericName: data.genericName,
          manufacturer: data.manufacturer,
          description: data.description || data.indication,
          dosage: data.dosage || data.usage,
          sideEffects: data.sideEffects || data.adverseReactions,
          category: data.category || data.drugClass,
          imageUrl: data.imageUrl || data.packageImage
        };

      case 'cfda':
        return {
          name: data.product_name,
          genericName: data.generic_name,
          manufacturer: data.manufacturer_name,
          description: data.indications,
          dosage: data.dosage_form,
          sideEffects: data.adverse_reactions,
          category: data.category,
          imageUrl: data.image_url
        };

      case 'fallback':
        return data; // Assume fallback API already uses our format

      default:
        return data;
    }
  }

  /**
   * Validate barcode format
   * 验证条形码格式
   */
  validateBarcode(barcode) {
    // Support common barcode formats: EAN-13, UPC-A, Code128, etc.
    const patterns = {
      ean13: /^\d{13}$/,
      ean8: /^\d{8}$/,
      upca: /^\d{12}$/,
      code128: /^[\x00-\x7F]{1,128}$/
    };

    return Object.values(patterns).some(pattern => pattern.test(barcode));
  }

  /**
   * Mock barcode scan for testing
   * 模拟条形码扫描（用于测试）
   */
  async mockScan(barcode) {
    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 500));

    // Return mock data for testing
    return {
      name: '阿莫西林胶囊',
      genericName: 'Amoxicillin Capsules',
      manufacturer: '某某制药有限公司',
      description: '用于敏感菌所致的呼吸道、泌尿道、皮肤软组织感染',
      dosage: '口服，成人一次0.5g，每6-8小时1次',
      sideEffects: '恶心、呕吐、腹泻、皮疹等',
      category: '抗生素',
      imageUrl: null
    };
  }
}

module.exports = new BarcodeAPIService();
