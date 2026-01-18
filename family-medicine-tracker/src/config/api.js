/**
 * API Configuration
 * API配置文件
 */

module.exports = {
  // Barcode API endpoints
  barcodeAPIs: {
    openDrug: {
      baseUrl: 'https://api.opendrug.com/v1',
      endpoints: {
        search: '/medicines',
        barcode: '/medicines/barcode'
      },
      apiKey: process.env.OPEN_DRUG_API_KEY || '',
      timeout: 5000
    },
    
    cfda: {
      baseUrl: 'https://api.cfda.gov.cn',
      endpoints: {
        barcode: '/drugs/barcode',
        search: '/drugs/search'
      },
      apiKey: process.env.CFDA_API_KEY || '',
      timeout: 5000
    },
    
    fallback: {
      baseUrl: 'https://api.medicine-tracker.com',
      endpoints: {
        barcode: '/barcode',
        search: '/search'
      },
      apiKey: process.env.FALLBACK_API_KEY || '',
      timeout: 3000
    }
  },

  // Cloud sync configuration
  cloudSync: {
    provider: 'firebase', // or 'supabase'
    
    firebase: {
      apiKey: process.env.FIREBASE_API_KEY || '',
      authDomain: process.env.FIREBASE_AUTH_DOMAIN || '',
      projectId: process.env.FIREBASE_PROJECT_ID || '',
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
      messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || '',
      appId: process.env.FIREBASE_APP_ID || ''
    },
    
    supabase: {
      url: process.env.SUPABASE_URL || '',
      anonKey: process.env.SUPABASE_ANON_KEY || ''
    }
  },

  // Notification configuration
  notifications: {
    enabled: true,
    defaultReminders: {
      oneMonthBefore: true,
      oneWeekBefore: true,
      oneDayBefore: false
    }
  }
};
