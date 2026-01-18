# API Documentation

## Overview

The Family Medicine Tracker app integrates with several APIs to provide medicine information, barcode scanning, and cloud synchronization.

## 药品数据API (Medicine Database APIs)

### 1. Barcode Scanning API

#### Fetch Medicine by Barcode

**Endpoint:** `GET /medicines/barcode/{barcode}`

**Description:** Retrieve medicine information using barcode

**Request:**
```javascript
const BarcodeAPI = require('./src/services/BarcodeAPI');

// Scan barcode and fetch medicine info
const medicineInfo = await BarcodeAPI.fetchMedicineByBarcode('1234567890123');
```

**Response:**
```json
{
  "name": "阿莫西林胶囊",
  "genericName": "Amoxicillin Capsules",
  "manufacturer": "某某制药有限公司",
  "description": "用于敏感菌所致的呼吸道、泌尿道、皮肤软组织感染",
  "dosage": "口服，成人一次0.5g，每6-8小时1次",
  "sideEffects": "恶心、呕吐、腹泻、皮疹等",
  "category": "抗生素",
  "imageUrl": "https://example.com/image.jpg"
}
```

### 2. Supported Barcode Formats

- **EAN-13**: 13-digit European Article Number
- **EAN-8**: 8-digit European Article Number
- **UPC-A**: 12-digit Universal Product Code
- **Code 128**: Variable length alphanumeric

## 云同步API (Cloud Sync APIs)

### Firebase/Supabase Integration

The app supports both Firebase and Supabase for cloud storage and synchronization.

#### Initialize Cloud Sync

```javascript
const CloudSync = require('./src/services/CloudSync');

// Firebase configuration
await CloudSync.initialize({
  provider: 'firebase',
  config: {
    apiKey: 'YOUR_API_KEY',
    authDomain: 'your-app.firebaseapp.com',
    projectId: 'your-project-id'
  }
});
```

#### Sync Data

```javascript
// Sync medicines to cloud
await CloudSync.syncMedicines(medicinesArray);

// Sync usage records
await CloudSync.syncUsageRecords(recordsArray);

// Fetch from cloud
const medicines = await CloudSync.fetchMedicines(familyGroupId);
```

## 通知API (Notification APIs)

### Schedule Expiry Reminders

```javascript
const Notification = require('./src/services/Notification');

// Schedule reminders for a medicine
await Notification.scheduleExpiryReminder(medicine, user);

// Send immediate notification
await Notification.sendNotification({
  title: '药品过期提醒',
  body: '您的药品即将过期',
  data: { medicineId: 'med_123' }
});
```

### Notification Types

1. **Expiry Warning (30 days)**: `expiry_warning`
2. **Expiry Urgent (7 days)**: `expiry_urgent`
3. **Expiry Critical (1 day)**: `expiry_critical`

## 本地存储API (Local Storage APIs)

### Save/Load Data

```javascript
const Storage = require('./src/services/Storage');

// Save medicines
await Storage.saveMedicines(medicinesArray);

// Load medicines
const medicines = await Storage.loadMedicines();

// Save usage records
await Storage.saveUsageRecords(recordsArray);

// Load current user
const user = await Storage.loadCurrentUser();
```

## Data Models

### Medicine Model

```javascript
const Medicine = require('./src/models/Medicine');

const medicine = new Medicine({
  name: '阿莫西林胶囊',
  barcode: '1234567890123',
  expiryDate: '2025-12-31',
  quantity: 2,
  unit: 'box',
  category: 'antibiotics'
});

// Check if expired
medicine.isExpired(); // false

// Get days until expiry
medicine.getDaysUntilExpiry(); // 700

// Get expiry status
medicine.getExpiryStatus(); // 'good', 'soon', 'urgent', or 'expired'
```

### User Model

```javascript
const User = require('./src/models/User');

const user = new User({
  username: 'john_doe',
  email: 'john@example.com',
  displayName: 'John Doe',
  role: 'admin'
});

// Check permissions
user.isAdmin(); // true
user.canEdit(); // true
```

### Usage Record Model

```javascript
const UsageRecord = require('./src/models/UsageRecord');

const record = new UsageRecord({
  medicineId: 'med_123',
  userId: 'user_456',
  userName: 'John Doe',
  quantity: 1,
  notes: 'Took after meal'
});

// Get formatted timestamp
record.getFormattedTimestamp(); // '2024-01-18 14:30'

// Check if today
record.isToday(); // true
```

### Family Group Model

```javascript
const FamilyGroup = require('./src/models/FamilyGroup');

const group = new FamilyGroup({
  name: 'Smith Family',
  adminUserId: 'user_123'
});

// Add member
group.addMember('user_456');

// Check if member
group.isMember('user_456'); // true

// Get invite code
const inviteCode = group.inviteCode; // 'ABC12345'
```

## Utility Functions

### Date Helper

```javascript
const DateHelper = require('./src/utils/dateHelper');

// Format date
DateHelper.formatDate(new Date()); // '2024/01/18'

// Get days between
DateHelper.getDaysBetween(date1, date2); // 30

// Get relative time
DateHelper.getRelativeTime(date); // '2小时前'
```

### Validator

```javascript
const Validator = require('./src/utils/validator');

// Validate medicine data
const result = Validator.validateMedicine(medicineData);
if (!result.isValid) {
  console.log(result.errors);
}

// Validate email
Validator.isValidEmail('user@example.com'); // true

// Validate barcode
Validator.isValidBarcode('1234567890123'); // true
```

## Error Handling

All API calls should be wrapped in try-catch blocks:

```javascript
try {
  const result = await BarcodeAPI.fetchMedicineByBarcode(barcode);
  if (!result) {
    console.log('Medicine not found in database');
  }
} catch (error) {
  console.error('API error:', error.message);
}
```

## Rate Limiting

To prevent API abuse, consider implementing rate limiting:

- Barcode API: Maximum 10 requests per minute
- Cloud Sync: Maximum 100 operations per hour

## Security Considerations

1. **API Keys**: Store API keys in environment variables, never hardcode
2. **Input Validation**: Always validate user input before API calls
3. **Data Sanitization**: Sanitize all user-provided data
4. **Authentication**: Use proper authentication for cloud sync operations

## Testing

Use the mock implementations for testing:

```javascript
// Mock barcode scan
const mockData = await BarcodeAPI.mockScan('1234567890123');

// Mock storage (uses in-memory Map)
await Storage.save('test_key', { data: 'test' });
```

## API Version

Current API Version: **v1.0.0**

Last Updated: 2024-01-18
