# Example Usage
# 使用示例

## Quick Start Example
## 快速开始示例

```javascript
const {
  FamilyMedicineTracker,
  Medicine,
  User,
  UsageRecord,
  BarcodeAPI,
  Storage,
  Notification
} = require('./index');

// Initialize the app
const app = new FamilyMedicineTracker();
await app.initialize({
  cloudSync: {
    enabled: false  // Use local storage only for this example
  }
});

console.log(`App version: ${app.getVersion()}`);
```

## Example 1: Add Medicine via Barcode
## 示例1：通过条形码添加药品

```javascript
const { Medicine, BarcodeAPI, Storage, Notification } = require('./index');

async function addMedicineByBarcode(barcode, expiryDate, quantity = 1) {
  try {
    // Scan barcode and fetch medicine info
    console.log(`Scanning barcode: ${barcode}`);
    const medicineInfo = await BarcodeAPI.fetchMedicineByBarcode(barcode);
    
    if (!medicineInfo) {
      console.log('Medicine not found in database');
      return null;
    }

    // Create medicine instance
    const medicine = new Medicine({
      ...medicineInfo,
      barcode,
      expiryDate,
      quantity,
      userId: 'user_123'
    });

    // Save to local storage
    const medicines = await Storage.loadMedicines();
    medicines.push(medicine);
    await Storage.saveMedicines(medicines);

    // Schedule expiry reminders
    const user = await Storage.loadCurrentUser();
    if (user) {
      await Notification.scheduleExpiryReminder(medicine, user);
    }

    console.log(`Medicine added: ${medicine.name}`);
    console.log(`Expiry status: ${medicine.getExpiryStatus()}`);
    console.log(`Days until expiry: ${medicine.getDaysUntilExpiry()}`);

    return medicine;
  } catch (error) {
    console.error('Error adding medicine:', error);
    throw error;
  }
}

// Usage
addMedicineByBarcode('1234567890123', '2025-12-31', 2);
```

## Example 2: Record Medicine Usage
## 示例2：记录用药

```javascript
const { UsageRecord, Storage } = require('./index');

async function recordMedicineUsage(medicineId, userId, userName, quantity = 1) {
  try {
    // Create usage record
    const record = new UsageRecord({
      medicineId,
      userId,
      userName,
      quantity,
      notes: 'Taken after meal'
    });

    // Save record
    const records = await Storage.loadUsageRecords();
    records.push(record);
    await Storage.saveUsageRecords(records);

    // Update medicine quantity
    const medicines = await Storage.loadMedicines();
    const medicine = medicines.find(m => m.id === medicineId);
    
    if (medicine) {
      medicine.decrementQuantity(quantity);
      await Storage.saveMedicines(medicines);
      
      console.log(`Usage recorded: ${record.getSummary()}`);
      console.log(`Remaining quantity: ${medicine.quantity} ${medicine.unit}`);
    }

    return record;
  } catch (error) {
    console.error('Error recording usage:', error);
    throw error;
  }
}

// Usage
recordMedicineUsage('med_123', 'user_456', 'John Doe', 1);
```

## Example 3: Check Expiring Medicines
## 示例3：检查即将过期的药品

```javascript
const { Storage, DateHelper } = require('./index');

async function checkExpiringMedicines() {
  try {
    const medicines = await Storage.loadMedicines();
    
    const expired = [];
    const urgent = [];
    const soon = [];
    
    for (const medicine of medicines) {
      const status = medicine.getExpiryStatus();
      
      switch (status) {
        case 'expired':
          expired.push(medicine);
          break;
        case 'urgent':
          urgent.push(medicine);
          break;
        case 'soon':
          soon.push(medicine);
          break;
      }
    }

    console.log('\n=== Medicine Expiry Report ===\n');
    
    if (expired.length > 0) {
      console.log('🔴 EXPIRED:');
      expired.forEach(m => {
        console.log(`  - ${m.name}: expired on ${DateHelper.formatDate(m.expiryDate)}`);
      });
    }

    if (urgent.length > 0) {
      console.log('\n🟡 URGENT (expires within 7 days):');
      urgent.forEach(m => {
        console.log(`  - ${m.name}: ${m.getDaysUntilExpiry()} days left`);
      });
    }

    if (soon.length > 0) {
      console.log('\n🟢 EXPIRING SOON (within 30 days):');
      soon.forEach(m => {
        console.log(`  - ${m.name}: ${m.getDaysUntilExpiry()} days left`);
      });
    }

    return { expired, urgent, soon };
  } catch (error) {
    console.error('Error checking expiring medicines:', error);
    throw error;
  }
}

// Usage
checkExpiringMedicines();
```

## Example 4: Family Group Management
## 示例4：家庭组管理

```javascript
const { FamilyGroup, User, Storage, CloudSync } = require('./index');

async function createFamilyGroup(groupName, adminUserId) {
  try {
    // Create family group
    const group = new FamilyGroup({
      name: groupName,
      adminUserId
    });

    // Add admin as first member
    group.addMember(adminUserId);

    // Save to storage
    await Storage.saveFamilyGroup(group);

    // Sync to cloud if enabled
    if (CloudSync.getSyncStatus().syncEnabled) {
      await CloudSync.createFamilyGroup(group.toJSON());
    }

    console.log(`Family group created: ${group.name}`);
    console.log(`Invite code: ${group.inviteCode}`);
    console.log('Share this code with family members to join!');

    return group;
  } catch (error) {
    console.error('Error creating family group:', error);
    throw error;
  }
}

async function joinFamilyGroup(inviteCode, userId) {
  try {
    // Join group via cloud sync
    const result = await CloudSync.joinFamilyGroup(inviteCode, userId);
    
    if (result.success) {
      console.log(`Successfully joined family group!`);
      console.log(`Group ID: ${result.familyGroupId}`);
      
      // Load user and update family group ID
      const user = await Storage.loadCurrentUser();
      user.familyGroupId = result.familyGroupId;
      await Storage.saveCurrentUser(user);
    }

    return result;
  } catch (error) {
    console.error('Error joining family group:', error);
    throw error;
  }
}

// Usage
createFamilyGroup('Smith Family', 'user_123');
joinFamilyGroup('ABC12345', 'user_456');
```

## Example 5: Generate Usage Report
## 示例5：生成使用报告

```javascript
const { Storage, DateHelper } = require('./index');

async function generateUsageReport(medicineId = null, days = 7) {
  try {
    const records = await Storage.loadUsageRecords();
    const startDate = DateHelper.subtractDays(new Date(), days);

    // Filter records
    let filteredRecords = records.filter(r => {
      const isRecent = new Date(r.timestamp) >= startDate;
      const matchesMedicine = !medicineId || r.medicineId === medicineId;
      return isRecent && matchesMedicine;
    });

    // Group by user
    const usageByUser = {};
    filteredRecords.forEach(record => {
      if (!usageByUser[record.userName]) {
        usageByUser[record.userName] = [];
      }
      usageByUser[record.userName].push(record);
    });

    console.log(`\n=== Usage Report (Last ${days} days) ===\n`);
    
    for (const [userName, userRecords] of Object.entries(usageByUser)) {
      console.log(`${userName}:`);
      userRecords.forEach(r => {
        console.log(`  - ${DateHelper.formatDateTime(r.timestamp)}: ${r.quantity} dose(s)`);
      });
      console.log(`  Total: ${userRecords.length} usage(s)\n`);
    }

    return { usageByUser, totalRecords: filteredRecords.length };
  } catch (error) {
    console.error('Error generating usage report:', error);
    throw error;
  }
}

// Usage
generateUsageReport(null, 7);  // All medicines, last 7 days
generateUsageReport('med_123', 30);  // Specific medicine, last 30 days
```

## Example 6: Bulk Import Medicines
## 示例6：批量导入药品

```javascript
const { Medicine, Storage, Validator } = require('./index');

async function bulkImportMedicines(medicinesData) {
  try {
    const imported = [];
    const errors = [];

    for (const data of medicinesData) {
      // Validate data
      const validation = Validator.validateMedicine(data);
      
      if (!validation.isValid) {
        errors.push({ data, errors: validation.errors });
        continue;
      }

      // Create medicine
      const medicine = new Medicine(data);
      imported.push(medicine);
    }

    // Save all imported medicines
    if (imported.length > 0) {
      const existing = await Storage.loadMedicines();
      const all = [...existing, ...imported];
      await Storage.saveMedicines(all);
    }

    console.log(`\nImport complete:`);
    console.log(`  ✓ ${imported.length} medicines imported`);
    console.log(`  ✗ ${errors.length} medicines failed validation`);

    if (errors.length > 0) {
      console.log('\nValidation errors:');
      errors.forEach(({ data, errors }) => {
        console.log(`  - ${data.name || 'Unknown'}: ${errors.join(', ')}`);
      });
    }

    return { imported, errors };
  } catch (error) {
    console.error('Error bulk importing medicines:', error);
    throw error;
  }
}

// Usage
const medicinesData = [
  {
    name: '阿莫西林胶囊',
    expiryDate: '2025-06-30',
    quantity: 2,
    category: 'antibiotics'
  },
  {
    name: '布洛芬片',
    expiryDate: '2025-12-31',
    quantity: 1,
    category: 'painkillers'
  }
];

bulkImportMedicines(medicinesData);
```

## Complete Application Example
## 完整应用示例

```javascript
const {
  FamilyMedicineTracker,
  Medicine,
  User,
  BarcodeAPI,
  Storage,
  Notification
} = require('./index');

async function main() {
  // 1. Initialize app
  const app = new FamilyMedicineTracker();
  await app.initialize();

  // 2. Create user
  const user = new User({
    username: 'john_doe',
    email: 'john@example.com',
    displayName: 'John Doe',
    role: 'admin'
  });
  await Storage.saveCurrentUser(user);

  // 3. Add medicines
  console.log('\n=== Adding Medicines ===');
  const medicine1 = await addMedicineByBarcode('1234567890123', '2025-12-31', 2);
  
  // 4. Check expiring medicines
  console.log('\n=== Checking Expiring Medicines ===');
  await checkExpiringMedicines();

  // 5. Record usage
  if (medicine1) {
    console.log('\n=== Recording Usage ===');
    await recordMedicineUsage(medicine1.id, user.id, user.displayName, 1);
  }

  // 6. Generate report
  console.log('\n=== Usage Report ===');
  await generateUsageReport();

  console.log('\n=== Demo Complete ===');
}

// Run the demo
main().catch(console.error);
```

For more examples, check the `/tests` directory.
