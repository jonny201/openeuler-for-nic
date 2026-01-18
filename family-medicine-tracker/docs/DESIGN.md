# Design Documentation
# 设计文档

## System Architecture
## 系统架构

### Overview

The Family Medicine Tracker follows a modular, layered architecture:

```
┌─────────────────────────────────────────┐
│         User Interface Layer            │
│      (Screens & Components)             │
├─────────────────────────────────────────┤
│         Business Logic Layer            │
│    (Models & Controllers)               │
├─────────────────────────────────────────┤
│         Service Layer                   │
│  (API, Storage, Notification, Sync)     │
├─────────────────────────────────────────┤
│         Infrastructure Layer            │
│  (Cloud, Device APIs, Native Features)  │
└─────────────────────────────────────────┘
```

## Data Models
## 数据模型

### Medicine (药品)

```javascript
{
  id: string,              // Unique identifier
  barcode: string,         // Product barcode
  name: string,            // Medicine name
  genericName: string,     // Generic/scientific name
  manufacturer: string,    // Manufacturer
  description: string,     // Description/indications
  dosage: string,          // Dosage instructions
  sideEffects: string,     // Side effects
  category: string,        // Category (antibiotics, painkillers, etc.)
  expiryDate: Date,        // Expiry date
  purchaseDate: Date,      // Purchase date
  quantity: number,        // Quantity remaining
  unit: string,            // Unit (box, bottle, tablet, etc.)
  storage: string,         // Storage location
  imageUrl: string,        // Medicine image URL
  userId: string,          // Owner user ID
  familyGroupId: string,   // Family group ID
  createdAt: Date,         // Creation timestamp
  updatedAt: Date          // Last update timestamp
}
```

### User (用户)

```javascript
{
  id: string,              // Unique identifier
  username: string,        // Username
  email: string,           // Email address
  displayName: string,     // Display name
  avatar: string,          // Avatar URL
  role: string,            // Role: admin, member, viewer
  familyGroupId: string,   // Family group ID
  preferences: {           // User preferences
    notifications: {
      expiryReminders: boolean,
      oneMonthBefore: boolean,
      oneWeekBefore: boolean,
      oneDayBefore: boolean,
      usageReminders: boolean
    },
    language: string,      // Language preference
    theme: string          // Theme preference
  },
  createdAt: Date,
  updatedAt: Date
}
```

### UsageRecord (用药记录)

```javascript
{
  id: string,              // Unique identifier
  medicineId: string,      // Medicine ID
  userId: string,          // User ID who took the medicine
  userName: string,        // User display name
  timestamp: Date,         // When medicine was taken
  quantity: number,        // Quantity taken
  notes: string,           // Optional notes
  createdAt: Date
}
```

### FamilyGroup (家庭组)

```javascript
{
  id: string,              // Unique identifier
  name: string,            // Group name
  adminUserId: string,     // Admin user ID
  memberIds: [string],     // Array of member user IDs
  inviteCode: string,      // Invite code for joining
  createdAt: Date,
  updatedAt: Date
}
```

## Service Architecture
## 服务架构

### 1. BarcodeAPI Service

**Purpose**: Handle barcode scanning and medicine database lookup

**Features**:
- Multi-API fallback mechanism
- Support for multiple barcode formats
- Response normalization
- Mock implementation for testing

**API Priority**:
1. Open Drug Database API
2. CFDA API (China Food and Drug Administration)
3. Fallback custom API

### 2. Storage Service

**Purpose**: Manage local data persistence

**Features**:
- AsyncStorage wrapper
- Structured data storage
- Model serialization/deserialization
- Mock implementation for testing

**Storage Keys**:
- `@medicines`: All medicines
- `@usage_records`: All usage records
- `@current_user`: Current logged-in user
- `@family_groups`: Family group data

### 3. Notification Service

**Purpose**: Handle expiry reminders and notifications

**Features**:
- Scheduled notifications
- Multiple reminder thresholds
- User preference-based notifications
- Notification lifecycle management

**Reminder Schedule**:
- 30 days before expiry (warning)
- 7 days before expiry (urgent)
- 1 day before expiry (critical)

### 4. CloudSync Service

**Purpose**: Synchronize data with cloud backend

**Features**:
- Firebase/Supabase integration
- Real-time sync
- Family data sharing
- Conflict resolution

**Sync Operations**:
- Push local changes to cloud
- Pull remote changes to local
- Merge conflicts
- Real-time updates

## User Flows
## 用户流程

### 1. Adding Medicine via Barcode
### 通过条形码添加药品

```
User opens app
  ↓
Tap "Add Medicine"
  ↓
Tap "Scan Barcode"
  ↓
Camera opens
  ↓
Scan barcode
  ↓
API fetches medicine info
  ↓
Display info for confirmation
  ↓
User adds expiry date & quantity
  ↓
Save medicine
  ↓
Schedule expiry reminders
```

### 2. Recording Medicine Usage
### 记录用药

```
User views medicine list
  ↓
Select a medicine
  ↓
Tap "Take Medicine"
  ↓
Confirm quantity
  ↓
Create usage record
  ↓
Update medicine quantity
  ↓
Sync to cloud (if enabled)
```

### 3. Family Sharing Setup
### 家庭共享设置

```
Admin creates family group
  ↓
Generate invite code
  ↓
Share code with family members
  ↓
Family member joins with code
  ↓
All members see shared medicines
  ↓
Usage records visible to all
```

## UI/UX Design Principles
## 界面设计原则

### Simplicity (简洁性)
- Clean, uncluttered interface
- Large, touch-friendly buttons
- Intuitive navigation
- Minimal text input

### Accessibility (易用性)
- Support for elderly users
- Large fonts option
- High contrast mode
- Voice input support (future)

### Visual Indicators (可视化提示)
- Color-coded expiry status:
  - 🟢 Green: Good (>30 days)
  - 🟡 Yellow: Expiring soon (7-30 days)
  - 🔴 Red: Urgent (<7 days)
  - ⚫ Gray: Expired

### Feedback (反馈)
- Immediate visual feedback on actions
- Success/error messages
- Loading indicators
- Haptic feedback

## Security Considerations
## 安全考虑

### Data Privacy
- Local-first approach
- Encrypted cloud storage
- User data isolation
- Secure authentication

### Input Validation
- All user inputs validated
- Barcode format validation
- Date range validation
- SQL injection prevention

### API Security
- API key management
- Rate limiting
- Timeout handling
- Error handling

## Performance Optimization
## 性能优化

### Local Storage
- Indexed data structures
- Efficient queries
- Minimal storage footprint
- Lazy loading

### API Calls
- Request caching
- Retry mechanism
- Fallback strategies
- Timeout handling

### UI Rendering
- Virtual lists for large datasets
- Image lazy loading
- Component memoization
- Debounced inputs

## Future Enhancements
## 未来增强功能

### Phase 2
- [ ] OCR for medicine label scanning
- [ ] Multi-language support (English, Japanese, etc.)
- [ ] Export data to PDF/Excel
- [ ] Medicine interaction checker

### Phase 3
- [ ] Voice commands
- [ ] AR medicine identification
- [ ] Pharmacy integration
- [ ] Doctor consultation integration

### Phase 4
- [ ] AI-powered health recommendations
- [ ] Medication adherence tracking
- [ ] Insurance claim integration
- [ ] Telemedicine integration

## Technology Stack
## 技术栈

### Frontend
- **Framework**: React Native
- **State Management**: React Hooks + Context API
- **UI Components**: React Native Paper / Native Base
- **Navigation**: React Navigation
- **Charts**: Victory Native / React Native Chart Kit

### Backend
- **BaaS**: Firebase / Supabase
- **Authentication**: Firebase Auth / Supabase Auth
- **Database**: Firestore / Supabase PostgreSQL
- **Storage**: Firebase Storage / Supabase Storage

### APIs & Libraries
- **Barcode Scanning**: react-native-camera / expo-barcode-scanner
- **Local Storage**: @react-native-async-storage/async-storage
- **Notifications**: react-native-push-notification
- **Date Handling**: date-fns / dayjs
- **HTTP Client**: axios / fetch

## Development Guidelines
## 开发指南

### Code Style
- Use ES6+ features
- Follow Airbnb style guide
- Use meaningful variable names
- Add JSDoc comments

### Testing
- Unit tests for models
- Integration tests for services
- E2E tests for critical flows
- Minimum 80% code coverage

### Version Control
- Feature branch workflow
- Semantic versioning
- Descriptive commit messages
- Code review required

## Deployment
## 部署

### iOS
- TestFlight for beta testing
- App Store submission
- Regular updates

### Android
- Google Play Console
- Beta track testing
- Production release

### CI/CD
- Automated builds
- Automated testing
- Automated deployment
