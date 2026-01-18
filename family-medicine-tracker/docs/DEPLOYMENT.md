# Deployment Guide
# 部署指南

## Prerequisites
## 先决条件

### Development Environment
- Node.js >= 14.x
- npm or yarn
- React Native CLI
- Xcode (for iOS development)
- Android Studio (for Android development)
- Git

### Cloud Services
- Firebase account (or Supabase account)
- Apple Developer account (for iOS)
- Google Play Console account (for Android)

## Setup Instructions
## 设置说明

### 1. Clone Repository
### 克隆仓库

```bash
git clone https://github.com/jonny201/openeuler-for-nic.git
cd openeuler-for-nic/family-medicine-tracker
```

### 2. Install Dependencies
### 安装依赖

```bash
npm install

# For iOS
cd ios && pod install && cd ..
```

### 3. Environment Configuration
### 环境配置

Create a `.env` file in the root directory:

```env
# API Keys
OPEN_DRUG_API_KEY=your_api_key_here
CFDA_API_KEY=your_api_key_here
FALLBACK_API_KEY=your_api_key_here

# Firebase Configuration
FIREBASE_API_KEY=your_firebase_api_key
FIREBASE_AUTH_DOMAIN=your-app.firebaseapp.com
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_STORAGE_BUCKET=your-app.appspot.com
FIREBASE_MESSAGING_SENDER_ID=your_sender_id
FIREBASE_APP_ID=your_app_id

# Supabase Configuration (alternative)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
```

### 4. Firebase Setup (if using Firebase)
### Firebase设置

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project
3. Add iOS and/or Android app
4. Download configuration files:
   - iOS: `GoogleService-Info.plist` → Place in `ios/` folder
   - Android: `google-services.json` → Place in `android/app/` folder
5. Enable Authentication, Firestore, and Storage

### 5. Supabase Setup (alternative to Firebase)
### Supabase设置

1. Go to [Supabase Dashboard](https://app.supabase.com/)
2. Create a new project
3. Note your project URL and anon key
4. Create database tables:

```sql
-- Medicines table
CREATE TABLE medicines (
  id TEXT PRIMARY KEY,
  barcode TEXT,
  name TEXT NOT NULL,
  generic_name TEXT,
  manufacturer TEXT,
  description TEXT,
  dosage TEXT,
  side_effects TEXT,
  category TEXT,
  expiry_date TIMESTAMP NOT NULL,
  purchase_date TIMESTAMP,
  quantity INTEGER,
  unit TEXT,
  storage TEXT,
  image_url TEXT,
  user_id TEXT NOT NULL,
  family_group_id TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Usage records table
CREATE TABLE usage_records (
  id TEXT PRIMARY KEY,
  medicine_id TEXT NOT NULL REFERENCES medicines(id),
  user_id TEXT NOT NULL,
  user_name TEXT,
  timestamp TIMESTAMP DEFAULT NOW(),
  quantity INTEGER,
  notes TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Family groups table
CREATE TABLE family_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  admin_user_id TEXT NOT NULL,
  member_ids TEXT[],
  invite_code TEXT UNIQUE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

## Development
## 开发

### Run on iOS Simulator

```bash
npm run ios
```

### Run on Android Emulator

```bash
npm run android
```

### Run on Physical Device

**iOS:**
```bash
npm run ios -- --device "Your iPhone Name"
```

**Android:**
```bash
npm run android -- --deviceId=device_id
```

### Development Server

```bash
npm start
```

## Testing
## 测试

### Run Unit Tests

```bash
npm test
```

### Run Integration Tests

```bash
npm run test:integration
```

### Run E2E Tests

```bash
npm run test:e2e
```

### Code Coverage

```bash
npm run test:coverage
```

## Building
## 构建

### iOS Build

#### Debug Build
```bash
cd ios
xcodebuild -workspace FamilyMedicineTracker.xcworkspace \
  -scheme FamilyMedicineTracker \
  -configuration Debug \
  -sdk iphonesimulator
```

#### Release Build
```bash
cd ios
xcodebuild -workspace FamilyMedicineTracker.xcworkspace \
  -scheme FamilyMedicineTracker \
  -configuration Release \
  -sdk iphoneos \
  archive -archivePath build/FamilyMedicineTracker.xcarchive
```

### Android Build

#### Debug APK
```bash
cd android
./gradlew assembleDebug
```

#### Release APK
```bash
cd android
./gradlew assembleRelease
```

#### Release AAB (for Play Store)
```bash
cd android
./gradlew bundleRelease
```

## Code Signing
## 代码签名

### iOS Code Signing

1. Open Xcode
2. Select project → Signing & Capabilities
3. Select your development team
4. Enable "Automatically manage signing"

For production:
1. Create Distribution Certificate in Apple Developer Portal
2. Create Provisioning Profile
3. Configure in Xcode

### Android Code Signing

1. Generate keystore:
```bash
keytool -genkeypair -v -storetype PKCS12 \
  -keystore my-release-key.keystore \
  -alias my-key-alias \
  -keyalg RSA -keysize 2048 \
  -validity 10000
```

2. Configure `android/gradle.properties`:
```properties
MYAPP_RELEASE_STORE_FILE=my-release-key.keystore
MYAPP_RELEASE_KEY_ALIAS=my-key-alias
MYAPP_RELEASE_STORE_PASSWORD=****
MYAPP_RELEASE_KEY_PASSWORD=****
```

## Publishing
## 发布

### iOS App Store

1. Archive the app in Xcode
2. Upload to App Store Connect
3. Fill in app metadata:
   - App name
   - Description
   - Screenshots
   - Keywords
   - Categories
4. Submit for review

### Google Play Store

1. Create app in Play Console
2. Upload AAB file
3. Fill in store listing:
   - Title
   - Short description
   - Full description
   - Screenshots
   - Feature graphic
4. Set pricing and distribution
5. Submit for review

## Continuous Integration/Deployment
## 持续集成/部署

### GitHub Actions

Create `.github/workflows/ci.yml`:

```yaml
name: CI/CD

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '14'
      - run: npm install
      - run: npm test

  build-android:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install
      - run: cd android && ./gradlew assembleRelease

  build-ios:
    runs-on: macos-latest
    needs: test
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
      - run: npm install
      - run: cd ios && pod install
      - run: xcodebuild -workspace ios/FamilyMedicineTracker.xcworkspace
```

## Monitoring and Analytics
## 监控和分析

### Crash Reporting

Use Firebase Crashlytics or Sentry:

```bash
npm install @sentry/react-native
```

### Analytics

Use Firebase Analytics or Mixpanel:

```bash
npm install @react-native-firebase/analytics
```

### Performance Monitoring

```bash
npm install @react-native-firebase/perf
```

## Troubleshooting
## 故障排除

### Common Issues

**iOS Pod Install Fails**
```bash
cd ios
pod deintegrate
pod install
```

**Android Build Fails**
```bash
cd android
./gradlew clean
./gradlew build --refresh-dependencies
```

**Metro Bundler Cache Issues**
```bash
npm start -- --reset-cache
```

**Node Modules Issues**
```bash
rm -rf node_modules
npm install
```

## Maintenance
## 维护

### Regular Updates

- Update dependencies monthly
- Review and fix security vulnerabilities
- Monitor crash reports
- Respond to user feedback
- Release updates every 2-4 weeks

### Database Backups

Set up automated backups in Firebase/Supabase:
- Daily backups
- Retention period: 30 days
- Test restore procedures regularly

## Support
## 支持

For deployment issues:
- Check documentation at `/docs`
- Open an issue on GitHub
- Contact: support@example.com

## Version History
## 版本历史

- **v1.0.0** (2024-01-18): Initial release
  - Basic medicine management
  - Barcode scanning
  - Expiry reminders
  - Family sharing
