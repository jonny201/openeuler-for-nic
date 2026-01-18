# Family Medicine Tracker (家庭药箱管家)

A mobile application to help families manage their medicine cabinet, track expiry dates, and prevent medication waste.

## 问题痛点 (Pain Points)

很多人买了感冒药、消炎药后就扔在抽屉里，等到下次生病想吃时，发现已经过期了，或者说明书丢了不知道用量。市面上的健康App太重（挂号、问诊），没有专门管"家里存药"的工具。

Many people buy cold medicine or anti-inflammatory drugs and throw them in a drawer. When they get sick again and want to take the medicine, they find it has expired or the instructions are lost and they don't know the dosage. Existing health apps are too heavy (focusing on appointments and consultations), with no dedicated tools for managing home medicine storage.

## 核心功能 (Core Features)

### 1. 扫码录入 (Barcode Scanning)
- Scan medicine package barcode
- Automatically fetch drug information via public API
- Store medicine name, effects, dosage instructions

### 2. 过期提醒 (Expiry Reminders)
- Input shelf life/expiry date
- Automatic push notifications 1 month and 1 week before expiry
- Visual indicators for medicines nearing expiry

### 3. 用药记录 (Medication Usage Tracking)
- Simple click-based logging: "who, when, what"
- Prevent accidental double-dosing
- Historical usage records

### 4. 家庭共享 (Family Sharing)
- Cloud-based data storage (Firebase/Supabase compatible)
- Family members can track each other's medication
- Especially useful for monitoring elderly family members

## 技术栈 (Technology Stack)

- **Frontend**: React Native (iOS & Android)
- **Backend**: Firebase/Supabase for cloud storage
- **Barcode Scanning**: Native device camera APIs
- **Notifications**: Push notification services
- **OCR/API**: Public medicine database APIs

## 项目结构 (Project Structure)

```
family-medicine-tracker/
├── src/
│   ├── models/          # Data models
│   ├── services/        # API services
│   ├── components/      # UI components
│   ├── screens/         # App screens
│   ├── utils/           # Helper functions
│   └── config/          # Configuration
├── docs/                # Documentation
├── tests/               # Test files
└── README.md
```

## 快速开始 (Quick Start)

### Prerequisites
- Node.js >= 14.x
- React Native development environment
- iOS/Android simulator or device

### Installation
```bash
cd family-medicine-tracker
npm install
```

### Development
```bash
# iOS
npm run ios

# Android
npm run android
```

## API Integration

The app supports integration with public medicine databases. See `docs/API.md` for details on supported APIs and data formats.

## 为什么能爆？(Why This Will Succeed?)

- **极其刚需**: Extremely high demand - everyone has medicine at home
- **受众全**: Universal audience - all family users
- **工具属性强**: Strong utility function - solves a real problem
- **市场空白**: Market gap - no dominant product currently exists
- **传播性好**: Easy to spread - users naturally recommend to family members

## License

MIT License

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.
