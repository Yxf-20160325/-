# 聊天室 App - 移动端打包指南

本项目已配置 Capacitor，可将聊天室 Web 应用打包为原生 Android 和 iOS App。

## 快速开始

### Android 构建

**方式一：一键构建（推荐）**
```bash
# 在项目根目录双击运行或命令行执行
build-android.bat
```

**方式二：手动构建**
```bash
# 1. 安装依赖
npm install

# 2. 同步 Web 资源到 Android
npx cap sync android

# 3. 构建 APK
cd android
./gradlew assembleDebug    # Linux/macOS
gradlew.bat assembleDebug   # Windows

# 4. 安装到设备
adb install app/build/outputs/apk/debug/app-debug.apk
```

**方式三：Android Studio 打开**
```
1. 用 Android Studio 打开 /android 目录
2. 点击 Run > Run 'App'
3. 选择连接的设备或模拟器
```

### iOS 构建（仅 macOS）

```bash
# 1. 添加 iOS 平台（如未添加）
npx cap add ios

# 2. 同步资源
npx cap sync ios

# 3. 用 Xcode 打开
npx cap open ios

# 4. 在 Xcode 中选择设备和点击 Run
```

## App 功能

打包后的 App 支持以下功能：

| 功能 | Android | iOS | 说明 |
|------|---------|-----|------|
| 文字消息 | ✅ | ✅ | 实时收发 |
| 图片消息 | ✅ | ✅ | 拍照/相册选择 |
| 语音消息 | ✅ | ✅ | 录音发送 |
| 音视频通话 | ✅ | ✅ | WebRTC |
| 实时位置 | ✅ | ✅ | 高德地图 |
| 推送通知 | ✅ | ✅ | 需要配置 FCM/APNs |
| 文件上传 | ✅ | ✅ | 相机相册 |
| 游戏互动 | ✅ | ✅ | 多种小游戏 |
| 白板协作 | ✅ | ✅ | 多人绘画 |
| 文档编辑 | ✅ | ✅ | CodeMirror |
| AI 对话 | ✅ | ✅ | GLM/DeepSeek |

## 配置说明

### 修改 App 名称

编辑 `capacitor.config.json`:
```json
{
  "appName": "你的App名称",
  "appId": "com.yourdomain.app"
}
```

然后同步：
```bash
npx cap sync android
npx cap sync ios
```

### 修改 App 图标

**Android**
- 替换 `android/app/src/main/res/mipmap-*/ic_launcher.png`
- 推荐尺寸：48x48, 72x72, 96x96, 144x144, 192x192
- 可使用在线工具：[Android Asset Studio](https://romannurik.github.io/AndroidAssetStudio/icons-launcher.html)

**iOS**
- 替换 `ios/App/App/Assets.xcassets/AppIcon.appiconset/`
- 推荐尺寸：20x20, 29x29, 40x40, 60x60, 76x76, 83.5x83.5, 1024x1024
- 可使用在线工具：[App Icon Generator](https://appicon.co/)

### 配置启动画面

编辑 `capacitor.config.json`:
```json
{
  "plugins": {
    "SplashScreen": {
      "launchShowDuration": 2000,
      "backgroundColor": "#667eea",
      "showSpinner": true,
      "spinnerColor": "#ffffff",
      "androidScaleType": "CENTER_CROP",
      "launchAutoHide": true
    }
  }
}
```

### 配置网络权限（Android）

已默认配置以下权限，如需调整编辑：
`android/app/src/main/AndroidManifest.xml`

### 配置 App Store（iOS）

编辑 `ios/App/App/Info.plist`:
```xml
<key>CFBundleDisplayName</key>
<string>聊天室</string>
<key>CFBundleShortVersionString</key>
<string>1.0.0</string>
<key>CFBundleVersion</key>
<string>1</string>
```

## 高级配置

### 配置 Firebase 推送通知

**Android (Firebase Cloud Messaging)**

1. 在 [Firebase Console](https://console.firebase.google.com/) 创建项目
2. 下载 `google-services.json` 放到 `android/app/`
3. 安装插件：
```bash
npm install @capacitor/push-notifications
npx cap sync android
```

**iOS (Apple Push Notification)**

1. 在 Apple Developer 配置 APNs
2. 下载 `Certificates.p12` 并配置
3. 安装插件：
```bash
npm install @capacitor/push-notifications
npx cap sync ios
```

### 添加新功能插件

```bash
# 搜索可用插件
npm search @capacitor

# 安装示例
npm install @capacitor/camera
npx cap sync android
npx cap sync ios
```

常用插件：
- `@capacitor/camera` - 相机
- `@capacitor/filesystem` - 文件系统
- `@capacitor/share` - 分享
- `@capacitor/haptics` - 震动反馈
- `@capacitor/geolocation` - 位置服务
- `@capacitor/push-notifications` - 推送通知
- `@capacitor/local-notifications` - 本地通知
- `@capacitor/barcode-scanner` - 扫码

## 常见问题

### Q: 构建失败提示 SDK 版本问题

检查 `android/build.gradle` 中的 SDK 版本：
```groovy
ext {
    compileSdkVersion = 34
    minSdkVersion = 24
    targetSdkVersion = 34
}
```

### Q: App 打开后白屏

1. 检查网络连接（App 需要能访问服务器）
2. 检查服务器地址配置
3. 查看 Logcat：`adb logcat | grep Capacitor`

### Q: 相机/麦克风无法使用

确保在 `AndroidManifest.xml` 中已添加权限：
```xml
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
```

### Q: WebSocket 连接失败

某些网络环境下需要配置 WSS（WebSocket Secure）。确保服务器使用 HTTPS/WSS。

## 发布到应用商店

### Google Play Store

1. 生成签名 APK：
```bash
cd android
./gradlew assembleRelease
```

2. 在 [Google Play Console](https://play.google.com/console) 创建应用
3. 上传 `.aab` 文件

### Apple App Store

1. 在 Xcode 中创建 Archive：
```bash
xcodebuild -workspace App/App.xcworkspace -scheme App -configuration Release -archivePath App.xcarchive archive
```

2. 导出 IPA：
```bash
xcodebuild -exportArchive -archivePath App.xcarchive -exportOptionsPlist exportOptions.plist -exportPath .
```

3. 在 [App Store Connect](https://appstoreconnect.apple.com/) 提交审核

## 技术栈

- **框架**: Capacitor 6.x
- **后端**: Node.js + Express + Socket.IO
- **前端**: Vanilla JavaScript (25000+ 行)
- **构建工具**: Gradle (Android), Xcode (iOS)

## 目录结构

```
chatroom/
├── android/                 # Android 原生项目
│   ├── app/
│   │   ├── src/
│   │   │   └── main/
│   │   │       ├── java/com/chatroom/app/
│   │   │       └── res/              # App 图标/资源
│   │   └── build.gradle
│   └── gradle/
├── ios/                     # iOS 原生项目 (macOS)
│   └── App/
├── public/                  # Web 应用源码
│   ├── index.html
│   ├── admin.html
│   └── mobile-bridge.js     # 移动端适配
├── capacitor.config.json     # Capacitor 配置
├── build-android.bat        # Android 一键构建脚本
└── build-ios.sh             # iOS 构建脚本
```

## 许可证

与主项目相同 - MIT License
