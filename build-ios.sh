#!/bin/bash
# 聊天室 App - iOS 打包脚本（签名 IPA）
# 在 macOS 上运行，生成带签名的 .ipa 文件

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SCHEME="App"
WORKSPACE="ios/App/App.xcworkspace"
ARCHIVE_PATH="$SCRIPT_DIR/build/ios/App.xcarchive"
EXPORT_PATH="$SCRIPT_DIR/build/ios/export"
IPA_NAME="ChatRoom.ipa"
TEAM_ID="9YGZU7N93G"
BUNDLE_ID="com.chatroom.app"

echo "========================================"
echo "   聊天室 App - iOS 签名打包"
echo "========================================"
echo ""

# 检查环境
if ! command -v node &> /dev/null; then
    echo "[错误] 未检测到 Node.js"
    exit 1
fi

if ! command -v xcodebuild &> /dev/null; then
    echo "[错误] 未检测到 Xcode"
    exit 1
fi

# 检查签名证书
if ! security find-identity -v -p codesigning | grep -q "Apple Development"; then
    echo "[错误] 未找到 Apple Development 签名证书"
    echo "请在 Xcode > Settings > Accounts 中登录并创建证书"
    exit 1
fi

# 参数处理
MODE="release"
while [[ "$1" != "" ]]; do
    case $1 in
        --debug)  MODE="debug" ;;
        --clean)  CLEAN="yes" ;;
        --open)   OPEN="yes" ;;
        *)        echo "用法: $0 [--debug] [--clean] [--open]"; exit 1 ;;
    esac
    shift
done

CONFIG="Release"
if [ "$MODE" = "debug" ]; then
    CONFIG="Debug"
fi

echo "[1/5] 安装依赖..."
npm install --silent 2>&1 | tail -1

echo ""
echo "[2/5] 同步 Web 资源到 iOS..."
npx cap sync ios 2>&1 | tail -3

echo ""
echo "[3/5] 构建 ${CONFIG}..."
if [ "$CLEAN" = "yes" ]; then
    rm -rf build/ios
fi
mkdir -p build/ios

# Archive
echo "  → Archive..."
xcodebuild archive \
    -workspace "$WORKSPACE" \
    -scheme "$SCHEME" \
    -configuration "$CONFIG" \
    -archivePath "$ARCHIVE_PATH" \
    -destination "generic/platform=iOS" \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    CODE_SIGN_STYLE=Automatic \
    COMPILER_INDEX_STORE_ENABLE=NO \
    | xcpretty --color 2>/dev/null || xcodebuild archive \
    -workspace "$WORKSPACE" \
    -scheme "$SCHEME" \
    -configuration "$CONFIG" \
    -archivePath "$ARCHIVE_PATH" \
    -destination "generic/platform=iOS" \
    DEVELOPMENT_TEAM="$TEAM_ID" \
    CODE_SIGN_STYLE=Automatic \
    COMPILER_INDEX_STORE_ENABLE=NO

if [ ! -d "$ARCHIVE_PATH" ]; then
    echo "[错误] Archive 失败"
    exit 1
fi

echo ""
echo "[4/5] 导出 IPA..."

# 创建 ExportOptions.plist
cat > "$SCRIPT_DIR/build/ios/ExportOptions.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>development</string>
    <key>teamID</key>
    <string>TEAM_ID_PLACEHOLDER</string>
    <key>signingStyle</key>
    <string>automatic</string>
    <key>stripSwiftSymbols</key>
    <true/>
    <key>thinning</key>
    <string>&lt;none&gt;</string>
</dict>
</plist>
EOF

# 替换 Team ID
sed -i '' "s/TEAM_ID_PLACEHOLDER/$TEAM_ID/" "$SCRIPT_DIR/build/ios/ExportOptions.plist"

xcodebuild -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportOptionsPlist "$SCRIPT_DIR/build/ios/ExportOptions.plist" \
    -exportPath "$EXPORT_PATH" \
    | xcpretty --color 2>/dev/null || xcodebuild -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportOptionsPlist "$SCRIPT_DIR/build/ios/ExportOptions.plist" \
    -exportPath "$EXPORT_PATH"

# 查找生成的 IPA
IPA_FILE=$(find "$EXPORT_PATH" -name "*.ipa" -type f | head -1)

if [ -z "$IPA_FILE" ]; then
    echo "[错误] 导出 IPA 失败"
    exit 1
fi

echo ""
echo "[5/5] 完成!"

# 重命名为固定名称
OUTPUT_IPA="$SCRIPT_DIR/build/ios/$IPA_NAME"
mv "$IPA_FILE" "$OUTPUT_IPA"

IPA_SIZE=$(du -h "$OUTPUT_IPA" | awk '{print $1}')
echo ""
echo "========================================"
echo "   ✅ IPA 已生成（已签名）"
echo "========================================"
echo ""
echo "  📦 路径: $OUTPUT_IPA"
echo "  📏 大小: $IPA_SIZE"
echo "  🔑 Team: $TEAM_ID"
echo "  📱 Bundle: $BUNDLE_ID"
echo ""

if [ "$OPEN" = "yes" ]; then
    open "$SCRIPT_DIR/build/ios/"
fi

echo "安装方式："
echo "  方式1: 通过 Xcode → Devices and Simulators 安装到设备"
echo "  方式2: 使用 Apple Configurator 2"
echo "  方式3: 通过 itms-services 分发（需配合 HTTPS 服务器 + manifest.plist）"
echo ""
