#!/bin/bash
# 聊天室 App - iOS/macOS 构建脚本
# 在 macOS 上运行

set -e

echo "========================================"
echo "   聊天室 App - iOS 构建脚本"
echo "========================================"
echo ""

# 检查 Node.js
if ! command -v node &> /dev/null; then
    echo "[错误] 未检测到 Node.js，请先安装 Node.js"
    exit 1
fi

# 检查 npm
if ! command -v npm &> /dev/null; then
    echo "[错误] 未检测到 npm"
    exit 1
fi

# 检查 Xcode 命令行工具
if ! command -v xcodebuild &> /dev/null; then
    echo "[错误] 未检测到 Xcode，请安装 Xcode 命令行工具"
    echo "运行: xcode-select --install"
    exit 1
fi

echo "[1/6] 安装依赖..."
npm install

echo ""
echo "[2/6] 同步 Web 资源到 iOS 项目..."
npx cap sync ios

echo ""
echo "[3/6] 构建 Web 应用..."
if grep -q '"build"' package.json; then
    npm run build
else
    echo "[跳过] 未找到 build 脚本，直接使用 public 目录"
fi

echo ""
echo "[4/6] 重新同步资源..."
npx cap sync ios

echo ""
echo "[5/6] 构建 iOS 项目..."
cd ios
xcodebuild -workspace App/App.xcworkspace -scheme App -configuration Debug -destination "generic/platform=iOS" build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO

if [ $? -eq 0 ]; then
    echo ""
    echo "[6/6] 导出 IPA..."
    cd ..
    npx cap open ios
else
    echo "[错误] iOS 构建失败"
    exit 1
fi

echo ""
echo "========================================"
echo "   构建完成！"
echo "========================================"
echo ""
echo "在 Xcode 中打开: open ios/App.xcworkspace"
echo "然后选择设备和运行"
echo ""
