@echo off
chcp 65001 >nul
echo ========================================
echo    聊天室 App - Android 构建脚本
echo ========================================
echo.

REM 检查 Node.js
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Node.js，请先安装 Node.js
    pause
    exit /b 1
)

REM 检查 npm
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 npm
    pause
    exit /b 1
)

echo [1/5] 安装依赖...
call npm install
if %errorlevel% neq 0 (
    echo [错误] npm install 失败
    pause
    exit /b 1
)
echo.

echo [2/5] 同步 Web 资源到 Android 项目...
call npx cap sync android
if %errorlevel% neq 0 (
    echo [错误] cap sync 失败
    pause
    exit /b 1
)
echo.

echo [3/5] 构建 Web 应用...
REM 如果有构建脚本则使用，否则直接复制
if exist "package.json" (
    for /f "delims=" %%i in ('findstr /C:"build" package.json') do set "HAS_BUILD=%%i"
)
if defined HAS_BUILD (
    call npm run build
) else (
    echo [跳过] 未找到 build 脚本，直接使用 public 目录
)
echo.

echo [4/5] 重新同步资源...
call npx cap sync android
if %errorlevel% neq 0 (
    echo [错误] cap sync 失败
    pause
    exit /b 1
)
echo.

echo [5/5] 构建 APK...
cd android
call gradlew assembleDebug
if %errorlevel% neq 0 (
    echo [错误] Gradle 构建失败
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo ========================================
echo    构建完成！
echo ========================================
echo.
echo APK 文件位置:
for /r "%CD%\android\app\build\outputs\apk\debug" %%f in (*.apk) do (
    echo   %%f
)
echo.
echo 安装到设备:
echo   adb install android\app\build\outputs\apk\debug\app-debug.apk
echo.
pause
