@echo off
chcp 65001 >nul
echo ========================================
echo    聊天室 App - 推送到 GitHub 自动构建
echo ========================================
echo.
echo 此脚本会将代码推送到 GitHub，
echo GitHub Actions 将自动构建 APK（约 5~10 分钟）
echo.

cd /d "%~dp0"

REM 检查 git
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 git，请先安装 Git
    pause
    exit /b 1
)

echo [1/3] 添加所有修改的文件...
git add -A
echo.

echo [2/3] 创建提交...
set /p COMMIT_MSG="输入提交说明（直接回车使用默认）: "
if "%COMMIT_MSG%"=="" set COMMIT_MSG=build: 更新代码，触发 APK 构建
git commit -m "%COMMIT_MSG%"
echo.

echo [3/3] 推送到 GitHub...
git push origin master
if %errorlevel% neq 0 (
    echo [提示] 推送到 master 失败，尝试 main 分支...
    git push origin main
)
echo.

echo ========================================
echo    推送完成！
echo ========================================
echo.
echo GitHub Actions 正在自动构建 APK...
echo 请访问以下地址查看构建进度：
echo   https://github.com/Yxf-20160325/-/actions
echo.
echo APK 构建完成后可在这里下载：
echo   https://github.com/Yxf-20160325/chatroom-app/releases/tag/apk-latest
echo.
pause
