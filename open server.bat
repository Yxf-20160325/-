@echo off
setlocal

:start
echo [启动] 聊天室服务器...
node server.cjs
echo.
echo [退出] 服务器已停止
echo.
set /p choice="输入 R 重启，或任意键退出: "
if /i "%choice%"=="R" goto :start

endlocal
